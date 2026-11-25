// SPDX-License-Identifier: GPL-3.0-or-later
package boxconfig

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/oschwald/maxminddb-golang"
)

func legacyGeoRules(assetsDir, kind, code string) (object, error) {
	if assetsDir == "" {
		return nil, errors.New("the app's GeoIP and GeoSite assets are unavailable")
	}
	if kind == "geoip" {
		return legacyGeoIP(filepath.Join(assetsDir, "geoip.db"), code)
	}
	data, err := os.ReadFile(filepath.Join(assetsDir, "geosite.db"))
	if err != nil {
		return nil, err
	}
	return legacyGeoSite(data, code)
}

func legacyGeoIP(path, code string) (object, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	var prefixes []string
	for networks.Next() {
		var country string
		network, err := networks.Network(&country)
		if err != nil {
			return nil, err
		}
		if country == code {
			prefixes = append(prefixes, network.String())
		}
	}
	if err := networks.Err(); err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("unknown GeoIP code %q", code)
	}
	return object{"ip_cidr": prefixes}, nil
}

// Version zero of the sing-box GeoSite database stores a metadata table
// followed by records of one type byte and one length-prefixed string.
func legacyGeoSite(data []byte, code string) (object, error) {
	reader := bytes.NewReader(data)
	if version, err := reader.ReadByte(); err != nil || version != 0 {
		return nil, errors.New("invalid GeoSite database version")
	}
	count, err := binary.ReadUvarint(reader)
	if err != nil || count > uint64(reader.Len()) {
		return nil, errors.New("invalid GeoSite metadata count")
	}
	var offset, length uint64
	for range count {
		key, err := geoString(reader)
		if err != nil {
			return nil, err
		}
		position, err := binary.ReadUvarint(reader)
		if err != nil {
			return nil, err
		}
		entries, err := binary.ReadUvarint(reader)
		if err != nil {
			return nil, err
		}
		if key == code {
			offset, length = position, entries
		}
	}
	if length == 0 {
		return nil, fmt.Errorf("unknown or empty GeoSite code %q", code)
	}
	if offset >= uint64(reader.Len()) || length > (uint64(reader.Len())-offset)/2 {
		return nil, errors.New("invalid GeoSite entry range")
	}
	if _, err := reader.Seek(int64(offset), io.SeekCurrent); err != nil {
		return nil, err
	}
	keys := []string{"domain", "domain_suffix", "domain_keyword", "domain_regex"}
	fields := make(map[string][]string)
	for range length {
		kind, err := reader.ReadByte()
		if err != nil || int(kind) >= len(keys) {
			return nil, errors.New("invalid GeoSite entry type")
		}
		value, err := geoString(reader)
		if err != nil {
			return nil, err
		}
		fields[keys[kind]] = append(fields[keys[kind]], value)
	}
	rule := object{}
	for key, values := range fields {
		rule[key] = values
	}
	return rule, nil
}

func geoString(reader *bytes.Reader) (string, error) {
	n, err := binary.ReadUvarint(reader)
	if err != nil {
		return "", err
	}
	if n > uint64(reader.Len()) {
		return "", io.ErrUnexpectedEOF
	}
	data := make([]byte, int(n))
	_, err = io.ReadFull(reader, data)
	return string(data), err
}

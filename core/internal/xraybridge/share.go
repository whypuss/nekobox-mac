// SPDX-License-Identifier: GPL-3.0-or-later
package xraybridge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/xtls/libxray/share"
)

// ParseShareLink returns an empty result for links handled by the existing
// sing-box profiles. Advanced transports are kept in their native Xray form.
func ParseShareLink(link string) (string, error) {
	scheme, _, found := strings.Cut(link, "://")
	if !found {
		return "", nil
	}
	switch scheme {
	case "vless", "vmess", "trojan", "ss", "socks", "hy2", "hysteria2":
	default:
		return "", nil
	}
	qr := readVMessQRCode(link)
	if !wantsXray(scheme, link, qr) {
		return "", nil
	}
	if qr != nil {
		var err error
		link, err = qr.shareLink()
		if err != nil {
			return "", err
		}
	} else if parsed, err := url.Parse(link); err == nil {
		query, queryErr := url.ParseQuery(parsed.RawQuery)
		if scheme == "hy2" || scheme == "hysteria2" {
			if queryErr != nil {
				return "", errors.New("invalid query in Hysteria 2 share link")
			}
			for _, field := range []string{"pinSHA256", "pin-sha256", "pin_sha256"} {
				if query.Get(field) != "" {
					return "", errors.New("Hysteria 2 pinSHA256 requires the native Hysteria 2 outbound")
				}
			}
		}
		if mask := query.Get("finalmask"); mask != "" && !query.Has("fm") {
			query.Set("fm", mask)
			parsed.RawQuery = query.Encode()
			link = parsed.String()
		}
	}
	data, err := share.ConvertShareLinksToXrayJson(link, "")
	if err != nil {
		return "", err
	}
	var document struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &document); err != nil || len(document.Outbounds) != 1 {
		return "", errors.New("expected one Xray outbound")
	}
	return WrapOutbound(string(document.Outbounds[0]))
}

func wantsXray(scheme, link string, qr *vmessQRCode) bool {
	withoutFragment, _, _ := strings.Cut(link, "#")
	_, rawQuery, _ := strings.Cut(withoutFragment, "?")
	query, _ := url.ParseQuery(rawQuery)
	if strings.EqualFold(query.Get("core"), "xray") {
		return true
	}
	transport := query.Get("type")
	if qr != nil {
		transport = qr.Network
	}
	switch strings.ToLower(transport) {
	case "xhttp", "splithttp", "kcp", "mkcp":
		return true
	}
	if scheme == "vless" {
		encryption := query.Get("encryption")
		if encryption != "" && !strings.EqualFold(encryption, "none") {
			return true
		}
	}
	for _, field := range []string{"pqv", "spx", "fm", "finalmask", "pcs", "vcn"} {
		if query.Get(field) != "" {
			return true
		}
	}
	return false
}

type vmessQRCode struct {
	Name        string          `json:"ps"`
	Address     string          `json:"add"`
	Port        json.RawMessage `json:"port"`
	ID          string          `json:"id"`
	AlterID     json.RawMessage `json:"aid"`
	Network     string          `json:"net"`
	Header      string          `json:"type"`
	Host        string          `json:"host"`
	Path        string          `json:"path"`
	Cipher      string          `json:"scy"`
	TLS         string          `json:"tls"`
	SNI         string          `json:"sni"`
	ALPN        string          `json:"alpn"`
	Fingerprint string          `json:"fp"`
	Mode        string          `json:"mode"`
	Extra       json.RawMessage `json:"extra"`
}

func readVMessQRCode(link string) *vmessQRCode {
	encoded, found := strings.CutPrefix(link, "vmess://")
	if !found {
		return nil
	}
	encoded = strings.SplitN(encoded, "#", 2)[0]
	encoded = strings.SplitN(encoded, "?", 2)[0]
	if strings.Contains(encoded, "@") {
		return nil
	}
	encoded = strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimRight(encoded, "="))
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	var node vmessQRCode
	if json.Unmarshal(decoded, &node) != nil {
		return nil
	}
	return &node
}

func (q vmessQRCode) shareLink() (string, error) {
	port, err := strconv.ParseUint(strings.Trim(string(q.Port), `"`), 10, 16)
	if err != nil || port == 0 || q.Address == "" || q.ID == "" {
		return "", errors.New("VMess QR code needs a host, port and UUID")
	}
	if aid := strings.Trim(string(q.AlterID), `"`); aid != "" && aid != "0" {
		return "", errors.New("Xray requires a VMess AEAD profile")
	}
	query := make(url.Values)
	for key, value := range map[string]string{
		"type": q.Network, "host": q.Host, "path": q.Path, "headerType": q.Header,
		"encryption": q.Cipher, "security": q.TLS, "sni": q.SNI, "alpn": q.ALPN,
		"fp": q.Fingerprint, "mode": q.Mode,
	} {
		if value != "" {
			query.Set(key, value)
		}
	}
	if q.Network == "grpc" {
		query.Set("serviceName", q.Path)
	}
	if len(q.Extra) != 0 && string(q.Extra) != "null" {
		var extra string
		if json.Unmarshal(q.Extra, &extra) != nil {
			extra = string(q.Extra)
		}
		query.Set("extra", extra)
	}
	link := url.URL{
		Scheme: "vmess", User: url.User(q.ID),
		Host:     net.JoinHostPort(strings.Trim(q.Address, "[]"), strconv.FormatUint(port, 10)),
		RawQuery: query.Encode(), Fragment: q.Name,
	}
	return link.String(), nil
}

func WrapOutbound(raw string) (string, error) {
	var outbound struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal([]byte(raw), &outbound); err != nil || !supportsProtocol(outbound.Protocol) {
		return "", errors.New("unsupported Xray outbound")
	}
	data, err := json.Marshal(struct {
		Type     string          `json:"type"`
		Outbound json.RawMessage `json:"outbound"`
	}{Type: Type, Outbound: json.RawMessage(raw)})
	return string(data), err
}

func ShareLink(config, name string) (string, error) {
	var wrapper struct {
		Outbound map[string]json.RawMessage `json:"outbound"`
	}
	if err := json.Unmarshal([]byte(config), &wrapper); err != nil || wrapper.Outbound == nil {
		return "", errors.New("invalid Xray outbound")
	}
	if name != "" {
		wrapper.Outbound["tag"], _ = json.Marshal(name)
	}
	data, err := json.Marshal(map[string]any{"outbounds": []any{wrapper.Outbound}})
	if err != nil {
		return "", err
	}
	link, err := share.ConvertXrayJsonToShareLinks(data)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		// Hysteria port hopping uses a range in the authority.
		base, fragment, hasFragment := strings.Cut(strings.TrimSpace(link), "#")
		separator := "?"
		if strings.Contains(base, "?") {
			separator = "&"
		}
		if hasFragment {
			fragment = "#" + fragment
		}
		return base + separator + "core=xray" + fragment, nil
	}
	query := parsed.Query()
	query.Set("core", "xray")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

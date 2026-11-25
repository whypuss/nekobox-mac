// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/netip"
	"strings"
)

func normalizeMasqueMapping(mapping map[string]any) error {
	// Accept common snake_case / usque / sing-box field aliases.
	aliasKey(mapping, "private-key", "private_key")
	aliasKey(mapping, "public-key", "public_key", "endpoint_pub_key", "peer_public_key")
	aliasKey(mapping, "uri", "connect_uri")
	aliasKey(mapping, "ip", "ipv4")
	aliasKey(mapping, "skip-cert-verify", "skip_cert_verify", "insecure")
	aliasKey(mapping, "remote-dns-resolve", "remote_dns_resolve")
	aliasKey(mapping, "congestion-controller", "congestion_controller", "congestion_control")
	aliasKey(mapping, "bbr-profile", "bbr_profile")
	aliasKey(mapping, "handshake-timeout", "handshake_timeout")

	// Extract ip/ipv6 from local_address (string or array) when provided.
	if rawLocal, ok := mapping["local_address"]; ok {
		delete(mapping, "local_address")
		var addrs []string
		switch typed := rawLocal.(type) {
		case string:
			for _, part := range strings.Split(typed, ",") {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					addrs = append(addrs, trimmed)
				}
			}
		case []any:
			for _, item := range typed {
				if s, ok := item.(string); ok {
					if trimmed := strings.TrimSpace(s); trimmed != "" {
						addrs = append(addrs, trimmed)
					}
				}
			}
		case []string:
			for _, s := range typed {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					addrs = append(addrs, trimmed)
				}
			}
		}
		for _, addr := range addrs {
			host := strings.SplitN(addr, "/", 2)[0]
			if parsed, err := netip.ParseAddr(host); err == nil {
				if parsed.Is4() {
					if strings.TrimSpace(asString(mapping["ip"])) == "" {
						mapping["ip"] = addr
					}
				} else if parsed.Is6() {
					if strings.TrimSpace(asString(mapping["ipv6"])) == "" {
						mapping["ipv6"] = addr
					}
				}
			}
		}
	}

	if network := strings.ToLower(strings.TrimSpace(asString(mapping["network"]))); network != "" {
		mapping["network"] = network
	}

	if privRaw := strings.TrimSpace(asString(mapping["private-key"])); privRaw != "" {
		normalized, err := normalizeMasquePrivateKey(privRaw)
		if err != nil {
			return err
		}
		mapping["private-key"] = normalized
	}

	if pubRaw := strings.TrimSpace(asString(mapping["public-key"])); pubRaw != "" {
		normalized, err := normalizeMasquePublicKey(pubRaw)
		if err != nil {
			return err
		}
		mapping["public-key"] = normalized
	}

	// Mihomo requires at least one local tunnel address unless running in h3-l4proxy mode.
	network := strings.ToLower(strings.TrimSpace(asString(mapping["network"])))
	if network != "h3-l4proxy" &&
		strings.TrimSpace(asString(mapping["ip"])) == "" &&
		strings.TrimSpace(asString(mapping["ipv6"])) == "" {
		mapping["ip"] = "172.16.0.2/32"
	}

	return nil
}

func aliasKey(mapping map[string]any, canonical string, aliases ...string) {
	hasCanonical := false
	if existing, ok := mapping[canonical]; ok && existing != nil {
		if s, isStr := existing.(string); !isStr || strings.TrimSpace(s) != "" {
			hasCanonical = true
		}
	}
	for _, alias := range aliases {
		val, exists := mapping[alias]
		if !exists {
			continue
		}
		delete(mapping, alias)
		if !hasCanonical && val != nil {
			if s, isStr := val.(string); !isStr || strings.TrimSpace(s) != "" {
				mapping[canonical] = val
				hasCanonical = true
			}
		}
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func decodePEMOrBase64(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if strings.Contains(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block != nil && len(block.Bytes) > 0 {
			return block.Bytes, nil
		}
		return nil, fmt.Errorf("invalid PEM block")
	}
	cleaned := strings.NewReplacer("\r", "", "\n", "", " ", "", "\t", "").Replace(trimmed)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if data, err := enc.DecodeString(cleaned); err == nil && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 key encoding")
}

// normalizeMasquePrivateKey accepts SEC1 or PKCS#8 ECDSA private keys in PEM or
// standard/URL-safe/unpadded Base64 and returns canonical standard Base64 SEC1 DER
// expected by Mihomo's MASQUE outbound.
func normalizeMasquePrivateKey(raw string) (string, error) {
	der, err := decodePEMOrBase64(raw)
	if err != nil {
		return "", fmt.Errorf("decode MASQUE private key: %w", err)
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return base64.StdEncoding.EncodeToString(der), nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", fmt.Errorf("parse MASQUE EC private key (expected SEC1 or PKCS#8): %w", err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("MASQUE private key must be an ECDSA key")
	}
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return "", fmt.Errorf("marshal MASQUE EC private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sec1DER), nil
}

// normalizeMasquePublicKey accepts PKIX ECDSA public keys in PEM or
// standard/URL-safe/unpadded Base64 and returns canonical standard Base64 PKIX DER.
func normalizeMasquePublicKey(raw string) (string, error) {
	der, err := decodePEMOrBase64(raw)
	if err != nil {
		return "", fmt.Errorf("decode MASQUE public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", fmt.Errorf("parse MASQUE ECDSA public key: %w", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		return "", fmt.Errorf("MASQUE public key must be an ECDSA key")
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

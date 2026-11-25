// SPDX-License-Identifier: GPL-3.0-or-later
package parser

import (
	"testing"

	"nekobox-mac/internal/configbuilder"
	"nekobox-mac/internal/store"
)

func TestParseAllCoreProtocolsAndBuildConfig(t *testing.T) {
	samples := []string{
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=abc123&sid=01ab&type=tcp&flow=xtls-rprx-vision#VLESS-Reality",
		"trojan://pass123@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Fws#Trojan-WS",
		"hysteria2://secret@hy2.example.com:443?sni=hy2.example.com&pinSHA256=AA:BB:CC#Hy2-Pin",
		"tuic://11111111-1111-1111-1111-111111111111:secret@tuic.example.com:443?congestion_control=bbr&alpn=h3#TUIC-v5",
		"anytls://mysecret@anytls.example.com:443?sni=anytls.example.com&insecure=1#AnyTLS-Node",
		"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.com:8388#SS-AEAD",
		"socks5://user:pass@127.0.0.1:1080#Local-Socks",
	}

	st := store.DefaultState()
	for _, uri := range samples {
		p, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI(%s) failed: %v", uri, err)
		}
		if p.Address == "" || p.Port <= 0 {
			t.Fatalf("invalid endpoint parsed for %s: %+v", uri, p)
		}
		cfg, err := configbuilder.BuildSingBoxConfig(st, p, configbuilder.BuildOptions{
			ForTest:   false,
			EnableTUN: false,
		})
		if err != nil {
			t.Fatalf("BuildSingBoxConfig(%s) failed: %v", p.Name, err)
		}
		if len(cfg) < 100 {
			t.Fatalf("unexpected short config for %s", p.Name)
		}
		share := ExportShareURI(p)
		if share == "" {
			t.Fatalf("empty exported share URI for %s", p.Name)
		}
	}
}

func TestDoHSubscriptionRejection(t *testing.T) {
	if !IsDoHURL("https://dns.google/dns-query") {
		t.Fatal("expected DoH URL to be detected")
	}
	if IsDoHURL("https://sub.example.com/api/v1/client/subscribe?token=abc") {
		t.Fatal("normal subscription URL falsely flagged as DoH")
	}
}

func TestWireGuardAndAmneziaWGConf(t *testing.T) {
	conf := `[Interface]
PrivateKey = cHJpdmF0ZWtleQ==
Address = 172.16.0.2/32
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 25

[Peer]
PublicKey = cHVibGlja2V5
Endpoint = [2001:db8::1]:51820
AllowedIPs = 0.0.0.0/0, ::/0
`
	list, err := ParseInput(conf)
	if err != nil || len(list) != 1 {
		t.Fatalf("expected 1 amneziawg profile, got %v (err=%v)", len(list), err)
	}
	if list[0].Type != "amneziawg" || list[0].Core != "mihomo" || list[0].Address != "2001:db8::1" {
		t.Fatalf("unexpected amneziawg parsed profile: %+v", list[0])
	}
}

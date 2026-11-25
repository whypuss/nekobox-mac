package xraybridge

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestHysteria2PinRequiresNativeOutbound(t *testing.T) {
	const link = "hy2://pass@example.test/?"
	for _, param := range []string{"pinSHA256", "pin-sha256", "pin_sha256"} {
		pin := param + "=" + strings.Repeat("ab", 32)
		if result, err := ParseShareLink(link + pin); result != "" || err != nil {
			t.Fatalf("ordinary Hysteria 2 link did not fall through to the native profile: %v", err)
		}
		if _, err := ParseShareLink(link + "core=xray&" + pin); err == nil || !strings.Contains(err.Error(), "requires the native") {
			t.Fatalf("Xray Hysteria 2 pin must be rejected: %v", err)
		}
	}
	if _, err := ParseShareLink(link + "core=xray&pinSHA256=%ZZ"); err == nil {
		t.Fatal("malformed Hysteria 2 pin must not be silently discarded")
	}
}

func TestVMessQRCodeWithXHTTP(t *testing.T) {
	const profile = `{"v":"2","ps":"Fixture","add":"example.test","port":"443","id":"02d42cc5-abe3-4f76-b826-41e1663ddc8e",
	"aid":0,"scy":"auto","net":"xhttp","type":"none","path":"/v2","mode":"stream-up","tls":"tls","sni":"peer.example",
	"extra":{"noGRPCHeader":true}}`
	link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(profile))
	config, err := ParseShareLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(config); err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ShareLink(config, "Fixture")
	if err != nil {
		t.Fatal(err)
	}
	result, err := url.Parse(roundTrip)
	if err != nil {
		t.Fatal(err)
	}
	if result.Query().Get("mode") != "stream-up" || result.Query().Get("type") != "xhttp" {
		t.Fatal("XHTTP settings were lost")
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(result.Query().Get("extra")), &extra); err != nil || extra["noGRPCHeader"] != true {
		t.Fatal("XHTTP extra settings were lost")
	}
}

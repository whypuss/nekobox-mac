// SPDX-License-Identifier: GPL-3.0-or-later
package configbuilder

import (
	"encoding/json"
	"strings"
	"testing"

	"nekobox-mac/internal/store"
)

func TestBuildSingBoxConfigPortRangesClashSecretAndCoreOverride(t *testing.T) {
	st := store.DefaultState()
	st.Settings.ClashAPISecret = "test-secret-xyz"
	st.Rules = []store.RouteRule{
		{
			ID:      101,
			Name:    "Port range & private rule",
			Enabled: true,
			Domains: "geosite:private, example.com",
			IPs:     "geoip:private, 1.1.1.1",
			Ports:   "80, 443, 1000:2000, 3000-3010",
			Outbound: "direct",
		},
	}

	p := store.Profile{
		ID:      1,
		Name:    "Mihomo VLESS",
		Type:    "vless",
		Core:    "mihomo",
		Address: "example.org",
		Port:    443,
		Params: map[string]any{
			"uuid":      "11111111-2222-3333-4444-555555555555",
			"security":  "tls",
			"sni":       "example.org",
			"transport": "ws",
			"path":      "/ws",
		},
	}

	cfgStr, err := BuildSingBoxConfig(st, p, BuildOptions{
		ForTest:   false,
		EnableTUN: false,
		DataDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(cfgStr), &parsed); err != nil {
		t.Fatalf("unmarshal generated config: %v", err)
	}

	if !strings.Contains(cfgStr, `"secret":"test-secret-xyz"`) {
		t.Fatalf("expected clash_api secret in generated config, got: %s", cfgStr)
	}
	if !strings.Contains(cfgStr, `"1000:2000"`) || !strings.Contains(cfgStr, `"3000:3010"`) {
		t.Fatalf("expected port_range 1000:2000 and 3000:3010 in generated config, got: %s", cfgStr)
	}
	if !strings.Contains(cfgStr, `"type":"mihomo"`) {
		t.Fatalf("expected explicit Core=mihomo to generate mihomo outbound, got: %s", cfgStr)
	}
}

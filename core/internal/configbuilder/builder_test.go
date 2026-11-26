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

func TestBuildSingBoxConfigPerAppBypassPathRegexSafariAndSpacedProcessName(t *testing.T) {
	st := store.DefaultState()
	st.AppProxy.AppActions = map[string]string{
		"com.google.Chrome": "bypass",
		"com.apple.Safari":  "bypass",
		"com.openai.chat":   "force_proxy",
	}
	st.AppProxy.AppProcessMap = map[string]string{
		"com.google.Chrome": "Google Chrome",
		"com.apple.Safari":  "Safari",
		"com.openai.chat":   "ChatGPT",
	}
	st.AppProxy.AppPathMap = map[string]string{
		"com.google.Chrome": "/Applications/Google Chrome 2.app",
		"com.apple.Safari":  "/Applications/Safari.app",
		"com.openai.chat":   "/Applications/ChatGPT.app",
	}
	st.Rules = []store.RouteRule{
		{
			ID:          201,
			Name:        "Spaced process direct",
			Enabled:     true,
			ProcessName: "Google Chrome Helper, Visual Studio Code",
			Outbound:    "direct",
		},
		{
			ID:       202,
			Name:     "Company intranet direct",
			Enabled:  true,
			Domains:  "corp.internal.example",
			Outbound: "direct",
		},
	}

	p := store.Profile{
		ID:      1,
		Name:    "Test SOCKS",
		Type:    "socks",
		Address: "127.0.0.1",
		Port:    10808,
	}

	cfgStr, err := BuildSingBoxConfig(st, p, BuildOptions{
		ForTest:   false,
		EnableTUN: false,
		DataDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var parsed struct {
		Route struct {
			FindProcess bool             `json:"find_process"`
			Rules       []map[string]any `json:"rules"`
		} `json:"route"`
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(cfgStr), &parsed); err != nil {
		t.Fatalf("unmarshal generated config: %v", err)
	}

	if !parsed.Route.FindProcess {
		t.Fatalf("expected route.find_process=true when per-app bypass rules exist")
	}

	containsStr := func(v any, target string) bool {
		arr, _ := v.([]any)
		for _, item := range arr {
			if s, _ := item.(string); s == target {
				return true
			}
		}
		return false
	}

	var hasBypassPathRule, hasBypassProcRule, hasForcePathRule, hasSpacedCustomProc bool
	for _, rule := range parsed.Route.Rules {
		out, _ := rule["outbound"].(string)
		_, hasRegex := rule["process_path_regex"]
		_, hasProc := rule["process_name"]
		if hasRegex && hasProc {
			t.Fatalf("process_path_regex and process_name must be separate OR rules, got combined rule: %+v", rule)
		}
		if out == TagBypass && hasRegex {
			if containsStr(rule["process_path_regex"], `^/Applications/Google Chrome 2\.app(/|$)`) &&
				containsStr(rule["process_path_regex"], `^/Applications/Safari\.app(/|$)`) {
				hasBypassPathRule = true
			}
		}
		if out == TagBypass && hasProc {
			if containsStr(rule["process_name"], "Google Chrome Helper") &&
				containsStr(rule["process_name"], "com.apple.WebKit.Networking") {
				hasBypassProcRule = true
			}
			if containsStr(rule["process_name"], "Visual Studio Code") {
				hasSpacedCustomProc = true
			}
		}
		if out == TagProxy && hasRegex {
			if containsStr(rule["process_path_regex"], `^/Applications/ChatGPT\.app(/|$)`) {
				hasForcePathRule = true
			}
		}
	}

	if !hasBypassPathRule {
		t.Fatalf("missing bypass process_path_regex rule for Chrome/Safari bundles in %s", cfgStr)
	}
	if !hasBypassProcRule {
		t.Fatalf("missing bypass process_name rule including Chrome Helper & Safari WebKit XPC in %s", cfgStr)
	}
	if !hasForcePathRule {
		t.Fatalf("missing force_proxy process_path_regex rule for ChatGPT in %s", cfgStr)
	}
	if !hasSpacedCustomProc {
		t.Fatalf("custom rule process_name with spaces was split unexpectedly in %s", cfgStr)
	}

	var hasDirectDNSBypassRegex, hasDirectDNSCustomDomain bool
	for _, rule := range parsed.DNS.Rules {
		if rule["server"] != "dns-direct" {
			continue
		}
		if _, ok := rule["process_path_regex"]; ok {
			hasDirectDNSBypassRegex = true
		}
		if raw, _ := json.Marshal(rule["domain_suffix"]); strings.Contains(string(raw), `"corp.internal.example"`) {
			hasDirectDNSCustomDomain = true
		}
	}
	if !hasDirectDNSBypassRegex {
		t.Fatalf("expected bypass process_path_regex DNS rule targeting dns-direct")
	}
	if !hasDirectDNSCustomDomain {
		t.Fatalf("expected custom direct domain rule mirrored into dns-direct DNS rules")
	}
}

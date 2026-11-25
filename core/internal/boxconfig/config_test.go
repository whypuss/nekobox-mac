// SPDX-License-Identifier: GPL-3.0-or-later
package boxconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"nekobox-mac/internal/mihomobridge"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
)

func testBoxContext(ctx context.Context) context.Context {
	outbounds := include.OutboundRegistry()
	mihomobridge.Register(outbounds)
	mihomobridge.RegisterRouting(outbounds)
	dnsTransports := include.DNSTransportRegistry()
	mihomobridge.RegisterDNS(dnsTransports)
	return box.Context(
		ctx,
		include.InboundRegistry(),
		outbounds,
		include.EndpointRegistry(),
		dnsTransports,
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)
}

func assertBuildsSingBox(t *testing.T, raw, assetsDir string) (option.Options, map[string]any) {
	t.Helper()
	normalized, err := Normalize(raw, assetsDir)
	if err != nil {
		t.Fatalf("Normalize failed: %v", err)
	}
	ctx := testBoxContext(context.Background())
	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(normalized))
	if err != nil {
		t.Fatalf("Unmarshal sing-box options failed: %v\nnormalized=%s", err, normalized)
	}
	instance, err := box.New(box.Options{
		Context: testBoxContext(context.Background()),
		Options: options,
	})
	if err != nil {
		t.Fatalf("box.New failed: %v\nnormalized=%s", err, normalized)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("box.Close failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(normalized), &parsed); err != nil {
		t.Fatalf("unmarshal normalized json: %v", err)
	}
	return options, parsed
}

func writeTestGeoSite(t *testing.T, dir string) {
	t.Helper()
	// GeoSite v0 with one code "test" and the domain suffix "example.test".
	database := append([]byte{0, 1, 4, 't', 'e', 's', 't', 0, 1, 1, 12}, []byte("example.test")...)
	if err := os.WriteFile(filepath.Join(dir, "geosite.db"), database, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyAndroidConfig(t *testing.T) {
	assets := t.TempDir()
	writeTestGeoSite(t, assets)
	const legacy = `{
		"dns": {
			"independent_cache": true,
			"fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
			"servers": [
				{"address": "rcode://success", "tag": "dns-block"},
				{"address": "local", "tag": "dns-local", "detour": "direct"},
				{"address": "223.5.5.5", "tag": "dns-direct", "detour": "direct"},
				{"address": "https://resolver.example/dns-query", "tag": "dns-remote",
				 "detour": "proxy", "address_resolver": "dns-direct"},
				{"address": "fakeip", "tag": "dns-fake", "strategy": "ipv4_only"}
			],
			"rules": [
				{"outbound": ["any"], "server": "dns-direct"},
				{"domain": ["blocked.example"], "server": "dns-block", "disable_cache": true},
				{"inbound": ["tun-in"], "server": "dns-fake", "disable_cache": true}
			],
			"final": "dns-remote"
		},
		"inbounds": [
			{"type": "tun", "tag": "tun-in", "inet4_address": ["172.19.0.1/28"],
			 "endpoint_independent_nat": true, "sniff": true, "sniff_override_destination": true,
			 "domain_strategy": "prefer_ipv4"}
		],
		"outbounds": [
			{"type": "wireguard", "tag": "proxy", "server": "127.0.0.1", "server_port": 51820,
			 "local_address": ["172.16.0.2/32"], "private_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
			 "peer_public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},
			{"type": "direct", "tag": "direct"}
		],
		"route": {
			"rules": [{"rule_set": ["geosite:test"], "outbound": "direct"}],
			"rule_set": [{"type": "local", "tag": "geosite:test", "path": "geosite:test", "format": "binary"}]
		}
	}`
	options, _ := assertBuildsSingBox(t, legacy, assets)
	if len(options.Endpoints) != 1 || options.Route.Final != "proxy" || len(options.Route.Rules) != 3 {
		t.Fatal("legacy TUN, route or WireGuard settings were lost")
	}
	if len(options.DNS.Servers) != 4 || len(options.DNS.Rules) != 2 {
		t.Fatal("legacy DNS settings were lost")
	}
	if len(options.Route.RuleSet[0].InlineOptions.Rules) != 1 {
		t.Fatal("legacy GeoSite rules were lost")
	}
}

func TestMetaRoutingDomainNodeWithFakeDNSAndIPv6(t *testing.T) {
	assets := t.TempDir()
	cases := []struct {
		name           string
		globalStrategy string
		directStrategy string
		remoteStrategy string
		wantGuardRule  bool
	}{
		{
			name:           "IPv6 disabled (reproduces v1.4.9 screenshot crash)",
			globalStrategy: "ipv4_only",
			directStrategy: "ipv4_only",
			remoteStrategy: "ipv4_only",
			wantGuardRule:  false,
		},
		{
			name:           "IPv6 enabled default",
			globalStrategy: "prefer_ipv4",
			directStrategy: "prefer_ipv4",
			remoteStrategy: "prefer_ipv4",
			wantGuardRule:  false,
		},
		{
			name:           "Mixed direct ipv4_only with IPv6 enabled remote",
			globalStrategy: "prefer_ipv4",
			directStrategy: "ipv4_only",
			remoteStrategy: "prefer_ipv4",
			wantGuardRule:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{
				"dns": {
					"independent_cache": true,
					"strategy": "` + tc.globalStrategy + `",
					"fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
					"servers": [
						{"address": "rcode://success", "tag": "dns-block"},
						{"address": "local", "tag": "dns-local", "detour": "direct"},
						{"address": "https://223.5.5.5/dns-query", "tag": "dns-direct", "detour": "direct",
						 "address_resolver": "dns-local", "strategy": "` + tc.directStrategy + `"},
						{"address": "https://dns.google/dns-query", "tag": "dns-remote", "detour": "proxy",
						 "address_resolver": "dns-direct", "strategy": "` + tc.remoteStrategy + `"},
						{"address": "fakeip", "tag": "dns-fake", "strategy": "ipv4_only"},
						{"type": "mihomo-dns", "tag": "dns-meta", "direct": "dns-direct", "remote": "dns-remote", "routing": "meta-auto"},
						{"type": "mihomo-dns", "tag": "dns-meta-tun", "direct": "dns-direct", "remote": "dns-fake", "routing": "meta-auto"}
					],
					"rules": [
						{"domain": ["node.example.com", "dns.google"], "server": "dns-direct"},
						{"outbound": ["any"], "server": "dns-direct"},
						{"inbound": ["tun-in"], "query_type": ["A", "AAAA"], "server": "dns-meta-tun", "disable_cache": true},
						{"inbound": ["tun-in", "mixed-in"], "server": "dns-meta"}
					],
					"final": "dns-remote"
				},
				"inbounds": [
					{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0, "sniff": true}
				],
				"outbounds": [
					{"type": "vless", "tag": "proxy", "server": "node.example.com", "server_port": 443,
					 "uuid": "02d42cc5-abe3-4f76-b826-41e1663ddc8e", "domain_strategy": "prefer_ipv4"},
					{"type": "direct", "tag": "direct"},
					{"type": "direct", "tag": "bypass"},
					{"type": "mihomo-routing", "tag": "meta-auto", "proxy": "proxy", "direct": "bypass"}
				],
				"route": {
					"rules": [
						{"port": [53], "action": "hijack-dns"},
						{"protocol": ["dns"], "action": "hijack-dns"},
						{"inbound": ["tun-in", "mixed-in"], "outbound": "meta-auto"}
					]
				}
			}`
			_, parsed := assertBuildsSingBox(t, raw, assets)
			dnsObj := parsed["dns"].(map[string]any)
			rules := dnsObj["rules"].([]any)
			foundGuard := false
			for _, item := range rules {
				rule := item.(map[string]any)
				if _, hasStrategy := rule["strategy"]; hasStrategy {
					t.Fatalf("unexpected deprecated strategy field on DNS rule: %#v", rule)
				}
				if rule["action"] == "predefined" && rule["rcode"] == "NOERROR" {
					foundGuard = true
				}
			}
			if foundGuard != tc.wantGuardRule {
				t.Fatalf("guard rule mismatch: got %v, want %v (rules=%#v)", foundGuard, tc.wantGuardRule, rules)
			}
			outbounds := parsed["outbounds"].([]any)
			proxyOut := outbounds[0].(map[string]any)
			if _, hasLegacyStrategy := proxyOut["domain_strategy"]; hasLegacyStrategy {
				t.Fatalf("expected outbound domain_strategy to migrate to domain_resolver: %#v", proxyOut)
			}
			if proxyOut["domain_resolver"] == nil {
				t.Fatalf("expected domain_resolver on proxy outbound: %#v", proxyOut)
			}
		})
	}
}

func TestLegacySingBox18To113FullCompat(t *testing.T) {
	assets := t.TempDir()
	writeTestGeoSite(t, assets)
	const oldCustom = `{
		"dns": {
			"servers": [
				{"type": "legacy", "tag": "local-dns", "address": "223.5.5.5", "detour": "freedom"},
				{"tag": "remote-dns", "address": "https://1.1.1.1/dns-query", "detour": "proxy", "strategy": "prefer_ipv4"},
				{"tag": "block-dns", "address": "rcode://name_error"}
			],
			"rules": [
				{"outbound": "any", "server": "local-dns", "strategy": "ipv4_only"},
				{"geosite": ["test"], "server": "block-dns"},
				{"ip_cidr": ["10.0.0.0/8"], "rule_set_ip_cidr_accept_empty": true, "server": "local-dns"},
				{"query_type": ["A", "AAAA"], "domain": ["dual.example"], "server": "remote-dns", "strategy": "ipv4_only"}
			],
			"final": "remote-dns"
		},
		"inbounds": [
			{"type": "mixed", "listen": "127.0.0.1", "listen_port": 0, "sniff": true, "udp_disable_domain_unmapping": true}
		],
		"outbounds": [
			{"type": "socks", "tag": "proxy", "server": "relay.example", "server_port": 1080, "detour": "front", "domain_strategy": "prefer_ipv4"},
			{"type": "socks", "tag": "front", "server": "front.example", "server_port": 1080, "domain_strategy": "prefer_ipv6"},
			{"type": "direct", "tag": "freedom"},
			{"type": "direct", "tag": "override-direct", "override_address": "127.0.0.1", "override_port": 8080},
			{"type": "dns", "tag": "dns-out"}
		],
		"route": {
			"geoip": {"path": "geoip.db"},
			"geosite": {"path": "geosite.db"},
			"rules": [
				{"protocol": "dns", "outbound": "dns-out"},
				{"geosite": ["test"], "outbound": "freedom"},
				{"geoip": ["private"], "outbound": "freedom"},
				{"domain": ["ads.example"], "outbound": "block"},
				{"domain": ["local-override.example"], "outbound": "override-direct"}
			]
		}
	}`
	options, parsed := assertBuildsSingBox(t, oldCustom, assets)
	if options.Route.DefaultDomainResolver == nil || options.Route.DefaultDomainResolver.Server != "local-dns" {
		t.Fatalf("expected default_domain_resolver=local-dns, got %#v", options.Route.DefaultDomainResolver)
	}
	// Chained proxy outbound with detour must NOT get forced local domain_resolver.
	outbounds := parsed["outbounds"].([]any)
	proxyOut := outbounds[0].(map[string]any)
	if proxyOut["domain_resolver"] != nil {
		t.Fatalf("chained outbound with detour should not force local domain_resolver: %#v", proxyOut)
	}
	frontOut := outbounds[1].(map[string]any)
	if frontOut["domain_resolver"] == nil {
		t.Fatalf("front outbound without detour should receive migrated domain_resolver: %#v", frontOut)
	}
}

func TestModernSingBox114Passthrough(t *testing.T) {
	const modern = `{
		"dns": {
			"strategy": "prefer_ipv4",
			"servers": [
				{"type": "local", "tag": "dns-local"},
				{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "proxy"},
				{"type": "fakeip", "tag": "dns-fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
			],
			"rules": [
				{"domain": ["example.org"], "action": "evaluate", "server": "dns-remote"},
				{"ip_is_private": true, "match_response": true, "action": "respond"},
				{"query_type": ["A", "AAAA"], "action": "route", "server": "dns-fake"}
			],
			"final": "dns-remote"
		},
		"endpoints": [
			{"type": "wireguard", "tag": "proxy", "address": ["172.16.0.2/32", "fd00::2/128"],
			 "private_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
			 "peers": [{"address": "127.0.0.1", "port": 51820,
			            "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
			            "allowed_ips": ["0.0.0.0/0", "::/0"]}]}
		],
		"outbounds": [
			{"type": "direct", "tag": "direct"}
		],
		"route": {
			"default_domain_resolver": "dns-local",
			"final": "proxy",
			"rules": [
				{"protocol": "dns", "action": "hijack-dns"},
				{"ip_is_private": true, "outbound": "direct"}
			]
		}
	}`
	assertBuildsSingBox(t, modern, "")
}

func TestLegacyDNSStrategiesStayScoped(t *testing.T) {
	base := `{
		"dns": {
			"servers": [{"tag": "dns-direct", "address": "127.0.0.1", "strategy": "prefer_ipv4"},
				{"tag": "default", "address": "local"}],
			"final": "default",
			"rules": [
				{"domain": "first.example", "server": "dns-direct"},
				{"domain": "second.example", "server": "default", "strategy": "prefer_ipv6"}
			]
		},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`
	options, parsed := assertBuildsSingBox(t, base, "")
	dns := parsed["dns"].(object)
	rules := dns["rules"].([]any)
	if dns["strategy"] != nil || rules[0].(object)["strategy"] != "prefer_ipv4" ||
		rules[1].(object)["strategy"] != "prefer_ipv6" {
		t.Fatalf("legacy DNS strategies were changed: %v", dns)
	}
	instance, err := box.New(box.Options{Context: testBoxContext(context.Background()), Options: options})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatalf("legacy DNS rules failed to start: %v", err)
	}
}

func TestModernDNSRulesDoNotPromoteLegacyStrategies(t *testing.T) {
	raw := `{
		"dns": {
			"servers": [{"tag": "default", "type": "local"}],
			"rules": [
				{"domain": "first.example", "server": "default", "strategy": "prefer_ipv6"},
				{"query_type": ["A", "AAAA"], "domain": "second.example", "server": "default", "strategy": "ipv4_only"}
			]
		},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`
	_, parsed := assertBuildsSingBox(t, raw, "")
	dns := parsed["dns"].(object)
	rules := dns["rules"].([]any)
	if dns["strategy"] != nil || len(rules) != 3 || rules[0].(object)["strategy"] != nil || rules[2].(object)["strategy"] != nil {
		t.Fatalf("legacy DNS strategies leaked into modern rules: %v", dns)
	}
	guard := rules[1].(object)
	if guard["domain"] != "second.example" || guard["action"] != "predefined" ||
		len(array(guard["query_type"])) != 1 || array(guard["query_type"])[0] != "AAAA" {
		t.Fatalf("strict address-family policy was not limited to its matching rule: %v", guard)
	}
}

func TestDNSRuleSetWithQueryTypeUsesModernStrategyMigration(t *testing.T) {
	raw := `{
		"dns": {
			"servers": [{"tag": "default", "type": "local"}],
			"rules": [
				{"domain": "first.example", "server": "default", "strategy": "prefer_ipv6"},
				{"rule_set": "address-queries", "server": "default"}
			]
		},
		"route": {"rule_set": [
			{"type": "inline", "tag": "address-queries", "rules": [{"query_type": ["AAAA"]}]}
		]},
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`
	_, parsed := assertBuildsSingBox(t, raw, "")
	dns := parsed["dns"].(object)
	if dns["strategy"] != nil || dns["rules"].([]any)[0].(object)["strategy"] != nil {
		t.Fatalf("inline rule set was not considered during strategy migration: %v", dns)
	}
}

// SPDX-License-Identifier: GPL-3.0-or-later
package configbuilder

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"nekobox-mac/internal/boxconfig"
	"nekobox-mac/internal/macos"
	"nekobox-mac/internal/store"
	"nekobox-mac/internal/xraybridge"
)

const (
	TagMixed  = "mixed-in"
	TagTUN    = "tun-in"
	TagProxy  = "proxy"
	TagDirect = "direct"
	TagBypass = "bypass"
	TagBlock  = "block"
	TagMeta   = "meta-auto"
)

type BuildOptions struct {
	ForTest   bool
	EnableTUN bool
	DataDir   string
	YacdDir   string
	AssetsDir string
}

// BuildSingBoxConfig translates Nekobox-Mac state + selected Profile into a normalized
// sing-box 1.14+ JSON configuration supporting sing-box, Xray, Mihomo, Meta smart routing,
// macOS per-app process_name rules, IPv6 modes, FakeDNS, and Power Saver options.
func BuildSingBoxConfig(st store.State, profile store.Profile, opts BuildOptions) (string, error) {
	// Full custom sing-box config passthrough
	if profile.Type == "full-config" && strings.TrimSpace(profile.CustomFullConfig) != "" {
		raw := profile.CustomFullConfig
		if opts.ForTest {
			raw = sanitizeFullConfigForTest(raw)
		}
		return boxconfig.Normalize(raw, opts.AssetsDir)
	}

	settings := st.Settings
	appProxy := st.AppProxy
	power := st.PowerSaver

	// Build main proxy outbound
	mainOutbound, err := buildOutbound(profile, TagProxy, settings.GlobalAllowInsecure)
	if err != nil {
		return "", fmt.Errorf("build outbound for %s: %w", profile.Name, err)
	}

	outbounds := []map[string]any{
		mainOutbound,
		{"type": "direct", "tag": TagDirect},
		{"type": "direct", "tag": TagBypass},
		{"type": "block", "tag": TagBlock},
	}

	// Extra outbounds referenced by custom route rules
	extraTags := map[int64]string{}
	if !opts.ForTest {
		for _, rule := range st.Rules {
			if !rule.Enabled || !strings.HasPrefix(rule.Outbound, "profile:") {
				continue
			}
			pid, err := strconv.ParseInt(strings.TrimPrefix(rule.Outbound, "profile:"), 10, 64)
			if err != nil || pid <= 0 || pid == profile.ID {
				continue
			}
			if _, exists := extraTags[pid]; exists {
				continue
			}
			for _, p := range st.Profiles {
				if p.ID == pid {
					tag := fmt.Sprintf("p-%d", pid)
					if ob, err := buildOutbound(p, tag, settings.GlobalAllowInsecure); err == nil {
						outbounds = append(outbounds, ob)
						extraTags[pid] = tag
					}
					break
				}
			}
		}
	}

	// Build inbounds
	var inbounds []map[string]any
	useTUN := !opts.ForTest && opts.EnableTUN
	useMeta := !opts.ForTest && appProxy.MetaAutoRouting
	useFakeDNS := !opts.ForTest && settings.EnableFakeDNS && useTUN
	needSniff := settings.TrafficSniffing > 0 || useMeta

	if !opts.ForTest {
		bind := "127.0.0.1"
		if settings.AllowLAN {
			bind = "0.0.0.0"
		}
		if useTUN {
			tunStack := "gvisor"
			if power.MixedTunStack {
				tunStack = "mixed"
			}
			tunIn := map[string]any{
				"type":                     "tun",
				"tag":                      TagTUN,
				"interface_name":           "utun99",
				"address":                  []string{"172.19.0.1/30"},
				"mtu":                      settings.MTU,
				"auto_route":               true,
				"strict_route":             true,
				"stack":                    tunStack,
				"endpoint_independent_nat": true,
				"sniff":                    needSniff,
			}
			if settings.IPv6Mode != "disable" {
				tunIn["address"] = []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
			}
			if settings.TrafficSniffing == 2 {
				tunIn["sniff_override_destination"] = true
			}
			inbounds = append(inbounds, tunIn)
		}

		mixedIn := map[string]any{
			"type":        "mixed",
			"tag":         TagMixed,
			"listen":      bind,
			"listen_port": settings.MixedPort,
			"sniff":       needSniff,
		}
		if settings.TrafficSniffing == 2 {
			mixedIn["sniff_override_destination"] = true
		}
		inbounds = append(inbounds, mixedIn)
	}

	// DNS configuration
	dnsServers := []map[string]any{}
	dnsRules := []map[string]any{}

	directDNSAddr := firstLine(settings.DirectDNS, "https://223.5.5.5/dns-query")
	remoteDNSAddr := firstLine(settings.RemoteDNS, "https://dns.google/dns-query")

	dnsServers = append(dnsServers,
		makeDNSServer("dns-direct", directDNSAddr, TagBypass),
		makeDNSServer("dns-remote", remoteDNSAddr, TagProxy),
		map[string]any{"type": "local", "tag": "dns-local"},
	)
	if useFakeDNS {
		fake := map[string]any{
			"type":        "fakeip",
			"tag":         "dns-fake",
			"inet4_range": "198.18.0.0/15",
		}
		if settings.IPv6Mode != "disable" {
			fake["inet6_range"] = "fc00::/18"
		}
		dnsServers = append(dnsServers, fake)
	}

	// Route rules: Priority #1 Custom Routes > #2 Per-App macOS process_name > #3 Meta Smart Routing
	var routeRules []map[string]any
	findProcess := false

	// Prevent server domain resolution loop
	if profile.Address != "" && net.ParseIP(profile.Address) == nil {
		dnsRules = append(dnsRules, map[string]any{
			"domain": []string{profile.Address},
			"server": "dns-direct",
		})
	}

	if !opts.ForTest {
		// Always direct private IPs & localhost
		routeRules = append(routeRules,
			map[string]any{"action": "sniff"},
			map[string]any{"protocol": "dns", "action": "hijack-dns"},
			map[string]any{"ip_is_private": true, "outbound": TagBypass},
		)

		// #1 Custom routing rules (highest priority)
		for _, r := range st.Rules {
			if !r.Enabled {
				continue
			}
			ruleObj := map[string]any{}
			if domains := splitList(r.Domains); len(domains) > 0 {
				var full, suffix, keyword, regex []string
				for _, d := range domains {
					switch {
					case strings.EqualFold(d, "geosite:private"):
						suffix = append(suffix, "local", "lan", "localhost", "invalid")
					case strings.HasPrefix(strings.ToLower(d), "geosite:"):
						// Avoid referencing external geosite.db when bundled MRS handles Meta routing
						code := strings.TrimSpace(d[len("geosite:"):])
						if code == "cn" {
							suffix = append(suffix, "cn")
						}
					case strings.HasPrefix(d, "full:"):
						full = append(full, strings.TrimPrefix(d, "full:"))
					case strings.HasPrefix(d, "domain:"):
						suffix = append(suffix, strings.TrimPrefix(d, "domain:"))
					case strings.HasPrefix(d, "keyword:"):
						keyword = append(keyword, strings.TrimPrefix(d, "keyword:"))
					case strings.HasPrefix(d, "regexp:"):
						regex = append(regex, strings.TrimPrefix(d, "regexp:"))
					default:
						suffix = append(suffix, d)
					}
				}
				if len(full) > 0 {
					ruleObj["domain"] = full
				}
				if len(suffix) > 0 {
					ruleObj["domain_suffix"] = suffix
				}
				if len(keyword) > 0 {
					ruleObj["domain_keyword"] = keyword
				}
				if len(regex) > 0 {
					ruleObj["domain_regex"] = regex
				}
			}
			if ips := splitList(r.IPs); len(ips) > 0 {
				var cidrs []string
				for _, ip := range ips {
					if strings.EqualFold(ip, "geoip:private") {
						ruleObj["ip_is_private"] = true
						continue
					}
					if !strings.HasPrefix(strings.ToLower(ip), "geoip:") {
						if !strings.Contains(ip, "/") {
							if strings.Contains(ip, ":") {
								ip += "/128"
							} else {
								ip += "/32"
							}
						}
						cidrs = append(cidrs, ip)
					}
				}
				if len(cidrs) > 0 {
					ruleObj["ip_cidr"] = cidrs
				}
			}
			if ports, portRanges := splitPortsAndRanges(r.Ports); len(ports) > 0 || len(portRanges) > 0 {
				if len(ports) > 0 {
					ruleObj["port"] = ports
				}
				if len(portRanges) > 0 {
					ruleObj["port_range"] = portRanges
				}
			}
			if r.Network != "" {
				ruleObj["network"] = r.Network
			}
			if r.Protocol != "" {
				ruleObj["protocol"] = splitList(r.Protocol)
			}
			if procs := splitProcessNames(r.ProcessName); len(procs) > 0 {
				ruleObj["process_name"] = procs
				findProcess = true
			}
			if len(ruleObj) == 0 {
				continue
			}
			// Mirror domain-only direct rules into DNS rules so TUN/FakeDNS also resolves them directly.
			if r.Outbound == "direct" && r.IPs == "" && r.Ports == "" && r.Network == "" && r.Protocol == "" && r.ProcessName == "" {
				dnsDirectRule := map[string]any{"server": "dns-direct"}
				hasDomainCond := false
				for _, k := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex"} {
					if v, ok := ruleObj[k]; ok {
						dnsDirectRule[k] = v
						hasDomainCond = true
					}
				}
				if hasDomainCond {
					dnsRules = append(dnsRules, dnsDirectRule)
				}
			}
			switch {
			case r.Outbound == "direct":
				ruleObj["outbound"] = TagBypass
			case r.Outbound == "block":
				ruleObj["action"] = "reject"
			case strings.HasPrefix(r.Outbound, "profile:"):
				pid, _ := strconv.ParseInt(strings.TrimPrefix(r.Outbound, "profile:"), 10, 64)
				if tag, ok := extraTags[pid]; ok {
					ruleObj["outbound"] = tag
				} else {
					ruleObj["outbound"] = TagProxy
				}
			default:
				ruleObj["outbound"] = TagProxy
			}
			routeRules = append(routeRules, ruleObj)
		}

		// #2 Per-App macOS routing via process_path_regex (.app bundle + all Helpers/XPC) + process_name (OR semantics)
		bypassProcs, bypassPathRegexes, forceProxyProcs, forceProxyPathRegexes := collectPerAppMatchers(appProxy)
		if len(forceProxyPathRegexes) > 0 {
			findProcess = true
			routeRules = append(routeRules, map[string]any{
				"process_path_regex": forceProxyPathRegexes,
				"outbound":           TagProxy,
			})
			if useFakeDNS {
				dnsRules = append(dnsRules, map[string]any{
					"inbound":            []string{TagTUN},
					"process_path_regex": forceProxyPathRegexes,
					"query_type":         []string{"A", "AAAA"},
					"server":             "dns-fake",
					"disable_cache":      true,
				})
			}
			dnsRules = append(dnsRules, map[string]any{
				"process_path_regex": forceProxyPathRegexes,
				"server":             "dns-remote",
			})
		}
		if len(forceProxyProcs) > 0 {
			findProcess = true
			routeRules = append(routeRules, map[string]any{
				"process_name": forceProxyProcs,
				"outbound":     TagProxy,
			})
			if useFakeDNS {
				dnsRules = append(dnsRules, map[string]any{
					"inbound":       []string{TagTUN},
					"process_name":  forceProxyProcs,
					"query_type":    []string{"A", "AAAA"},
					"server":        "dns-fake",
					"disable_cache": true,
				})
			}
			dnsRules = append(dnsRules, map[string]any{
				"process_name": forceProxyProcs,
				"server":       "dns-remote",
			})
		}
		if len(bypassPathRegexes) > 0 {
			findProcess = true
			routeRules = append(routeRules, map[string]any{
				"process_path_regex": bypassPathRegexes,
				"outbound":           TagBypass,
			})
			dnsRules = append(dnsRules, map[string]any{
				"process_path_regex": bypassPathRegexes,
				"server":             "dns-direct",
			})
		}
		if len(bypassProcs) > 0 {
			findProcess = true
			routeRules = append(routeRules, map[string]any{
				"process_name": bypassProcs,
				"outbound":     TagBypass,
			})
			dnsRules = append(dnsRules, map[string]any{
				"process_name": bypassProcs,
				"server":       "dns-direct",
			})
		}

		// #3 Meta Smart Routing (mihomo-routing + mihomo-dns with 17 bundled MRS rule sets)
		if useMeta {
			if !power.SmartFindProcess {
				findProcess = true
			}
			outbounds = append(outbounds, map[string]any{
				"type":        "mihomo-routing",
				"tag":         TagMeta,
				"proxy":       TagProxy,
				"direct":      TagBypass,
				"rule_source": appProxy.MetaRuleSource,
				"mode":        appProxy.MetaRoutingMode,
				"block_ads":   appProxy.MetaBlockAds,
			})
			metaInbounds := []string{TagMixed}
			if useTUN {
				metaInbounds = append([]string{TagTUN}, metaInbounds...)
			}
			routeRules = append(routeRules, map[string]any{
				"inbound":  metaInbounds,
				"outbound": TagMeta,
			})
			dnsServers = append(dnsServers, map[string]any{
				"type":    "mihomo-dns",
				"tag":     "dns-meta",
				"direct":  "dns-direct",
				"remote":  "dns-remote",
				"routing": TagMeta,
			})
			if useFakeDNS {
				dnsServers = append(dnsServers, map[string]any{
					"type":    "mihomo-dns",
					"tag":     "dns-meta-tun",
					"direct":  "dns-direct",
					"remote":  "dns-fake",
					"routing": TagMeta,
				})
				dnsRules = append(dnsRules, map[string]any{
					"inbound":       []string{TagTUN},
					"query_type":    []string{"A", "AAAA"},
					"server":        "dns-meta-tun",
					"disable_cache": true,
				})
			}
			dnsRules = append(dnsRules, map[string]any{
				"inbound": metaInbounds,
				"server":  "dns-meta",
			})
		}
	}

	finalDNS := "dns-remote"
	if opts.ForTest {
		finalDNS = "dns-direct"
	} else if useMeta {
		finalDNS = "dns-meta"
	}

	routeObj := map[string]any{
		"auto_detect_interface": true,
		"default_domain_resolver": map[string]any{
			"server": "dns-direct",
		},
		"final": TagProxy,
		"rules": routeRules,
	}
	if findProcess {
		routeObj["find_process"] = true
	}

	dnsObj := map[string]any{
		"servers":           dnsServers,
		"rules":             dnsRules,
		"final":             finalDNS,
		"independent_cache": true,
	}
	switch settings.IPv6Mode {
	case "disable":
		dnsObj["strategy"] = "ipv4_only"
	case "prefer":
		dnsObj["strategy"] = "prefer_ipv6"
	case "only":
		dnsObj["strategy"] = "ipv6_only"
	default:
		dnsObj["strategy"] = "prefer_ipv4"
	}

	root := map[string]any{
		"log": map[string]any{
			"level":     settings.LogLevel,
			"timestamp": true,
		},
		"dns":       dnsObj,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     routeObj,
	}

	if !opts.ForTest {
		exp := map[string]any{}
		cachePath := "cache.db"
		if opts.DataDir != "" {
			cachePath = filepath.Join(opts.DataDir, "cache.db")
		}
		exp["cache_file"] = map[string]any{
			"enabled":      true,
			"path":         cachePath,
			"store_fakeip": useFakeDNS,
		}
		if settings.EnableClashAPI {
			clashAPI := map[string]any{
				"external_controller": fmt.Sprintf("127.0.0.1:%d", settings.ClashAPIPort),
			}
			if settings.ClashAPISecret != "" {
				clashAPI["secret"] = settings.ClashAPISecret
			}
			if opts.YacdDir != "" {
				clashAPI["external_ui"] = opts.YacdDir
			}
			exp["clash_api"] = clashAPI
		}
		root["experimental"] = exp
	}

	raw, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}
	return boxconfig.Normalize(string(raw), opts.AssetsDir)
}

func buildOutbound(p store.Profile, tag string, globalAllowInsecure bool) (map[string]any, error) {
	// Custom outbound JSON override
	if strings.TrimSpace(p.CustomOutbound) != "" {
		var ob map[string]any
		if err := json.Unmarshal([]byte(p.CustomOutbound), &ob); err != nil {
			return nil, fmt.Errorf("invalid custom outbound json: %w", err)
		}
		ob["tag"] = tag
		return ob, nil
	}

	// Raw outbound from Xray / Mihomo / sing-box JSON import
	if len(p.RawOutbound) > 0 {
		cp := make(map[string]any, len(p.RawOutbound)+1)
		for k, v := range p.RawOutbound {
			cp[k] = v
		}
		cp["tag"] = tag
		return cp, nil
	}

	getS := func(k string) string { return strVal(p.Params[k]) }
	getI := func(k string, def int) int { return intVal(p.Params[k], def) }
	getB := func(k string) bool { return boolVal(p.Params[k]) }
	insecure := globalAllowInsecure || getB("allowInsecure")

	// Explicit core selection overrides
	if strings.EqualFold(p.Core, "mihomo") && p.Type != "naive" {
		return buildMihomoOutbound(p, tag, insecure), nil
	}
	if strings.EqualFold(p.Core, "xray") {
		if xob, err := buildXrayOutbound(p, tag); err == nil {
			return xob, nil
		}
	}

	// Mihomo-native protocols
	switch p.Type {
	case "ssr", "amneziawg", "masque", "mieru", "snell", "trusttunnel", "sudoku", "shadowquic":
		return buildMihomoOutbound(p, tag, insecure), nil
	}

	switch p.Type {
	case "vless":
		ob := map[string]any{
			"type":        "vless",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"uuid":        getS("uuid"),
		}
		if v := getS("flow"); v != "" {
			ob["flow"] = v
		}
		if v := getS("packetEncoding"); v != "" {
			ob["packet_encoding"] = v
		}
		attachTLS(ob, p, insecure)
		attachTransport(ob, p)
		return ob, nil

	case "vmess":
		ob := map[string]any{
			"type":        "vmess",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"uuid":        getS("uuid"),
			"security":    firstNonEmpty(getS("cipher"), "auto"),
			"alter_id":    getI("alterId", 0),
		}
		attachTLS(ob, p, insecure)
		attachTransport(ob, p)
		return ob, nil

	case "trojan", "trojan-go":
		ob := map[string]any{
			"type":        "trojan",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"password":    getS("password"),
		}
		attachTLS(ob, p, insecure)
		attachTransport(ob, p)
		return ob, nil

	case "shadowsocks":
		ob := map[string]any{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"method":      getS("method"),
			"password":    getS("password"),
		}
		if v := getS("plugin"); v != "" {
			ob["plugin"] = v
			if opts := getS("pluginOpts"); opts != "" {
				ob["plugin_opts"] = opts
			}
		}
		if getB("uot") {
			ob["udp_over_tcp"] = true
		}
		return ob, nil

	case "hysteria2":
		ob := map[string]any{
			"type":        "hysteria2",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"password":    getS("password"),
		}
		if up := getI("upMbps", 0); up > 0 {
			ob["up_mbps"] = up
		}
		if down := getI("downMbps", 0); down > 0 {
			ob["down_mbps"] = down
		}
		if obfs := getS("obfs"); obfs != "" {
			ob["obfs"] = map[string]any{
				"type":     obfs,
				"password": getS("obfsPassword"),
			}
		}
		if mport := getS("mport"); mport != "" {
			ob["server_ports"] = strings.Split(strings.ReplaceAll(mport, "-", ":"), ",")
		}
		tlsCfg := map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(getS("sni"), p.Address),
			"insecure":    insecure,
		}
		if pin := getS("pinSHA256"); pin != "" {
			tlsCfg["certificate_public_key_sha256"] = []string{pin}
		}
		ob["tls"] = tlsCfg
		return ob, nil

	case "hysteria":
		return map[string]any{
			"type":        "hysteria",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"auth_str":    getS("auth"),
			"up_mbps":     getI("upMbps", 50),
			"down_mbps":   getI("downMbps", 100),
			"obfs":        getS("obfs"),
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(getS("sni"), p.Address),
				"insecure":    insecure,
			},
		}, nil

	case "tuic":
		tlsCfg := map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(getS("sni"), p.Address),
			"insecure":    insecure,
			"alpn":        splitList(firstNonEmpty(getS("alpn"), "h3")),
		}
		if getB("disableSni") {
			tlsCfg["disable_sni"] = true
		}
		return map[string]any{
			"type":               "tuic",
			"tag":                tag,
			"server":             p.Address,
			"server_port":        p.Port,
			"uuid":               getS("uuid"),
			"password":           getS("password"),
			"congestion_control": firstNonEmpty(getS("congestionControl"), "bbr"),
			"udp_relay_mode":     firstNonEmpty(getS("udpRelayMode"), "native"),
			"zero_rtt_handshake": getB("zeroRttHandshake"),
			"heartbeat":          firstNonEmpty(getS("heartbeat"), "10s"),
			"tls":                tlsCfg,
		}, nil

	case "anytls":
		tlsCfg := map[string]any{
			"enabled":     true,
			"server_name": firstNonEmpty(getS("sni"), p.Address),
			"insecure":    insecure,
		}
		if fp := getS("fp"); fp != "" {
			tlsCfg["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if alpn := splitList(getS("alpn")); len(alpn) > 0 {
			tlsCfg["alpn"] = alpn
		}
		ob := map[string]any{
			"type":                        "anytls",
			"tag":                         tag,
			"server":                      p.Address,
			"server_port":                 p.Port,
			"password":                    getS("password"),
			"idle_session_check_interval": firstNonEmpty(getS("idleSessionCheckInterval"), "30s"),
			"idle_session_timeout":        firstNonEmpty(getS("idleSessionTimeout"), "30s"),
			"tls":                         tlsCfg,
		}
		if minIdle := getI("minIdleSession", 0); minIdle > 0 {
			ob["min_idle_session"] = minIdle
		}
		return ob, nil

	case "wireguard":
		addrs := splitList(firstNonEmpty(getS("address"), "172.16.0.2/32"))
		ob := map[string]any{
			"type":            "wireguard",
			"tag":             tag,
			"server":          p.Address,
			"server_port":     p.Port,
			"local_address":   addrs,
			"private_key":     getS("privateKey"),
			"peer_public_key": getS("publicKey"),
			"mtu":             getI("mtu", 1420),
		}
		if psk := getS("presharedKey"); psk != "" {
			ob["pre_shared_key"] = psk
		}
		return ob, nil

	case "socks":
		ob := map[string]any{
			"type":        "socks",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"version":     firstNonEmpty(getS("version"), "5"),
		}
		if u := getS("username"); u != "" {
			ob["username"] = u
			ob["password"] = getS("password")
		}
		return ob, nil

	case "http":
		ob := map[string]any{
			"type":        "http",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
		}
		if u := getS("username"); u != "" {
			ob["username"] = u
			ob["password"] = getS("password")
		}
		if getB("tls") {
			ob["tls"] = map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(getS("sni"), p.Address),
				"insecure":    insecure,
			}
		}
		return ob, nil

	case "ssh":
		ob := map[string]any{
			"type":        "ssh",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"user":        getS("username"),
		}
		if pw := getS("password"); pw != "" {
			ob["password"] = pw
		}
		if pk := getS("privateKey"); pk != "" {
			ob["private_key"] = pk
		}
		return ob, nil

	case "naive":
		ob := map[string]any{
			"type":        "http",
			"tag":         tag,
			"server":      p.Address,
			"server_port": p.Port,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": firstNonEmpty(getS("sni"), p.Address),
				"insecure":    insecure,
			},
		}
		if u := getS("username"); u != "" {
			ob["username"] = u
			ob["password"] = getS("password")
		}
		return ob, nil

	default:
		// Route any additional Clash/Mihomo protocol cleanly through mihomobridge
		return buildMihomoOutbound(p, tag, insecure), nil
	}
}

func buildXrayOutbound(p store.Profile, tag string) (map[string]any, error) {
	uri := formatXrayShareURI(p)
	if uri == "" {
		return nil, fmt.Errorf("protocol %s does not support Xray share bridge", p.Type)
	}
	wrapped, err := xraybridge.ParseShareLink(uri)
	if err != nil || wrapped == "" {
		return nil, fmt.Errorf("xray bridge parse: %w", err)
	}
	var ob map[string]any
	if err := json.Unmarshal([]byte(wrapped), &ob); err != nil {
		return nil, err
	}
	ob["tag"] = tag
	return ob, nil
}

func formatXrayShareURI(p store.Profile) string {
	hostPort := net.JoinHostPort(p.Address, strconv.Itoa(p.Port))
	getS := func(k string) string { return strVal(p.Params[k]) }
	q := url.Values{}
	q.Set("core", "xray")

	switch p.Type {
	case "vless":
		q.Set("encryption", firstNonEmpty(getS("encryption"), "none"))
		if v := getS("security"); v != "" {
			q.Set("security", v)
		}
		if v := getS("flow"); v != "" {
			q.Set("flow", v)
		}
		if v := getS("sni"); v != "" {
			q.Set("sni", v)
		}
		if v := getS("fp"); v != "" {
			q.Set("fp", v)
		}
		if v := getS("pbk"); v != "" {
			q.Set("pbk", v)
		}
		if v := getS("sid"); v != "" {
			q.Set("sid", v)
		}
		if v := getS("spx"); v != "" {
			q.Set("spx", v)
		}
		if v := getS("transport"); v != "" {
			q.Set("type", v)
		}
		if v := getS("host"); v != "" {
			q.Set("host", v)
		}
		if v := getS("path"); v != "" {
			q.Set("path", v)
		}
		if v := getS("serviceName"); v != "" {
			q.Set("serviceName", v)
		}
		if v := getS("mode"); v != "" {
			q.Set("mode", v)
		}
		return fmt.Sprintf("vless://%s@%s?%s", url.User(getS("uuid")).String(), hostPort, q.Encode())
	case "trojan", "trojan-go":
		if v := getS("security"); v != "" {
			q.Set("security", v)
		}
		if v := getS("sni"); v != "" {
			q.Set("sni", v)
		}
		if v := getS("transport"); v != "" {
			q.Set("type", v)
		}
		if v := getS("host"); v != "" {
			q.Set("host", v)
		}
		if v := getS("path"); v != "" {
			q.Set("path", v)
		}
		return fmt.Sprintf("trojan://%s@%s?%s", url.User(getS("password")).String(), hostPort, q.Encode())
	case "vmess":
		q.Set("encryption", firstNonEmpty(getS("cipher"), "auto"))
		if v := getS("security"); v != "" {
			q.Set("security", v)
		}
		if v := getS("sni"); v != "" {
			q.Set("sni", v)
		}
		if v := getS("transport"); v != "" {
			q.Set("type", v)
		}
		if v := getS("host"); v != "" {
			q.Set("host", v)
		}
		if v := getS("path"); v != "" {
			q.Set("path", v)
		}
		return fmt.Sprintf("vmess://%s@%s?%s", url.User(getS("uuid")).String(), hostPort, q.Encode())
	case "shadowsocks":
		cred := base64.RawURLEncoding.EncodeToString([]byte(getS("method") + ":" + getS("password")))
		return fmt.Sprintf("ss://%s@%s?%s", cred, hostPort, q.Encode())
	default:
		return ""
	}
}

func buildMihomoOutbound(p store.Profile, tag string, insecure bool) map[string]any {
	getS := func(k string) string { return strVal(p.Params[k]) }
	getI := func(k string, def int) int { return intVal(p.Params[k], def) }

	proxy := map[string]any{
		"name":   firstNonEmpty(p.Name, tag),
		"type":   p.Type,
		"server": p.Address,
		"port":   p.Port,
	}
	switch p.Type {
	case "shadowsocks":
		proxy["type"] = "ss"
		proxy["cipher"] = firstNonEmpty(getS("method"), getS("cipher"))
		proxy["password"] = getS("password")
		proxy["udp"] = true
	case "vless":
		proxy["uuid"] = getS("uuid")
		proxy["udp"] = true
		if f := getS("flow"); f != "" {
			proxy["flow"] = f
		}
		if sec := strings.ToLower(getS("security")); sec == "tls" || sec == "reality" {
			proxy["tls"] = true
			proxy["servername"] = firstNonEmpty(getS("sni"), p.Address)
			proxy["skip-cert-verify"] = insecure
			if fp := getS("fp"); fp != "" {
				proxy["client-fingerprint"] = fp
			}
			if sec == "reality" {
				proxy["reality-opts"] = map[string]any{
					"public-key": getS("pbk"),
					"short-id":   getS("sid"),
				}
			}
		}
		if tr := strings.ToLower(getS("transport")); tr != "" && tr != "tcp" {
			proxy["network"] = tr
			if tr == "ws" {
				wsOpts := map[string]any{"path": firstNonEmpty(getS("path"), "/")}
				if h := getS("host"); h != "" {
					wsOpts["headers"] = map[string]any{"Host": h}
				}
				proxy["ws-opts"] = wsOpts
			} else if tr == "grpc" {
				proxy["grpc-opts"] = map[string]any{"grpc-service-name": firstNonEmpty(getS("serviceName"), getS("path"))}
			}
		}
	case "vmess":
		proxy["uuid"] = getS("uuid")
		proxy["alterId"] = getI("alterId", 0)
		proxy["cipher"] = firstNonEmpty(getS("cipher"), "auto")
		proxy["udp"] = true
		if strings.EqualFold(getS("security"), "tls") {
			proxy["tls"] = true
			proxy["servername"] = firstNonEmpty(getS("sni"), p.Address)
			proxy["skip-cert-verify"] = insecure
		}
		if tr := strings.ToLower(getS("transport")); tr != "" && tr != "tcp" {
			proxy["network"] = tr
			if tr == "ws" {
				wsOpts := map[string]any{"path": firstNonEmpty(getS("path"), "/")}
				if h := getS("host"); h != "" {
					wsOpts["headers"] = map[string]any{"Host": h}
				}
				proxy["ws-opts"] = wsOpts
			} else if tr == "grpc" {
				proxy["grpc-opts"] = map[string]any{"grpc-service-name": firstNonEmpty(getS("serviceName"), getS("path"))}
			}
		}
	case "trojan", "trojan-go":
		proxy["type"] = "trojan"
		proxy["password"] = getS("password")
		proxy["sni"] = firstNonEmpty(getS("sni"), p.Address)
		proxy["skip-cert-verify"] = insecure
		proxy["udp"] = true
	case "hysteria2":
		proxy["password"] = getS("password")
		proxy["sni"] = firstNonEmpty(getS("sni"), p.Address)
		proxy["skip-cert-verify"] = insecure
		if obfs := getS("obfs"); obfs != "" {
			proxy["obfs"] = obfs
			proxy["obfs-password"] = getS("obfsPassword")
		}
	case "tuic":
		proxy["uuid"] = getS("uuid")
		proxy["password"] = getS("password")
		proxy["sni"] = firstNonEmpty(getS("sni"), p.Address)
		proxy["skip-cert-verify"] = insecure
		proxy["udp-relay-mode"] = firstNonEmpty(getS("udpRelayMode"), "native")
		proxy["congestion-controller"] = firstNonEmpty(getS("congestionControl"), "bbr")
	case "anytls":
		proxy["password"] = getS("password")
		proxy["sni"] = firstNonEmpty(getS("sni"), p.Address)
		proxy["skip-cert-verify"] = insecure
		proxy["udp"] = true
		if fp := getS("fp"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
	case "wireguard":
		proxy["private-key"] = getS("privateKey")
		proxy["public-key"] = getS("publicKey")
		proxy["ip"] = firstNonEmpty(strings.Split(getS("address"), ",")[0], "172.16.0.2/32")
		proxy["mtu"] = getI("mtu", 1420)
		proxy["udp"] = true
	case "socks":
		proxy["type"] = "socks5"
		proxy["udp"] = true
		if u := getS("username"); u != "" {
			proxy["username"] = u
			proxy["password"] = getS("password")
		}
	case "ssr":
		proxy["password"] = getS("password")
		proxy["cipher"] = getS("cipher")
		proxy["protocol"] = getS("protocol")
		proxy["protocol-param"] = getS("protocolParam")
		proxy["obfs"] = getS("obfs")
		proxy["obfs-param"] = getS("obfsParam")
	case "amneziawg":
		proxy["type"] = "wireguard"
		proxy["private-key"] = getS("privateKey")
		proxy["public-key"] = getS("publicKey")
		proxy["ip"] = firstNonEmpty(strings.Split(getS("address"), ",")[0], "172.16.0.2/32")
		proxy["mtu"] = getI("mtu", 1420)
		proxy["udp"] = true
		awg := map[string]any{}
		for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"} {
			if v := getI(k, 0); v > 0 {
				awg[k] = v
			}
		}
		if len(awg) > 0 {
			proxy["amnezia-wg-option"] = awg
		}
	case "masque":
		proxy["private-key"] = getS("privateKey")
		proxy["public-key"] = getS("publicKey")
		proxy["ip"] = firstNonEmpty(getS("ip"), "172.16.0.2/32")
		if v := getS("ipv6"); v != "" {
			proxy["ipv6"] = v
		}
		proxy["mtu"] = getI("mtu", 1280)
		proxy["udp"] = true
		if sni := getS("sni"); sni != "" {
			proxy["sni"] = sni
		}
	case "mieru":
		proxy["username"] = getS("username")
		proxy["password"] = getS("password")
		proxy["transport"] = firstNonEmpty(getS("transport"), "TCP")
		proxy["multiplexing"] = firstNonEmpty(getS("multiplexing"), "MULTIPLEXING_LOW")
		if pr := getS("portRange"); pr != "" {
			proxy["port-range"] = pr
		}
	case "snell":
		proxy["psk"] = getS("psk")
		proxy["version"] = getI("version", 4)
		if obfs := getS("obfs"); obfs != "" {
			proxy["obfs-opts"] = map[string]any{
				"mode": obfs,
				"host": getS("obfsHost"),
			}
		}
	default:
		for k, v := range p.Params {
			if _, exists := proxy[k]; !exists {
				proxy[k] = v
			}
		}
		if insecure {
			proxy["skip-cert-verify"] = true
		}
	}
	return map[string]any{
		"type":  "mihomo",
		"tag":   tag,
		"proxy": proxy,
	}
}

func attachTLS(ob map[string]any, p store.Profile, insecure bool) {
	getS := func(k string) string { return strVal(p.Params[k]) }
	sec := strings.ToLower(getS("security"))
	if sec == "" && (p.Type == "trojan" || p.Type == "trojan-go") {
		sec = "tls"
	}
	if sec != "tls" && sec != "reality" {
		return
	}
	tlsCfg := map[string]any{
		"enabled":     true,
		"server_name": firstNonEmpty(getS("sni"), p.Address),
		"insecure":    insecure,
	}
	if alpn := splitList(getS("alpn")); len(alpn) > 0 {
		tlsCfg["alpn"] = alpn
	}
	if fp := getS("fp"); fp != "" {
		tlsCfg["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": fp,
		}
	}
	if sec == "reality" {
		tlsCfg["reality"] = map[string]any{
			"enabled":    true,
			"public_key": getS("pbk"),
			"short_id":   getS("sid"),
		}
		if tlsCfg["utls"] == nil {
			tlsCfg["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": "chrome",
			}
		}
	}
	ob["tls"] = tlsCfg
}

func attachTransport(ob map[string]any, p store.Profile) {
	getS := func(k string) string { return strVal(p.Params[k]) }
	tr := strings.ToLower(getS("transport"))
	switch tr {
	case "ws":
		ws := map[string]any{
			"type": "ws",
			"path": firstNonEmpty(getS("path"), "/"),
		}
		if h := getS("host"); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		ob["transport"] = ws
	case "grpc":
		ob["transport"] = map[string]any{
			"type":         "grpc",
			"service_name": firstNonEmpty(getS("serviceName"), getS("path")),
		}
	case "http", "h2":
		httpTr := map[string]any{
			"type": "http",
			"path": firstNonEmpty(getS("path"), "/"),
		}
		if h := getS("host"); h != "" {
			httpTr["host"] = splitList(h)
		}
		ob["transport"] = httpTr
	case "httpupgrade":
		ob["transport"] = map[string]any{
			"type": "httpupgrade",
			"host": getS("host"),
			"path": firstNonEmpty(getS("path"), "/"),
		}
	}
}

func makeDNSServer(tag, rawAddr, detour string) map[string]any {
	addr := strings.TrimSpace(rawAddr)
	if addr == "" || addr == "local" {
		return map[string]any{"type": "local", "tag": tag}
	}
	// Let boxconfig.Normalize upgrade legacy string address format cleanly
	srv := map[string]any{
		"tag":     tag,
		"address": addr,
		"detour":  detour,
	}
	if strings.HasPrefix(addr, "https://") || strings.HasPrefix(addr, "tls://") || strings.HasPrefix(addr, "quic://") {
		srv["address_resolver"] = "dns-local"
	}
	return srv
}

func sanitizeFullConfigForTest(raw string) string {
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return raw
	}
	root["inbounds"] = []any{}
	if exp, ok := root["experimental"].(map[string]any); ok {
		delete(exp, "clash_api")
		delete(exp, "cache_file")
	}
	if route, ok := root["route"].(map[string]any); ok {
		delete(route, "rules")
		delete(route, "rule_set")
	}
	out, err := json.Marshal(root)
	if err != nil {
		return raw
	}
	return string(out)
}

func firstLine(s, def string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return def
}

func collectPerAppMatchers(appProxy store.AppProxyConfig) (bypassProcs, bypassPathRegexes, forceProxyProcs, forceProxyPathRegexes []string) {
	if len(appProxy.AppActions) == 0 {
		return nil, nil, nil, nil
	}

	// Lazily inspect installed macOS apps if any configured bundle lacks path or process metadata
	// (e.g. legacy state.json created before appPathMap was stored).
	needLookup := false
	for bundleID, action := range appProxy.AppActions {
		if action != "bypass" && action != "force_proxy" {
			continue
		}
		if strings.TrimSpace(appProxy.AppPathMap[bundleID]) == "" || strings.TrimSpace(appProxy.AppProcessMap[bundleID]) == "" {
			needLookup = true
			break
		}
	}
	var installed map[string]macos.InstalledApp
	if needLookup {
		installed = macos.LookupInstalledAppsByBundleID()
	}

	addUnique := func(dst *[]string, seen map[string]bool, val string) {
		val = strings.TrimSpace(val)
		if val == "" || seen[val] {
			return
		}
		seen[val] = true
		*dst = append(*dst, val)
	}
	addPathRegex := func(dst *[]string, seen map[string]bool, rawPath string) {
		rawPath = strings.TrimSpace(rawPath)
		if rawPath == "" {
			return
		}
		clean := filepath.Clean(rawPath)
		pattern := "^" + regexp.QuoteMeta(clean) + "(/|$)"
		addUnique(dst, seen, pattern)
		if resolved, err := filepath.EvalSymlinks(clean); err == nil && resolved != "" && resolved != clean {
			addUnique(dst, seen, "^"+regexp.QuoteMeta(filepath.Clean(resolved))+"(/|$)")
		}
	}

	bypassProcSeen := map[string]bool{}
	bypassPathSeen := map[string]bool{}
	forceProcSeen := map[string]bool{}
	forcePathSeen := map[string]bool{}

	for bundleID, action := range appProxy.AppActions {
		if action != "bypass" && action != "force_proxy" {
			continue
		}
		proc := strings.TrimSpace(appProxy.AppProcessMap[bundleID])
		appPath := strings.TrimSpace(appProxy.AppPathMap[bundleID])
		if info, ok := installed[bundleID]; ok {
			if proc == "" {
				proc = strings.TrimSpace(info.ProcessName)
			}
			if appPath == "" {
				appPath = strings.TrimSpace(info.Path)
			}
		}
		extras := macos.ExtraProcessNamesForBundle(bundleID)

		if action == "bypass" {
			addUnique(&bypassProcs, bypassProcSeen, proc)
			for _, extra := range extras {
				addUnique(&bypassProcs, bypassProcSeen, extra)
			}
			addPathRegex(&bypassPathRegexes, bypassPathSeen, appPath)
		} else {
			addUnique(&forceProxyProcs, forceProcSeen, proc)
			for _, extra := range extras {
				addUnique(&forceProxyProcs, forceProcSeen, extra)
			}
			addPathRegex(&forceProxyPathRegexes, forcePathSeen, appPath)
		}
	}

	slices.Sort(bypassProcs)
	slices.Sort(bypassPathRegexes)
	slices.Sort(forceProxyProcs)
	slices.Sort(forceProxyPathRegexes)
	return
}

func splitProcessNames(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	// macOS executable names frequently contain spaces (e.g. "Google Chrome Helper");
	// split only on newlines, commas, and semicolons.
	replacer := strings.NewReplacer("\r\n", "\n", ",", "\n", "，", "\n", ";", "\n", "；", "\n")
	var res []string
	for _, item := range strings.Split(replacer.Replace(s), "\n") {
		item = strings.TrimSpace(item)
		if item != "" {
			res = append(res, item)
		}
	}
	return res
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	replacer := strings.NewReplacer("\r\n", "\n", ",", "\n", " ", "\n")
	var res []string
	for _, item := range strings.Split(replacer.Replace(s), "\n") {
		item = strings.TrimSpace(item)
		if item != "" {
			res = append(res, item)
		}
	}
	return res
}

func splitPortsAndRanges(s string) ([]uint16, []string) {
	var ports []uint16
	var ranges []string
	for _, part := range splitList(s) {
		norm := strings.ReplaceAll(part, "-", ":")
		if aStr, bStr, ok := strings.Cut(norm, ":"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(aStr))
			b, err2 := strconv.Atoi(strings.TrimSpace(bStr))
			if err1 == nil && err2 == nil && a > 0 && b <= 65535 && a <= b {
				ranges = append(ranges, fmt.Sprintf("%d:%d", a, b))
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n > 0 && n <= 65535 {
			ports = append(ports, uint16(n))
		}
	}
	return ports, ranges
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func strVal(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case int:
		return strconv.Itoa(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func intVal(v any, def int) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	}
	return def
}

func boolVal(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		low := strings.ToLower(strings.TrimSpace(x))
		return low == "true" || low == "1" || low == "yes"
	case float64:
		return x != 0
	case int:
		return x != 0
	default:
		return false
	}
}

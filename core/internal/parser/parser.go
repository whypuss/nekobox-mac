// SPDX-License-Identifier: GPL-3.0-or-later
package parser

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"nekobox-mac/internal/mihomobridge"
	"nekobox-mac/internal/store"
	"nekobox-mac/internal/xraybridge"
)

var ErrDoHSubscriptionURL = errors.New("该链接是 DoH 加密 DNS 地址，而非节点订阅链接，请检查并替换为正确的订阅地址")

// IsDoHURL detects accidentally pasted DoH URLs (/dns-query) like Nekobox-Next v1.5.2+.
func IsDoHURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	p := strings.TrimRight(strings.ToLower(u.Path), "/")
	return p == "/dns-query" || strings.HasSuffix(p, "/dns-query")
}

// ParseInput parses single/multi-line share URIs, Base64 subscription payloads,
// Clash/Mihomo YAML, sing-box JSON, Xray JSON, WireGuard/AmneziaWG .conf, and usque config.json.
func ParseInput(raw string) ([]store.Profile, error) {
	text := strings.TrimSpace(strings.TrimPrefix(raw, "\xef\xbb\xbf"))
	if text == "" {
		return nil, errors.New("输入内容为空")
	}

	// 1. JSON formats (sing-box config/outbound, Xray config/outbound, usque MASQUE config.json)
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		if list, err := parseJSONInput(text); err == nil && len(list) > 0 {
			return list, nil
		}
	}

	// 2. WireGuard / AmneziaWG INI .conf
	if strings.Contains(text, "[Interface]") && strings.Contains(text, "[Peer]") {
		if p, err := parseWireGuardConf(text); err == nil {
			return []store.Profile{p}, nil
		}
	}

	// 3. Clash / Mihomo YAML (proxies: ...)
	if strings.Contains(text, "proxies:") || strings.Contains(text, "\n- name:") || strings.HasPrefix(text, "- name:") {
		if list, err := parseClashYAML(text); err == nil && len(list) > 0 {
			return list, nil
		}
	}

	// 4. Plain URI list
	if list := parseLines(text); len(list) > 0 {
		return list, nil
	}

	// 5. Base64-encoded subscription payload
	if decoded, ok := tryDecodeBase64(text); ok {
		decoded = strings.TrimSpace(decoded)
		if strings.Contains(decoded, "proxies:") {
			if list, err := parseClashYAML(decoded); err == nil && len(list) > 0 {
				return list, nil
			}
		}
		if list := parseLines(decoded); len(list) > 0 {
			return list, nil
		}
	}

	return nil, errors.New("未识别到有效节点或订阅格式")
}

func parseLines(text string) []store.Profile {
	lines := strings.Split(text, "\n")
	var out []store.Profile
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if p, err := ParseURI(line); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// ParseURI parses a single Nekobox-Next compatible share link.
func ParseURI(link string) (store.Profile, error) {
	link = strings.TrimSpace(link)
	idx := strings.Index(link, "://")
	if idx <= 0 {
		return store.Profile{}, errors.New("invalid uri")
	}
	scheme := strings.ToLower(link[:idx])
	switch scheme {
	case "vless":
		return parseVLESS(link)
	case "vmess":
		return parseVMess(link)
	case "trojan":
		return parseTrojan(link, "trojan")
	case "trojan-go":
		return parseTrojan(link, "trojan-go")
	case "ss":
		return parseShadowsocks(link)
	case "ssr":
		return parseSSR(link)
	case "hy2", "hysteria2":
		return parseHysteria2(link)
	case "hysteria", "hy":
		return parseHysteria1(link)
	case "tuic":
		return parseTUIC(link)
	case "anytls":
		return parseAnyTLS(link)
	case "wg", "wireguard":
		return parseWireGuardURI(link, false)
	case "awg", "amneziawg":
		return parseWireGuardURI(link, true)
	case "masque":
		return parseMASQUE(link)
	case "mieru", "mierus":
		return parseMieru(link)
	case "snell":
		return parseSnell(link)
	case "trusttunnel":
		return parseGenericMihomoURI(link, "trusttunnel")
	case "sudoku":
		return parseGenericMihomoURI(link, "sudoku")
	case "shadowquic":
		return parseGenericMihomoURI(link, "shadowquic")
	case "socks", "socks5", "socks4", "socks4a":
		return parseSocks(link, scheme)
	case "http", "https":
		return parseHTTP(link, scheme == "https")
	case "ssh":
		return parseSSH(link)
	case "naive+https", "naive+quic":
		return parseNaive(link, scheme)
	default:
		return store.Profile{}, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func parseVLESS(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	name := decodeFragment(u.Fragment, host, port)
	flow := q.Get("flow")
	if strings.EqualFold(flow, "none") {
		flow = ""
	}
	flow = strings.TrimSuffix(flow, "-udp443")

	transport := strings.ToLower(firstNonEmpty(q.Get("type"), "tcp"))
	security := strings.ToLower(firstNonEmpty(q.Get("security"), "none"))
	encryption := firstNonEmpty(q.Get("encryption"), "none")
	core := strings.ToLower(q.Get("core"))

	// XHTTP, mKCP, VLESS Encryption (!= none), FinalMask, or explicit core=xray route to xraybridge
	useXray := core == "xray" ||
		transport == "xhttp" || transport == "splithttp" || transport == "kcp" || transport == "mkcp" ||
		(encryption != "" && encryption != "none") ||
		q.Get("fm") != "" || q.Get("finalmask") != "" || q.Get("mldsa65Verify") != ""

	params := map[string]any{
		"uuid":             uuid,
		"flow":             flow,
		"encryption":       encryption,
		"security":         security,
		"sni":              firstNonEmpty(q.Get("sni"), q.Get("peer")),
		"fp":               q.Get("fp"),
		"alpn":             q.Get("alpn"),
		"pbk":              q.Get("pbk"),
		"sid":              q.Get("sid"),
		"spx":              q.Get("spx"),
		"transport":        transport,
		"path":             q.Get("path"),
		"host":             q.Get("host"),
		"serviceName":      firstNonEmpty(q.Get("serviceName"), q.Get("service_name")),
		"mode":             q.Get("mode"),
		"extra":            q.Get("extra"),
		"packetEncoding":   q.Get("packetEncoding"),
		"allowInsecure":    isTruthy(q.Get("allowInsecure")) || isTruthy(q.Get("insecure")),
		"ech":              q.Get("ech"),
	}

	p := store.Profile{
		Name:     name,
		Type:     "vless",
		Core:     "sing-box",
		Address:  host,
		Port:     port,
		Params:   params,
		ShareURI: link,
	}
	if useXray {
		p.Core = "xray"
		if wrapped, err := xraybridge.ParseShareLink(link); err == nil {
			var raw map[string]any
			if json.Unmarshal([]byte(wrapped), &raw) == nil {
				p.RawOutbound = raw
			}
		}
	}
	return p, nil
}

func parseVMess(link string) (store.Profile, error) {
	body := strings.TrimPrefix(link, "vmess://")
	// Standard V2RayN base64 JSON format
	if decoded, ok := tryDecodeBase64(body); ok && strings.HasPrefix(strings.TrimSpace(decoded), "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(decoded), &m); err != nil {
			return store.Profile{}, err
		}
		host := strVal(m["add"])
		port := intVal(m["port"], 443)
		name := firstNonEmpty(strVal(m["ps"]), fmt.Sprintf("%s:%d", host, port))
		sec := firstNonEmpty(strVal(m["scy"]), strVal(m["security"]), "auto")
		if sec == "chacha20-ietf-poly1305" {
			sec = "chacha20-poly1305"
		}
		transport := strings.ToLower(firstNonEmpty(strVal(m["net"]), "tcp"))
		tlsVal := strings.ToLower(strVal(m["tls"]))
		security := "none"
		if tlsVal == "tls" || tlsVal == "1" || tlsVal == "true" {
			security = "tls"
		}
		core := "sing-box"
		if transport == "kcp" || transport == "mkcp" || transport == "xhttp" {
			core = "xray"
		}
		return store.Profile{
			Name:    name,
			Type:    "vmess",
			Core:    core,
			Address: host,
			Port:    port,
			Params: map[string]any{
				"uuid":          strVal(m["id"]),
				"alterId":       intVal(m["aid"], 0),
				"cipher":        sec,
				"security":      security,
				"sni":           firstNonEmpty(strVal(m["sni"]), strVal(m["host"])),
				"fp":            strVal(m["fp"]),
				"alpn":          strVal(m["alpn"]),
				"transport":     transport,
				"headerType":    strVal(m["type"]),
				"host":          strVal(m["host"]),
				"path":          strVal(m["path"]),
				"serviceName":   strVal(m["path"]),
				"allowInsecure": isTruthy(strVal(m["insecure"])) || isTruthy(strVal(m["skip-cert-verify"])),
			},
			ShareURI: link,
		}, nil
	}
	// Fallback URL-style vmess://
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "vmess",
		Core:    firstNonEmpty(q.Get("core"), "sing-box"),
		Address: host,
		Port:    port,
		Params: map[string]any{
			"uuid":          uuid,
			"alterId":       intVal(q.Get("aid"), 0),
			"cipher":        firstNonEmpty(q.Get("encryption"), "auto"),
			"security":      firstNonEmpty(q.Get("security"), "tls"),
			"sni":           q.Get("sni"),
			"fp":            q.Get("fp"),
			"transport":     firstNonEmpty(q.Get("type"), "tcp"),
			"path":          q.Get("path"),
			"host":          q.Get("host"),
			"allowInsecure": isTruthy(q.Get("allowInsecure")),
		},
		ShareURI: link,
	}, nil
}

func parseTrojan(link, protoType string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	transport := strings.ToLower(firstNonEmpty(q.Get("type"), "tcp"))
	core := strings.ToLower(q.Get("core"))
	if core == "" {
		if transport == "xhttp" || transport == "kcp" || transport == "mkcp" {
			core = "xray"
		} else {
			core = "sing-box"
		}
	}
	p := store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    protoType,
		Core:    core,
		Address: host,
		Port:    port,
		Params: map[string]any{
			"password":      password,
			"security":      firstNonEmpty(q.Get("security"), "tls"),
			"sni":           firstNonEmpty(q.Get("sni"), q.Get("peer")),
			"fp":            q.Get("fp"),
			"alpn":          q.Get("alpn"),
			"pbk":           q.Get("pbk"),
			"sid":           q.Get("sid"),
			"transport":     transport,
			"host":          q.Get("host"),
			"path":          q.Get("path"),
			"serviceName":   firstNonEmpty(q.Get("serviceName"), q.Get("service_name")),
			"allowInsecure": isTruthy(q.Get("allowInsecure")) || isTruthy(q.Get("insecure")),
			"ech":           q.Get("ech"),
		},
		ShareURI: link,
	}
	if core == "xray" {
		if wrapped, err := xraybridge.ParseShareLink(link); err == nil {
			var raw map[string]any
			if json.Unmarshal([]byte(wrapped), &raw) == nil {
				p.RawOutbound = raw
			}
		}
	}
	return p, nil
}

func parseShadowsocks(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	var method, password, host string
	var port int

	if u.User != nil && u.Host != "" {
		host, port = splitHostPortDefault(u.Host, 8388)
		if pass, hasPass := u.User.Password(); hasPass {
			method = u.User.Username()
			password = pass
		} else if decoded, ok := tryDecodeBase64(u.User.Username()); ok && strings.Contains(decoded, ":") {
			method, password, _ = strings.Cut(decoded, ":")
		} else {
			method = u.User.Username()
		}
	} else {
		// Legacy ss://BASE64(method:password@host:port)#name
		raw := strings.TrimPrefix(link, "ss://")
		raw, frag, _ := strings.Cut(raw, "#")
		u.Fragment = frag
		raw, qs, _ := strings.Cut(raw, "?")
		if qs != "" {
			q, _ = url.ParseQuery(qs)
		}
		decoded, ok := tryDecodeBase64(raw)
		if !ok {
			return store.Profile{}, errors.New("invalid shadowsocks uri")
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return store.Profile{}, errors.New("invalid shadowsocks payload")
		}
		method, password, _ = strings.Cut(decoded[:at], ":")
		host, port = splitHostPortDefault(decoded[at+1:], 8388)
	}

	pluginRaw := q.Get("plugin")
	plugin, pluginOpts := "", ""
	if pluginRaw != "" {
		plugin, pluginOpts, _ = strings.Cut(pluginRaw, ";")
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "shadowsocks",
		Core:    firstNonEmpty(q.Get("core"), "sing-box"),
		Address: host,
		Port:    port,
		Params: map[string]any{
			"method":     method,
			"password":   password,
			"plugin":     plugin,
			"pluginOpts": pluginOpts,
			"uot":        isTruthy(q.Get("uot")),
		},
		ShareURI: link,
	}, nil
}

func parseSSR(link string) (store.Profile, error) {
	body := strings.TrimPrefix(link, "ssr://")
	decoded, ok := tryDecodeBase64(body)
	if !ok {
		return store.Profile{}, errors.New("invalid ssr base64")
	}
	mainPart, queryPart, _ := strings.Cut(decoded, "/?")
	if mainPart == decoded {
		mainPart, queryPart, _ = strings.Cut(decoded, "?")
	}
	// Support IPv6 host by splitting from right (5 colons after host)
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return store.Profile{}, errors.New("invalid ssr fields")
	}
	n := len(parts)
	host := strings.Trim(strings.Join(parts[:n-5], ":"), "[]")
	port := intVal(parts[n-5], 8388)
	protocol := parts[n-4]
	cipher := parts[n-3]
	obfs := parts[n-2]
	passDecoded, _ := tryDecodeBase64(parts[n-1])

	q, _ := url.ParseQuery(queryPart)
	remarks, _ := tryDecodeBase64(q.Get("remarks"))
	protoParam, _ := tryDecodeBase64(q.Get("protoparam"))
	obfsParam, _ := tryDecodeBase64(q.Get("obfsparam"))

	name := firstNonEmpty(remarks, fmt.Sprintf("%s:%d", host, port))
	return store.Profile{
		Name:    name,
		Type:    "ssr",
		Core:    "mihomo",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"password":      passDecoded,
			"cipher":        cipher,
			"protocol":      protocol,
			"protocolParam": protoParam,
			"obfs":          obfs,
			"obfsParam":     obfsParam,
		},
		ShareURI: link,
	}, nil
}

func parseHysteria2(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	password := ""
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			password = u.User.Username() + ":" + p
		} else {
			password = u.User.Username()
		}
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "hysteria2",
		Core:    firstNonEmpty(q.Get("core"), "sing-box"),
		Address: host,
		Port:    port,
		Params: map[string]any{
			"password":      password,
			"sni":           firstNonEmpty(q.Get("sni"), q.Get("peer")),
			"obfs":          q.Get("obfs"),
			"obfsPassword":  q.Get("obfs-password"),
			"pinSHA256":     firstNonEmpty(q.Get("pinSHA256"), q.Get("pinsha256")),
			"mport":         firstNonEmpty(q.Get("mport"), q.Get("ports")),
			"upMbps":        intVal(q.Get("upmbps"), 0),
			"downMbps":      intVal(q.Get("downmbps"), 0),
			"alpn":          q.Get("alpn"),
			"ech":           q.Get("ech"),
			"allowInsecure": isTruthy(q.Get("insecure")) || isTruthy(q.Get("allowInsecure")),
		},
		ShareURI: link,
	}, nil
}

func parseHysteria1(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "hysteria",
		Core:    "sing-box",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"auth":          firstNonEmpty(q.Get("auth"), u.User.String()),
			"protocol":      firstNonEmpty(q.Get("protocol"), "udp"),
			"obfs":          q.Get("obfsParam"),
			"sni":           firstNonEmpty(q.Get("peer"), q.Get("sni")),
			"alpn":          q.Get("alpn"),
			"upMbps":        intVal(q.Get("upmbps"), 50),
			"downMbps":      intVal(q.Get("downmbps"), 100),
			"allowInsecure": isTruthy(q.Get("insecure")),
		},
		ShareURI: link,
	}, nil
}

func parseTUIC(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	uuid, password := "", ""
	if u.User != nil {
		uuid = u.User.Username()
		password, _ = u.User.Password()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "tuic",
		Core:    "sing-box",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"uuid":              uuid,
			"password":          password,
			"congestionControl": firstNonEmpty(q.Get("congestion_control"), "bbr"),
			"udpRelayMode":      firstNonEmpty(q.Get("udp_relay_mode"), "native"),
			"zeroRttHandshake":  isTruthy(q.Get("reduce_rtt")) || isTruthy(q.Get("zero_rtt_handshake")),
			"heartbeat":         firstNonEmpty(q.Get("heartbeat"), "10s"),
			"sni":               q.Get("sni"),
			"alpn":              firstNonEmpty(q.Get("alpn"), "h3"),
			"allowInsecure":     isTruthy(q.Get("allow_insecure")) || isTruthy(q.Get("insecure")),
			"disableSni":        isTruthy(q.Get("disable_sni")),
		},
		ShareURI: link,
	}, nil
}

func parseAnyTLS(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "anytls",
		Core:    "sing-box",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"password":                 password,
			"sni":                      firstNonEmpty(q.Get("sni"), q.Get("peer")),
			"fp":                       q.Get("fp"),
			"alpn":                     q.Get("alpn"),
			"allowInsecure":            isTruthy(q.Get("insecure")) || isTruthy(q.Get("allowInsecure")),
			"idleSessionCheckInterval": firstNonEmpty(q.Get("idle_session_check_interval"), "30s"),
			"idleSessionTimeout":       firstNonEmpty(q.Get("idle_session_timeout"), "30s"),
			"minIdleSession":           intVal(q.Get("min_idle_session"), 0),
		},
		ShareURI: link,
	}, nil
}

func parseWireGuardURI(link string, amnezia bool) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 51820)
	privKey := ""
	if u.User != nil {
		privKey = u.User.Username()
	}
	if q.Get("jc") != "" || q.Get("s1") != "" || q.Get("h1") != "" {
		amnezia = true
	}
	pType := "wireguard"
	core := "sing-box"
	if amnezia {
		pType = "amneziawg"
		core = "mihomo"
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    pType,
		Core:    core,
		Address: host,
		Port:    port,
		Params: map[string]any{
			"privateKey":   firstNonEmpty(privKey, q.Get("privatekey")),
			"publicKey":    firstNonEmpty(q.Get("publickey"), q.Get("peerPublicKey")),
			"presharedKey": q.Get("presharedkey"),
			"address":      firstNonEmpty(q.Get("address"), "172.16.0.2/32"),
			"mtu":          intVal(q.Get("mtu"), 1420),
			"reserved":     q.Get("reserved"),
			"jc":           intVal(q.Get("jc"), 0),
			"jmin":         intVal(q.Get("jmin"), 0),
			"jmax":         intVal(q.Get("jmax"), 0),
			"s1":           intVal(q.Get("s1"), 0),
			"s2":           intVal(q.Get("s2"), 0),
			"h1":           intVal(q.Get("h1"), 0),
			"h2":           intVal(q.Get("h2"), 0),
			"h3":           intVal(q.Get("h3"), 0),
			"h4":           intVal(q.Get("h4"), 0),
		},
		ShareURI: link,
	}, nil
}

func parseMASQUE(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "masque",
		Core:    "mihomo",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"privateKey": firstNonEmpty(q.Get("private_key"), q.Get("private-key"), q.Get("key")),
			"publicKey":  firstNonEmpty(q.Get("public_key"), q.Get("public-key"), q.Get("peer_public_key")),
			"ip":         firstNonEmpty(q.Get("ip"), "172.16.0.2/32"),
			"ipv6":       q.Get("ipv6"),
			"mtu":        intVal(q.Get("mtu"), 1280),
			"mode":       firstNonEmpty(q.Get("mode"), "h3"),
			"sni":        firstNonEmpty(q.Get("sni"), host),
			"uri":        q.Get("uri"),
		},
		ShareURI: link,
	}, nil
}

func parseMieru(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "mieru",
		Core:    "mihomo",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"username":     user,
			"password":     pass,
			"transport":    strings.ToUpper(firstNonEmpty(q.Get("protocol"), q.Get("transport"), "TCP")),
			"multiplexing": firstNonEmpty(q.Get("multiplexing"), "MULTIPLEXING_LOW"),
			"portRange":    q.Get("port-range"),
		},
		ShareURI: link,
	}, nil
}

func parseSnell(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	psk := ""
	if u.User != nil {
		psk = u.User.Username()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "snell",
		Core:    "mihomo",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"psk":      firstNonEmpty(psk, q.Get("psk")),
			"version":  intVal(q.Get("version"), 4),
			"obfs":     q.Get("obfs"),
			"obfsHost": q.Get("obfs-host"),
		},
		ShareURI: link,
	}, nil
}

func parseGenericMihomoURI(link, proto string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	q := u.Query()
	host, port := splitHostPortDefault(u.Host, 443)
	params := map[string]any{}
	if u.User != nil {
		params["username"] = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			params["password"] = pass
		} else {
			params["password"] = u.User.Username()
		}
	}
	for k, vals := range q {
		if len(vals) > 0 {
			params[k] = vals[0]
		}
	}
	return store.Profile{
		Name:     decodeFragment(u.Fragment, host, port),
		Type:     proto,
		Core:     "mihomo",
		Address:  host,
		Port:     port,
		Params:   params,
		ShareURI: link,
	}, nil
}

func parseSocks(link, scheme string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	host, port := splitHostPortDefault(u.Host, 1080)
	user, pass := "", ""
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			user, pass = u.User.Username(), p
		} else if dec, ok := tryDecodeBase64(u.User.Username()); ok && strings.Contains(dec, ":") {
			user, pass, _ = strings.Cut(dec, ":")
		} else {
			user = u.User.Username()
		}
	}
	ver := "5"
	if scheme == "socks4" {
		ver = "4"
	} else if scheme == "socks4a" {
		ver = "4a"
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "socks",
		Core:    "sing-box",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"version":  ver,
			"username": user,
			"password": pass,
		},
		ShareURI: link,
	}, nil
}

func parseHTTP(link string, useTLS bool) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	defPort := 80
	if useTLS {
		defPort = 443
	}
	host, port := splitHostPortDefault(u.Host, defPort)
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "http",
		Core:    "sing-box",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"username": user,
			"password": pass,
			"tls":      useTLS,
			"sni":      u.Query().Get("sni"),
		},
		ShareURI: link,
	}, nil
}

func parseSSH(link string) (store.Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return store.Profile{}, err
	}
	host, port := splitHostPortDefault(u.Host, 22)
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "ssh",
		Core:    "sing-box",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"username":   user,
			"password":   pass,
			"privateKey": u.Query().Get("privateKey"),
		},
		ShareURI: link,
	}, nil
}

func parseNaive(link, scheme string) (store.Profile, error) {
	norm := strings.Replace(link, scheme+"://", "https://", 1)
	u, err := url.Parse(norm)
	if err != nil {
		return store.Profile{}, err
	}
	host, port := splitHostPortDefault(u.Host, 443)
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return store.Profile{
		Name:    decodeFragment(u.Fragment, host, port),
		Type:    "naive",
		Core:    "sing-box",
		Address: host,
		Port:    port,
		Params: map[string]any{
			"username": user,
			"password": pass,
			"proto":    strings.TrimPrefix(scheme, "naive+"),
			"sni":      u.Query().Get("sni"),
		},
		ShareURI: link,
	}, nil
}

func parseWireGuardConf(text string) (store.Profile, error) {
	section := ""
	params := map[string]any{"mtu": 1420}
	host, port := "", 51820
	amnezia := false
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				params["privateKey"] = val
			case "address":
				params["address"] = val
			case "mtu":
				params["mtu"] = intVal(val, 1420)
			case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4":
				amnezia = true
				params[key] = intVal(val, 0)
			case "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime":
				amnezia = true
				params[key] = val
			}
		case "peer":
			switch key {
			case "publickey":
				params["publicKey"] = val
			case "presharedkey":
				params["presharedKey"] = val
			case "endpoint":
				host, port = splitHostPortDefault(val, 51820)
			case "allowedips":
				params["allowedIps"] = val
			case "persistentkeepalive":
				params["keepalive"] = intVal(val, 25)
			}
		}
	}
	if host == "" {
		return store.Profile{}, errors.New("missing WireGuard Endpoint")
	}
	pType, core := "wireguard", "sing-box"
	if amnezia {
		pType, core = "amneziawg", "mihomo"
	}
	return store.Profile{
		Name:    fmt.Sprintf("%s (%s:%d)", strings.ToUpper(pType), host, port),
		Type:    pType,
		Core:    core,
		Address: host,
		Port:    port,
		Params:  params,
	}, nil
}

func parseClashYAML(text string) ([]store.Profile, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil || len(doc.Proxies) == 0 {
		var list []map[string]any
		if err2 := yaml.Unmarshal([]byte(text), &list); err2 != nil || len(list) == 0 {
			return nil, errors.New("no proxies in Clash YAML")
		}
		doc.Proxies = list
	}
	var out []store.Profile
	for _, item := range doc.Proxies {
		pType := strings.ToLower(strVal(item["type"]))
		if pType == "" {
			continue
		}
		name := firstNonEmpty(strVal(item["name"]), pType)
		host := strVal(item["server"])
		port := intVal(item["port"], 443)
		// Normalize Clash types to Mihomo bridge (which natively supports 25+ Clash types including AmneziaWG/SSR/MASQUE/Mieru/Snell/TrustTunnel/Sudoku/ShadowQUIC/Tailscale/etc.)
		displayType := pType
		if pType == "ss" {
			displayType = "shadowsocks"
		}
		if pType == "wireguard" {
			if _, hasAwg := item["amnezia-wg-option"]; hasAwg {
				displayType = "amneziawg"
			}
		}
		rawJSON, _ := json.Marshal(item)
		var wrapped map[string]any
		if w, err := mihomobridge.WrapProxy(string(rawJSON)); err == nil {
			_ = json.Unmarshal([]byte(w), &wrapped)
		} else {
			wrapped = map[string]any{"type": "mihomo", "proxy": item}
		}
		out = append(out, store.Profile{
			Name:        name,
			Type:        displayType,
			Core:        "mihomo",
			Address:     host,
			Port:        port,
			Params:      item,
			RawOutbound: wrapped,
		})
	}
	return out, nil
}

func parseJSONInput(text string) ([]store.Profile, error) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		var arr []map[string]any
		if err2 := json.Unmarshal([]byte(text), &arr); err2 == nil && len(arr) > 0 {
			var res []store.Profile
			for _, o := range arr {
				if p, ok := outboundMapToProfile(o); ok {
					res = append(res, p)
				}
			}
			return res, nil
		}
		return nil, err
	}

	// Cloudflare WARP / usque config.json
	if _, hasPriv := obj["private_key"]; hasPriv {
		if _, hasEP := obj["endpoint_v4"]; hasEP {
			ep := strVal(obj["endpoint_v4"])
			host, port := splitHostPortDefault(ep, 2408)
			if port == 2408 && strVal(obj["endpoint_pub_key"]) != "" {
				// usque MASQUE default
			}
			return []store.Profile{{
				Name:    "MASQUE (usque)",
				Type:    "masque",
				Core:    "mihomo",
				Address: host,
				Port:    port,
				Params: map[string]any{
					"privateKey": strVal(obj["private_key"]),
					"publicKey":  strVal(obj["endpoint_pub_key"]),
					"ip":         firstNonEmpty(strVal(obj["ipv4"]), "172.16.0.2/32"),
					"ipv6":       strVal(obj["ipv6"]),
					"sni":        firstNonEmpty(strVal(obj["sni_address"]), "consumer-masque.cloudflareclient.com"),
					"mode":       "h3",
				},
			}}, nil
		}
	}

	// Full sing-box config (contains inbounds/outbounds/route)
	if _, hasIn := obj["inbounds"]; hasIn {
		if _, hasOut := obj["outbounds"]; hasOut {
			return []store.Profile{{
				Name:             "自定义 sing-box 完整配置",
				Type:             "full-config",
				Core:             "sing-box",
				Address:          "custom",
				Port:             0,
				CustomFullConfig: text,
			}}, nil
		}
	}

	// Xray outbound JSON (has "protocol" and "settings")
	if proto := strings.ToLower(strVal(obj["protocol"])); proto != "" {
		if wrapped, err := xraybridge.WrapOutbound(text); err == nil {
			var m map[string]any
			_ = json.Unmarshal([]byte(wrapped), &m)
			return []store.Profile{{
				Name:        firstNonEmpty(strVal(obj["tag"]), "Xray "+strings.ToUpper(proto)),
				Type:        proto,
				Core:        "xray",
				Address:     extractXrayHost(obj),
				Port:        extractXrayPort(obj),
				RawOutbound: m,
			}}, nil
		}
	}

	// Single sing-box outbound JSON
	if p, ok := outboundMapToProfile(obj); ok {
		return []store.Profile{p}, nil
	}
	return nil, errors.New("unrecognized json")
}

func outboundMapToProfile(obj map[string]any) (store.Profile, bool) {
	t := strings.ToLower(strVal(obj["type"]))
	if t == "" || t == "direct" || t == "block" || t == "dns" || t == "selector" || t == "urltest" {
		return store.Profile{}, false
	}
	host := strVal(obj["server"])
	port := intVal(obj["server_port"], 443)
	name := firstNonEmpty(strVal(obj["tag"]), fmt.Sprintf("%s (%s:%d)", strings.ToUpper(t), host, port))
	core := "sing-box"
	if t == "xray" {
		core = "xray"
	} else if t == "mihomo" || t == "masque" {
		core = "mihomo"
	}
	return store.Profile{
		Name:        name,
		Type:        t,
		Core:        core,
		Address:     host,
		Port:        port,
		RawOutbound: obj,
	}, true
}

// ExportShareURI generates a shareable URI for a Profile.
func ExportShareURI(p store.Profile) string {
	if p.ShareURI != "" && p.Type != "custom" && p.Type != "full-config" {
		return p.ShareURI
	}
	frag := url.PathEscape(p.Name)
	hostPort := net.JoinHostPort(p.Address, strconv.Itoa(p.Port))
	getS := func(k string) string { return strVal(p.Params[k]) }

	switch p.Type {
	case "vless":
		q := url.Values{}
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
		if p.Core == "xray" {
			q.Set("core", "xray")
		}
		return fmt.Sprintf("vless://%s@%s?%s#%s", url.User(getS("uuid")).String(), hostPort, q.Encode(), frag)

	case "vmess":
		m := map[string]any{
			"v":    "2",
			"ps":   p.Name,
			"add":  p.Address,
			"port": p.Port,
			"id":   getS("uuid"),
			"aid":  intVal(p.Params["alterId"], 0),
			"scy":  firstNonEmpty(getS("cipher"), "auto"),
			"net":  firstNonEmpty(getS("transport"), "tcp"),
			"host": getS("host"),
			"path": getS("path"),
			"tls":  getS("security"),
			"sni":  getS("sni"),
		}
		raw, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)

	case "trojan", "trojan-go":
		q := url.Values{}
		if v := getS("sni"); v != "" {
			q.Set("sni", v)
		}
		if v := getS("transport"); v != "" && v != "tcp" {
			q.Set("type", v)
		}
		if v := getS("host"); v != "" {
			q.Set("host", v)
		}
		if v := getS("path"); v != "" {
			q.Set("path", v)
		}
		if isTruthy(getS("allowInsecure")) {
			q.Set("allowInsecure", "1")
		}
		return fmt.Sprintf("%s://%s@%s?%s#%s", p.Type, url.User(getS("password")).String(), hostPort, q.Encode(), frag)

	case "shadowsocks":
		cred := base64.RawURLEncoding.EncodeToString([]byte(getS("method") + ":" + getS("password")))
		return fmt.Sprintf("ss://%s@%s#%s", cred, hostPort, frag)

	case "hysteria2":
		q := url.Values{}
		if v := getS("sni"); v != "" {
			q.Set("sni", v)
		}
		if v := getS("obfs"); v != "" {
			q.Set("obfs", v)
			q.Set("obfs-password", getS("obfsPassword"))
		}
		if v := getS("pinSHA256"); v != "" {
			q.Set("pinSHA256", v)
		}
		if v := getS("mport"); v != "" {
			q.Set("mport", v)
		}
		if isTruthy(getS("allowInsecure")) {
			q.Set("insecure", "1")
		}
		return fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.QueryEscape(getS("password")), hostPort, q.Encode(), frag)

	case "tuic":
		q := url.Values{}
		q.Set("congestion_control", firstNonEmpty(getS("congestionControl"), "bbr"))
		q.Set("udp_relay_mode", firstNonEmpty(getS("udpRelayMode"), "native"))
		if v := getS("sni"); v != "" {
			q.Set("sni", v)
		}
		if v := getS("alpn"); v != "" {
			q.Set("alpn", v)
		}
		return fmt.Sprintf("tuic://%s:%s@%s?%s#%s", url.QueryEscape(getS("uuid")), url.QueryEscape(getS("password")), hostPort, q.Encode(), frag)

	case "anytls":
		q := url.Values{}
		if v := getS("sni"); v != "" {
			q.Set("sni", v)
		}
		if isTruthy(getS("allowInsecure")) {
			q.Set("insecure", "1")
		}
		return fmt.Sprintf("anytls://%s@%s?%s#%s", url.QueryEscape(getS("password")), hostPort, q.Encode(), frag)

	case "socks":
		auth := ""
		if getS("username") != "" {
			auth = url.UserPassword(getS("username"), getS("password")).String() + "@"
		}
		return fmt.Sprintf("socks5://%s%s#%s", auth, hostPort, frag)

	case "http":
		scheme := "http"
		if isTruthy(getS("tls")) {
			scheme = "https"
		}
		auth := ""
		if getS("username") != "" {
			auth = url.UserPassword(getS("username"), getS("password")).String() + "@"
		}
		return fmt.Sprintf("%s://%s%s#%s", scheme, auth, hostPort, frag)

	default:
		if p.CustomFullConfig != "" {
			return p.CustomFullConfig
		}
		raw, _ := json.MarshalIndent(p, "", "  ")
		return string(raw)
	}
}

// ParseSubscriptionUserinfo parses Subscription-Userinfo header: upload=...; download=...; total=...; expire=...
func ParseSubscriptionUserinfo(header string) (upload, download, total, expire int64) {
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		val, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			upload = val
		case "download":
			download = val
		case "total":
			total = val
		case "expire":
			expire = val
		}
	}
	return
}

// DeduplicateProfiles removes duplicate endpoints while preserving order.
func DeduplicateProfiles(in []store.Profile) []store.Profile {
	seen := map[string]bool{}
	out := make([]store.Profile, 0, len(in))
	for _, p := range in {
		key := fmt.Sprintf("%s|%s|%d|%s|%s", p.Type, p.Address, p.Port, strVal(p.Params["uuid"]), strVal(p.Params["password"]))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func extractXrayHost(obj map[string]any) string {
	settings, _ := obj["settings"].(map[string]any)
	for _, k := range []string{"vnext", "servers"} {
		if list, ok := settings[k].([]any); ok && len(list) > 0 {
			if first, ok := list[0].(map[string]any); ok {
				if addr := strVal(first["address"]); addr != "" {
					return addr
				}
			}
		}
	}
	return ""
}

func extractXrayPort(obj map[string]any) int {
	settings, _ := obj["settings"].(map[string]any)
	for _, k := range []string{"vnext", "servers"} {
		if list, ok := settings[k].([]any); ok && len(list) > 0 {
			if first, ok := list[0].(map[string]any); ok {
				if port := intVal(first["port"], 0); port > 0 {
					return port
				}
			}
		}
	}
	return 443
}

func splitHostPortDefault(hostPort string, defPort int) (string, int) {
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		return h, intVal(p, defPort)
	}
	return strings.Trim(hostPort, "[]"), defPort
}

func decodeFragment(frag, host string, port int) string {
	if frag != "" {
		if dec, err := url.QueryUnescape(frag); err == nil && strings.TrimSpace(dec) != "" {
			return strings.TrimSpace(dec)
		}
		return frag
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func tryDecodeBase64(s string) (string, bool) {
	clean := strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "", " ", "").Replace(s))
	if clean == "" {
		return "", false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if b, err := enc.DecodeString(clean); err == nil && len(b) > 0 {
			return string(b), true
		}
	}
	return "", false
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
	case int64:
		return strconv.FormatInt(x, 10)
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

func isTruthy(s string) bool {
	return slices.Contains([]string{"1", "true", "yes", "on"}, strings.ToLower(strings.TrimSpace(s)))
}

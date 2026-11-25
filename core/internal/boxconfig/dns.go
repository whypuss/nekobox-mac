// SPDX-License-Identifier: GPL-3.0-or-later
package boxconfig

import (
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func upgradeDNS(dns object, ruleSets []any, emptyDirectTags map[string]bool) (string, []string, error) {
	delete(dns, "independent_cache")
	fakeIP := child(dns, "fakeip")
	delete(dns, "fakeip")

	var servers []any
	rcodes := make(map[string]string)
	strategies := make(map[string]string)
	fakeIPTags := make(map[string]bool)

	for _, item := range array(dns["servers"]) {
		server, ok := item.(object)
		if !ok {
			servers = append(servers, item)
			continue
		}
		serverType, _ := server["type"].(string)
		tag, _ := server["tag"].(string)

		if serverType != "" && serverType != "legacy" {
			// Modern DNS server format: still clean accidental legacy fields and
			// empty-direct detours that sing-box 1.14 rejects.
			for _, key := range []string{"address_resolver", "address_strategy", "address_fallback_delay", "strategy"} {
				delete(server, key)
			}
			stripEmptyDirectDetour(server, emptyDirectTags)
			if serverType == "fakeip" && tag != "" {
				fakeIPTags[tag] = true
			}
			servers = append(servers, server)
			continue
		}

		// Legacy DNS server format (type omitted or "legacy").
		delete(server, "type")
		address, _ := server["address"].(string)
		strategy, _ := server["strategy"].(string)
		if strategy != "" && tag != "" {
			strategies[tag] = strategy
		}
		if rcode, found := strings.CutPrefix(address, "rcode://"); found {
			code, known := map[string]string{
				"success": "NOERROR", "format_error": "FORMERR", "server_failure": "SERVFAIL",
				"name_error": "NXDOMAIN", "not_implemented": "NOTIMP", "refused": "REFUSED",
			}[rcode]
			if !known {
				return "", nil, fmt.Errorf("unknown legacy DNS response %q", rcode)
			}
			rcodes[tag] = code
			continue
		}
		if err := upgradeDNSServer(server, address, fakeIP, emptyDirectTags); err != nil {
			return "", nil, fmt.Errorf("DNS server %q: %w", tag, err)
		}
		if server["type"] == "fakeip" && tag != "" {
			fakeIPTags[tag] = true
		}
		servers = append(servers, server)
	}
	if dns["servers"] != nil {
		dns["servers"] = servers
	}

	final, _ := dns["final"].(string)
	if _, oldRcode := rcodes[final]; final != "" && oldRcode {
		return "", nil, fmt.Errorf("legacy DNS response %q must be used in a DNS rule", final)
	}
	if final == "" && len(servers) > 0 {
		first, _ := servers[0].(object)
		final, _ = first["tag"].(string)
	}

	upgradedRules, bootstrapServer, geoRefs := upgradeDNSRules(
		dns, array(dns["rules"]), ruleSets, rcodes, strategies, fakeIPTags, final)
	if dns["rules"] != nil {
		dns["rules"] = upgradedRules
	}
	return bootstrapServer, geoRefs, nil
}

func stripEmptyDirectDetour(server object, emptyDirectTags map[string]bool) {
	detour, _ := server["detour"].(string)
	if detour == "" {
		return
	}
	if detour == "direct" || detour == "bypass" || emptyDirectTags[detour] {
		delete(server, "detour")
	}
}

func upgradeDNSServer(server object, address string, fakeIP object, emptyDirectTags map[string]bool) error {
	resolver, _ := server["address_resolver"].(string)
	resolveStrategy, _ := server["address_strategy"].(string)
	for _, key := range []string{"address", "address_resolver", "address_strategy", "address_fallback_delay", "strategy", "client_subnet"} {
		delete(server, key)
	}
	if address == "local" || address == "fakeip" {
		server["type"] = address
		delete(server, "detour")
		if address == "fakeip" {
			hasRange := false
			for _, key := range []string{"inet4_range", "inet6_range"} {
				if value := fakeIP[key]; value != nil && value != "" {
					server[key] = value
					hasRange = true
				}
			}
			if !hasRange && server["inet4_range"] == nil && server["inet6_range"] == nil {
				server["inet4_range"] = "198.18.0.0/15"
			}
		}
		return nil
	}
	if iface, isDHCP := strings.CutPrefix(address, "dhcp://"); isDHCP {
		server["type"] = "dhcp"
		if iface != "" && iface != "auto" {
			server["interface"] = iface
		}
		stripEmptyDirectDetour(server, emptyDirectTags)
		return nil
	}
	if !strings.Contains(address, "://") {
		if ip, err := netip.ParseAddr(address); err == nil && ip.Is6() {
			address = "[" + address + "]"
		}
		address = "udp://" + address
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("invalid legacy DNS address")
	}
	dnsType := parsed.Scheme
	if dnsType == "https+h3" {
		dnsType = "h3"
	}
	switch dnsType {
	case "udp", "tcp", "tls", "quic", "https", "h3":
		server["type"] = dnsType
	default:
		return fmt.Errorf("unsupported legacy DNS scheme %q", dnsType)
	}
	server["server"] = parsed.Hostname()
	if parsed.Port() != "" {
		port, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("invalid DNS port")
		}
		server["server_port"] = port
	}
	if (dnsType == "https" || dnsType == "h3") && parsed.RequestURI() != "/" {
		server["path"] = parsed.RequestURI()
	}
	if _, err := netip.ParseAddr(parsed.Hostname()); err != nil && resolver != "" {
		domainResolver := object{"server": resolver}
		if resolveStrategy != "" {
			domainResolver["strategy"] = resolveStrategy
		}
		server["domain_resolver"] = domainResolver
	}
	stripEmptyDirectDetour(server, emptyDirectTags)
	return nil
}

func upgradeDNSRules(dns object, rules, ruleSets []any, rcodes, strategies map[string]string, fakeIPTags map[string]bool, final string) ([]any, string, []string) {
	var bootstrapServer string
	var geoRefs []string

	// Normalize actions before deciding whether this rule list can keep legacy strategies.
	var pass1 []any
	for _, item := range rules {
		rule, ok := item.(object)
		if !ok {
			pass1 = append(pass1, item)
			continue
		}
		if target, isBootstrap := isOutboundAnyBootstrapRule(rule); isBootstrap {
			if target != "" && !fakeIPTags[target] && rcodes[target] == "" && bootstrapServer == "" {
				bootstrapServer = target
			}
			continue
		}

		cleanDNSRuleTree(rule, &geoRefs)

		server, _ := rule["server"].(string)
		if rcode, exists := rcodes[server]; exists {
			rule["action"] = "predefined"
			rule["rcode"] = rcode
			for _, key := range []string{"server", "disable_cache", "strategy", "rewrite_ttl", "client_subnet"} {
				delete(rule, key)
			}
			pass1 = append(pass1, rule)
			continue
		}

		action, _ := rule["action"].(string)
		if action == "" || action == "route" || action == "evaluate" {
			if strategy := strategies[server]; strategy != "" && !fakeIPTags[server] && isEmptyValue(rule["strategy"]) {
				rule["strategy"] = strategy
			}
		}
		pass1 = append(pass1, rule)
	}

	modernSets, opaqueSets := dnsRuleSetModes(pass1, ruleSets)
	modern := dnsRulesUseModernMode(pass1) || modernSets
	keepScoped := !modern && !opaqueSets
	restoreDefaultDNSStrategy(dns, pass1, final, strategies[final], fakeIPTags, keepScoped)
	if keepScoped {
		return pass1, bootstrapServer, geoRefs
	}

	// Modern DNS rules cannot set lookup preferences per rule. Translate strict
	// address-family restrictions when the match can run before a DNS response.
	globalStrategy, _ := dns["strategy"].(string)
	var pass2 []any
	for index, item := range pass1 {
		rule, ok := item.(object)
		if !ok {
			pass2 = append(pass2, item)
			continue
		}
		strategy, _ := rule["strategy"].(string)
		delete(rule, "strategy")
		if strategy != "" && strategy != "as_is" && strategy != globalStrategy {
			if guard, preserved := scopedDNSStrategyGuard(rule, strategy, modern); preserved {
				if guard != nil {
					pass2 = append(pass2, guard)
				}
			} else {
				log.Printf("DNS compatibility: dns.rules[%d] strategy %q cannot be preserved for this rule; check the DNS strategy in your configuration", index, strategy)
			}
		}
		if modern {
			pass2 = append(pass2, migrateLegacyDNSAddressFilterRule(dns, rule, fakeIPTags)...)
		} else {
			pass2 = append(pass2, rule)
		}
	}
	return pass2, bootstrapServer, geoRefs
}

func restoreDefaultDNSStrategy(dns object, rules []any, final, strategy string, fakeIPTags map[string]bool, keepScoped bool) {
	if !isEmptyValue(dns["strategy"]) || strategy == "" || strategy == "as_is" {
		return
	}
	for _, item := range rules {
		rule, _ := item.(object)
		server, _ := rule["server"].(string)
		if server == "" || server == final || fakeIPTags[server] {
			continue
		}
		scoped, _ := rule["strategy"].(string)
		if scoped == strategy || (keepScoped && scoped != "" && scoped != "as_is") {
			continue
		}
		log.Printf("DNS compatibility: default server %q uses strategy %q; applying it globally would change other DNS rules", final, strategy)
		return
	}
	dns["strategy"] = strategy
}

func scopedDNSStrategyGuard(rule object, strategy string, modern bool) (object, bool) {
	action, _ := rule["action"].(string)
	if !modern || (action != "" && action != "route") {
		return nil, false
	}
	var blockedType string
	switch strategy {
	case "ipv4_only":
		blockedType = "AAAA"
	case "ipv6_only":
		blockedType = "A"
	default:
		return nil, false
	}
	if types := dnsQueryTypes(rule["query_type"]); len(types) > 0 && !boolValue(rule["invert"]) {
		if !containsQueryType(types, blockedType) {
			return nil, true
		}
	}
	guard := buildQueryTypeBlockRule(rule, blockedType)
	return guard, guard != nil
}

func isOutboundAnyBootstrapRule(rule object) (string, bool) {
	outbounds := stringsArray(rule["outbound"])
	if len(outbounds) != 1 || outbounds[0] != "any" {
		return "", false
	}
	if rule["invert"] == true {
		return "", false
	}
	for key := range rule {
		switch key {
		case "outbound", "server", "action", "strategy", "disable_cache",
			"disable_optimistic_cache", "rewrite_ttl", "client_subnet", "timeout":
			continue
		default:
			return "", false
		}
	}
	action, _ := rule["action"].(string)
	if action != "" && action != "route" {
		return "", false
	}
	server, _ := rule["server"].(string)
	return server, true
}

func cleanDNSRuleTree(rule object, geoRefs *[]string) {
	move(rule, "rule_set_ipcidr_match_source", rule, "rule_set_ip_cidr_match_source")
	upgradeLegacyGeoRuleFields(rule, geoRefs)
	if subRules := array(rule["rules"]); len(subRules) > 0 {
		for _, sub := range subRules {
			if subObj, ok := sub.(object); ok {
				delete(subObj, "strategy")
				cleanDNSRuleTree(subObj, geoRefs)
			}
		}
	}
}

func buildQueryTypeBlockRule(rule object, blockedType string) object {
	// Do not copy legacy response-filter fields into a pre-response guard rule.
	if ruleHasLegacyAddressFilter(rule) {
		return nil
	}
	matchPart := cloneDNSMatchFields(rule)
	if len(matchPart) == 0 {
		return nil
	}
	isLogical := rule["type"] == "logical"
	isInverted, _ := rule["invert"].(bool)
	if isLogical || isInverted {
		return object{
			"type": "logical",
			"mode": "and",
			"rules": []any{
				matchPart,
				object{"query_type": []any{blockedType}},
			},
			"action": "predefined",
			"rcode":  "NOERROR",
		}
	}
	matchPart["query_type"] = []any{blockedType}
	matchPart["action"] = "predefined"
	matchPart["rcode"] = "NOERROR"
	return matchPart
}

func dnsQueryTypes(value any) []any {
	switch value.(type) {
	case float64, int:
		return []any{value}
	default:
		return stringsArray(value)
	}
}

func containsQueryType(items []any, target string) bool {
	targetNum := 1
	if target == "AAAA" {
		targetNum = 28
	}
	for _, item := range items {
		switch v := item.(type) {
		case string:
			if strings.EqualFold(v, target) {
				return true
			}
		case float64:
			if int(v) == targetNum {
				return true
			}
		case int:
			if v == targetNum {
				return true
			}
		}
	}
	return false
}

var dnsActionKeys = map[string]bool{
	"action":                   true,
	"server":                   true,
	"strategy":                 true,
	"disable_cache":            true,
	"disable_optimistic_cache": true,
	"speculative":              true,
	"rewrite_ttl":              true,
	"client_subnet":            true,
	"remove_client_subnet":     true,
	"timeout":                  true,
	"method":                   true,
	"no_drop":                  true,
	"rcode":                    true,
	"answer":                   true,
	"ns":                       true,
	"extra":                    true,
	"tag":                      true,
	"race":                     true,
}

func cloneDNSMatchFields(rule object) object {
	cloned := make(object, len(rule))
	for key, val := range rule {
		if dnsActionKeys[key] {
			continue
		}
		cloned[key] = val
	}
	return cloned
}

func dnsRulesUseModernMode(rules []any) bool {
	for _, item := range rules {
		rule, ok := item.(object)
		if !ok {
			continue
		}
		if dnsRuleTreeUsesModernMode(rule) {
			return true
		}
	}
	return false
}

// File and remote rule sets may acquire query types outside this configuration.
func dnsRuleSetModes(rules, definitions []any) (modern, opaque bool) {
	sets := make(map[string]object)
	for _, item := range definitions {
		if definition, ok := item.(object); ok {
			if tag, ok := definition["tag"].(string); ok {
				sets[tag] = definition
			}
		}
	}
	var visit func([]any)
	visit = func(rules []any) {
		for _, item := range rules {
			rule, _ := item.(object)
			for _, ref := range stringsArray(rule["rule_set"]) {
				tag, _ := ref.(string)
				if definition := sets[tag]; definition != nil {
					if definition["type"] == "inline" || (definition["type"] == nil && definition["rules"] != nil) {
						modern = modern || dnsRulesUseModernMode(array(definition["rules"]))
					} else {
						opaque = true
					}
				}
			}
			visit(array(rule["rules"]))
		}
	}
	visit(rules)
	return
}

func dnsRuleTreeUsesModernMode(rule object) bool {
	action, _ := rule["action"].(string)
	if action == "evaluate" || action == "respond" {
		return true
	}
	if boolValue(rule["race"]) || boolValue(rule["disable_optimistic_cache"]) || boolValue(rule["speculative"]) {
		return true
	}
	if hasMatchResponse(rule) {
		return true
	}
	if rule["response_rcode"] != nil || len(stringsArray(rule["response_answer"])) > 0 ||
		len(stringsArray(rule["response_ns"])) > 0 || len(stringsArray(rule["response_extra"])) > 0 {
		return true
	}
	if len(dnsQueryTypes(rule["query_type"])) > 0 {
		return true
	}
	if v, ok := rule["ip_version"].(float64); ok && v > 0 {
		return true
	}
	if v, ok := rule["ip_version"].(int); ok && v > 0 {
		return true
	}
	for _, sub := range array(rule["rules"]) {
		if subObj, ok := sub.(object); ok && dnsRuleTreeUsesModernMode(subObj) {
			return true
		}
	}
	return false
}

func hasMatchResponse(rule object) bool {
	switch v := rule["match_response"].(type) {
	case bool:
		return v
	case string:
		return v != ""
	default:
		return false
	}
}

func ruleHasLegacyAddressFilter(rule object) bool {
	if hasMatchResponse(rule) {
		return false
	}
	if len(stringsArray(rule["ip_cidr"])) > 0 || boolValue(rule["ip_is_private"]) || boolValue(rule["ip_accept_any"]) {
		return true
	}
	if !boolValue(rule["rule_set_ip_cidr_match_source"]) {
		for _, item := range stringsArray(rule["rule_set"]) {
			if tag, _ := item.(string); strings.HasPrefix(tag, "geoip:") {
				return true
			}
		}
	}
	return false
}

func migrateLegacyDNSAddressFilterRule(dns object, rule object, fakeIPTags map[string]bool) []any {
	if hasMatchResponse(rule) || rule["type"] == "logical" {
		delete(rule, "rule_set_ip_cidr_accept_empty")
		return []any{rule}
	}
	delete(rule, "rule_set_ip_cidr_accept_empty")

	if !ruleHasLegacyAddressFilter(rule) {
		return []any{rule}
	}

	action, _ := rule["action"].(string)
	server, _ := rule["server"].(string)
	if server == "" {
		server, _ = dns["final"].(string)
	}
	if server == "" || fakeIPTags[server] {
		server = firstNonFakeIPServer(dns, fakeIPTags)
	}
	if server == "" {
		return []any{rule}
	}

	// Build step 1: evaluate query against the target transport using only
	// pre-response match conditions.
	evalRule := object{
		"action": "evaluate",
		"server": server,
	}
	for _, key := range []string{"disable_cache", "rewrite_ttl", "client_subnet", "timeout"} {
		if val, exists := rule[key]; exists {
			evalRule[key] = val
		}
	}
	for key, val := range rule {
		if dnsActionKeys[key] || key == "ip_cidr" || key == "ip_is_private" ||
			key == "ip_accept_any" || key == "invert" || key == "rule_set_ip_cidr_accept_empty" {
			continue
		}
		if key == "rule_set" && !boolValue(rule["rule_set_ip_cidr_match_source"]) {
			var nonGeoIP []any
			for _, rs := range stringsArray(val) {
				if tag, _ := rs.(string); !strings.HasPrefix(tag, "geoip:") {
					nonGeoIP = append(nonGeoIP, rs)
				}
			}
			if len(nonGeoIP) > 0 {
				evalRule["rule_set"] = nonGeoIP
			}
			continue
		}
		evalRule[key] = val
	}

	// Build step 2: match the evaluated response and return (or reject/predefined).
	respondRule := cloneDNSMatchFields(rule)
	respondRule["match_response"] = true
	switch action {
	case "reject", "predefined":
		respondRule["action"] = action
		for _, key := range []string{"method", "no_drop", "rcode", "answer", "ns", "extra"} {
			if val, exists := rule[key]; exists {
				respondRule[key] = val
			}
		}
	default:
		respondRule["action"] = "respond"
	}

	return []any{evalRule, respondRule}
}

func resolveDefaultDomainResolver(dns, route object, bootstrapDNS string) string {
	if existing := route["default_domain_resolver"]; existing != nil {
		switch v := existing.(type) {
		case string:
			if v != "" {
				return v
			}
		case object:
			if s, _ := v["server"].(string); s != "" {
				return s
			}
		}
	}
	if dns == nil {
		return ""
	}
	if serverExists(dns, "dns-direct") {
		return "dns-direct"
	}
	if bootstrapDNS != "" && serverExists(dns, bootstrapDNS) {
		return bootstrapDNS
	}
	// Prefer a local or non-detour non-fakeip server so bootstrap resolution does
	// not loop back through an unresolved proxy outbound.
	for _, item := range array(dns["servers"]) {
		server, ok := item.(object)
		if !ok {
			continue
		}
		tag, _ := server["tag"].(string)
		sType, _ := server["type"].(string)
		detour, _ := server["detour"].(string)
		if tag != "" && sType != "fakeip" && sType != "mihomo-dns" && detour == "" {
			return tag
		}
	}
	if final, _ := dns["final"].(string); final != "" && serverExists(dns, final) && !isFakeIPServer(dns, final) {
		return final
	}
	return ""
}

func firstNonFakeIPServer(dns object, fakeIPTags map[string]bool) string {
	if final, _ := dns["final"].(string); final != "" && !fakeIPTags[final] && serverExists(dns, final) {
		return final
	}
	for _, item := range array(dns["servers"]) {
		server, ok := item.(object)
		if !ok {
			continue
		}
		tag, _ := server["tag"].(string)
		sType, _ := server["type"].(string)
		if tag != "" && !fakeIPTags[tag] && sType != "fakeip" && sType != "mihomo-dns" {
			return tag
		}
	}
	return ""
}

func isFakeIPServer(dns object, tag string) bool {
	for _, item := range array(dns["servers"]) {
		if server, ok := item.(object); ok && server["tag"] == tag {
			return server["type"] == "fakeip"
		}
	}
	return false
}

func serverExists(dns object, tag string) bool {
	for _, item := range array(dns["servers"]) {
		if server, ok := item.(object); ok && server["tag"] == tag {
			return true
		}
	}
	return false
}

func isEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return s == ""
	}
	return false
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

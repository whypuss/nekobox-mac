// SPDX-License-Identifier: GPL-3.0-or-later
package boxconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	SJSON "github.com/sagernet/sing/common/json"
)

type object = map[string]any

type outboundMeta struct {
	emptyDirectTags map[string]bool
	dnsOutboundTags map[string]bool
	hasTag          map[string]bool
	directOverrides map[string]object
}

// Normalize upgrades configurations from older sing-box / NekoBox versions
// (1.8–1.13) while preserving modern sing-box 1.14+ configurations cleanly.
func Normalize(content, assetsDir string) (string, error) {
	config, err := SJSON.UnmarshalExtendedContext[object](context.Background(), []byte(content))
	if err != nil {
		return "", fmt.Errorf("decode config: %w", err)
	}
	if config == nil {
		return "", errors.New("expected a sing-box configuration object")
	}

	route := child(config, "route")
	if route == nil {
		route = object{}
	}

	outMeta := upgradeOutbounds(config, route)

	dns := child(config, "dns")
	var bootstrapDNS string
	var geoRefs []string
	if dns != nil {
		var dnsGeoRefs []string
		bootstrapDNS, dnsGeoRefs, err = upgradeDNS(dns, array(route["rule_set"]), outMeta.emptyDirectTags)
		if err != nil {
			return "", err
		}
		geoRefs = append(geoRefs, dnsGeoRefs...)
	}

	upgradeInbounds(config, route)
	routeGeoRefs := upgradeRouteRules(route, outMeta)
	geoRefs = append(geoRefs, routeGeoRefs...)

	defaultResolver := resolveDefaultDomainResolver(dns, route, bootstrapDNS)
	if defaultResolver != "" {
		if _, exists := route["default_domain_resolver"]; !exists {
			route["default_domain_resolver"] = defaultResolver
		}
	}
	upgradeOutboundDomainStrategy(config, defaultResolver)

	if err := upgradeRuleSets(route, assetsDir, geoRefs, outMeta.emptyDirectTags); err != nil {
		return "", err
	}
	if len(route) > 0 {
		config["route"] = route
	}
	encoded, err := json.Marshal(config)
	return string(encoded), err
}

func upgradeInbounds(config, route object) {
	var rules []any
	for i, item := range array(config["inbounds"]) {
		inbound, ok := item.(object)
		if !ok {
			continue
		}
		tag, _ := inbound["tag"].(string)
		sniff, _ := inbound["sniff"].(bool)
		strategy, _ := inbound["domain_strategy"].(string)
		if (sniff || strategy != "") && tag == "" {
			tag = fmt.Sprintf("inbound-%d", i)
			inbound["tag"] = tag
		}
		if sniff && tag != "" {
			rule := object{"inbound": tag, "action": "sniff"}
			move(inbound, "sniff_timeout", rule, "timeout")
			rules = append(rules, rule)
		}
		if strategy != "" && tag != "" {
			rules = append(rules, object{"inbound": tag, "action": "resolve", "strategy": strategy})
		}
		for _, key := range []string{
			"sniff", "sniff_timeout", "sniff_override_destination", "domain_strategy",
			"udp_disable_domain_unmapping", "proxy_protocol", "proxy_protocol_accept_no_header",
		} {
			delete(inbound, key)
		}
		if inbound["type"] != "tun" {
			continue
		}
		for _, field := range []string{"address", "route_address", "route_exclude_address"} {
			for _, family := range []string{"inet4_", "inet6_"} {
				if old := stringsArray(inbound[family+field]); len(old) != 0 {
					inbound[field] = append(stringsArray(inbound[field]), old...)
				}
				delete(inbound, family+field)
			}
		}
		if independent, _ := inbound["endpoint_independent_nat"].(bool); independent && inbound["udp_mapping"] == nil {
			inbound["udp_mapping"] = "endpoint_independent"
		}
		delete(inbound, "endpoint_independent_nat")
		delete(inbound, "gso")
	}
	if len(rules) != 0 {
		route["rules"] = append(rules, array(route["rules"])...)
	}
}

func upgradeOutbounds(config, route object) outboundMeta {
	meta := outboundMeta{
		emptyDirectTags: make(map[string]bool),
		dnsOutboundTags: make(map[string]bool),
		hasTag:          make(map[string]bool),
		directOverrides: make(map[string]object),
	}
	original := array(config["outbounds"])
	var outbounds []any
	endpoints := array(config["endpoints"])
	for i, item := range original {
		out, ok := item.(object)
		if !ok {
			outbounds = append(outbounds, item)
			continue
		}
		if out["domain_strategy"] == "" {
			delete(out, "domain_strategy")
		}
		outType, _ := out["type"].(string)
		tag, _ := out["tag"].(string)

		// Removed in sing-box 1.13.0: migrate dns outbound to hijack-dns route actions.
		if outType == "dns" {
			if tag != "" {
				meta.dnsOutboundTags[tag] = true
			}
			continue
		}

		// Removed in sing-box 1.13.0: migrate direct outbound destination override fields to route rules.
		if outType == "direct" {
			override := object{}
			move(out, "override_address", override, "override_address")
			move(out, "override_port", override, "override_port")
			delete(out, "proxy_protocol")
			if len(override) > 0 && tag != "" {
				meta.directOverrides[tag] = override
			}
			if isEmptyDirectOutbound(out) && tag != "" {
				meta.emptyDirectTags[tag] = true
			}
		}

		if outType != "wireguard" {
			if tag != "" {
				meta.hasTag[tag] = true
			}
			outbounds = append(outbounds, out)
			continue
		}
		upgradeWireGuard(out)
		if i == 0 && route["final"] == nil {
			if tag == "" {
				tag = "wireguard-0"
				out["tag"] = tag
			}
			route["final"] = tag
		}
		if tag != "" {
			meta.hasTag[tag] = true
		}
		endpoints = append(endpoints, out)
	}
	for _, item := range endpoints {
		if ep, ok := item.(object); ok {
			if ep["domain_strategy"] == "" {
				delete(ep, "domain_strategy")
			}
			if tag, _ := ep["tag"].(string); tag != "" {
				meta.hasTag[tag] = true
			}
		}
	}
	if len(original) != 0 {
		config["outbounds"] = outbounds
	}
	if len(endpoints) != 0 {
		config["endpoints"] = endpoints
	}
	return meta
}

func isEmptyDirectOutbound(out object) bool {
	for key, val := range out {
		if key == "type" || key == "tag" || key == "domain_strategy" {
			continue
		}
		if val == nil || val == "" || val == false {
			continue
		}
		return false
	}
	return true
}

func outboundSupportsDialer(outType string) bool {
	switch outType {
	case "", "selector", "urltest", "block", "dns", "mihomo-routing":
		return false
	default:
		return true
	}
}

func upgradeOutboundDomainStrategy(config object, defaultResolver string) {
	migrate := func(items []any) {
		for _, item := range items {
			out, ok := item.(object)
			if !ok {
				continue
			}
			strategy, _ := out["domain_strategy"].(string)
			if strategy == "" {
				delete(out, "domain_strategy")
				continue
			}
			outType, _ := out["type"].(string)
			if !outboundSupportsDialer(outType) {
				delete(out, "domain_strategy")
				continue
			}
			detour, _ := out["detour"].(string)
			if out["domain_resolver"] != nil || detour != "" {
				// Chained outbounds resolve remotely through their detour unless an
				// explicit domain_resolver is already configured.
				delete(out, "domain_strategy")
				continue
			}
			if defaultResolver != "" {
				out["domain_resolver"] = object{
					"server":   defaultResolver,
					"strategy": strategy,
				}
				delete(out, "domain_strategy")
			}
		}
	}
	migrate(array(config["outbounds"]))
	migrate(array(config["endpoints"]))
}

func upgradeWireGuard(out object) {
	move(out, "local_address", out, "address")
	move(out, "interface_name", out, "name")
	move(out, "system_interface", out, "system")
	delete(out, "gso")
	delete(out, "network")

	peers := array(out["peers"])
	if len(peers) == 0 {
		peer := object{}
		for old, field := range map[string]string{
			"server": "address", "server_port": "port", "peer_public_key": "public_key",
			"pre_shared_key": "pre_shared_key", "reserved": "reserved",
		} {
			move(out, old, peer, field)
		}
		peers = []any{peer}
	}
	for _, item := range peers {
		peer, ok := item.(object)
		if !ok {
			continue
		}
		move(peer, "server", peer, "address")
		move(peer, "server_port", peer, "port")
		move(peer, "peer_public_key", peer, "public_key")
		if peer["allowed_ips"] == nil {
			peer["allowed_ips"] = []string{"0.0.0.0/0", "::/0"}
		}
	}
	out["peers"] = peers
}

func upgradeRouteRules(route object, outMeta outboundMeta) []string {
	// Removed in sing-box 1.12.0: top-level geoip/geosite database download config.
	delete(route, "geoip")
	delete(route, "geosite")

	var geoRefs []string
	rules := array(route["rules"])
	if len(rules) == 0 {
		return nil
	}
	for _, item := range rules {
		rule, ok := item.(object)
		if !ok {
			continue
		}
		upgradeRouteRule(rule, outMeta, &geoRefs, true)
	}
	return geoRefs
}

func upgradeRouteRule(rule object, outMeta outboundMeta, geoRefs *[]string, topLevel bool) {
	move(rule, "rule_set_ipcidr_match_source", rule, "rule_set_ip_cidr_match_source")
	upgradeLegacyGeoRuleFields(rule, geoRefs)

	if subRules := array(rule["rules"]); len(subRules) > 0 {
		for _, sub := range subRules {
			if subObj, ok := sub.(object); ok {
				upgradeRouteRule(subObj, outMeta, geoRefs, false)
			}
		}
	}
	if !topLevel {
		return
	}

	outTag, _ := rule["outbound"].(string)
	if outTag == "" {
		return
	}
	if outMeta.dnsOutboundTags[outTag] {
		delete(rule, "outbound")
		rule["action"] = "hijack-dns"
		return
	}
	if outTag == "block" && !outMeta.hasTag["block"] {
		delete(rule, "outbound")
		rule["action"] = "reject"
		return
	}
	if override, exists := outMeta.directOverrides[outTag]; exists {
		for k, v := range override {
			if _, already := rule[k]; !already {
				rule[k] = v
			}
		}
	}
}

// upgradeLegacyGeoRuleFields migrates removed sing-box < 1.12 geosite, geoip,
// and source_geoip rule fields into inline rule_set references and ip_is_private.
func upgradeLegacyGeoRuleFields(rule object, geoRefs *[]string) {
	appendRuleSet := func(tag string) {
		existing := stringsArray(rule["rule_set"])
		for _, item := range existing {
			if s, _ := item.(string); s == tag {
				return
			}
		}
		rule["rule_set"] = append(existing, tag)
		*geoRefs = append(*geoRefs, tag)
	}

	if geosites := stringsArray(rule["geosite"]); len(geosites) > 0 {
		delete(rule, "geosite")
		for _, entry := range geosites {
			code, _ := entry.(string)
			code = strings.ToLower(strings.TrimSpace(code))
			if code != "" {
				appendRuleSet("geosite:" + code)
			}
		}
	}
	if geoips := stringsArray(rule["geoip"]); len(geoips) > 0 {
		delete(rule, "geoip")
		for _, entry := range geoips {
			code, _ := entry.(string)
			code = strings.ToLower(strings.TrimSpace(code))
			if code == "private" {
				rule["ip_is_private"] = true
			} else if code != "" {
				appendRuleSet("geoip:" + code)
			}
		}
	}
	if srcGeoips := stringsArray(rule["source_geoip"]); len(srcGeoips) > 0 {
		delete(rule, "source_geoip")
		hasNonPrivate := false
		for _, entry := range srcGeoips {
			code, _ := entry.(string)
			code = strings.ToLower(strings.TrimSpace(code))
			if code == "private" {
				rule["source_ip_is_private"] = true
			} else if code != "" {
				appendRuleSet("geoip:" + code)
				hasNonPrivate = true
			}
		}
		if hasNonPrivate {
			rule["rule_set_ip_cidr_match_source"] = true
		}
	}
}

func upgradeRuleSets(route object, assetsDir string, geoRefs []string, emptyDirectTags map[string]bool) error {
	existing := array(route["rule_set"])
	seen := make(map[string]bool, len(existing)+len(geoRefs))
	var merged []any

	for _, item := range existing {
		set, ok := item.(object)
		if !ok {
			merged = append(merged, item)
			continue
		}
		if tag, ok := set["tag"].(string); ok && tag != "" {
			if seen[tag] {
				continue
			}
			seen[tag] = true
		}
		merged = append(merged, set)
	}

	for _, ref := range geoRefs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		merged = append(merged, object{
			"type":   "local",
			"tag":    ref,
			"format": "binary",
			"path":   ref,
		})
	}

	for _, item := range merged {
		set, ok := item.(object)
		if !ok {
			continue
		}
		setType, _ := set["type"].(string)
		switch setType {
		case "local":
			path, _ := set["path"].(string)
			kind, code, hasCode := strings.Cut(path, ":")
			if hasCode && (kind == "geoip" || kind == "geosite") {
				rules, err := legacyGeoRules(assetsDir, kind, strings.ToLower(code))
				if err != nil {
					return fmt.Errorf("load %s: %w", path, err)
				}
				set["type"] = "inline"
				set["rules"] = []object{rules}
				delete(set, "path")
				delete(set, "format")
			} else if path != "" && !filepath.IsAbs(path) && assetsDir != "" {
				candidate := filepath.Join(assetsDir, path)
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					set["path"] = candidate
				}
			}
		case "remote":
			detour, _ := set["download_detour"].(string)
			if detour != "" && set["http_client"] == nil && !emptyDirectTags[detour] {
				set["http_client"] = object{"detour": detour}
				delete(set, "download_detour")
			}
		}
	}
	if len(merged) > 0 {
		route["rule_set"] = merged
	}
	return nil
}

func child(parent object, key string) object {
	child, _ := parent[key].(object)
	return child
}

func array(value any) []any {
	values, _ := value.([]any)
	return values
}

func stringsArray(value any) []any {
	if str, ok := value.(string); ok {
		return []any{str}
	}
	return array(value)
}

func move(from object, key string, to object, newKey string) {
	value, exists := from[key]
	if exists {
		delete(from, key)
		if _, exists := to[newKey]; !exists {
			to[newKey] = value
		}
	}
}

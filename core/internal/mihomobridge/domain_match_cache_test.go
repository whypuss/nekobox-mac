// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge

import (
	"io"
	"net/netip"
	"strconv"
	"testing"

	MC "github.com/metacubex/mihomo/constant"
)

type countedAdMatcher struct{ calls int }

func (*countedAdMatcher) FromMrs(io.Reader, int) error { return nil }
func (m *countedAdMatcher) Match(meta *MC.Metadata, _ MC.RuleMatchHelper) bool {
	m.calls++
	return meta.Host == "ad.example"
}

func TestDomainCachePreservesRouting(t *testing.T) {
	ads := &countedAdMatcher{}
	cache := &domainMatchCache{entries: make(map[domainMatchKey]domainMatchResult)}
	policy := &routingPolicy{adsDomain: ads, domainCache: cache}
	meta := &MC.Metadata{Host: "AD.EXAMPLE."}
	opts := matchOptions{mode: RoutingModeBypassCN, blockAds: true}
	check := func(fakeIP bool, want string) {
		t.Helper()
		if _, got := policy.matchAction(meta, fakeIP, opts); got != want {
			t.Fatalf("wanted %s, got %s", want, got)
		}
	}
	check(false, "GEOSITE,ads")
	meta.Host = "ad.example"
	check(false, "GEOSITE,ads")
	if ads.calls != 1 {
		t.Fatal("repeated domain lookup missed the cache")
	}
	meta.DstIP = netip.MustParseAddr("192.168.1.1")
	check(false, "PRIVATE-IP")
	check(true, "GEOSITE,ads")
	opts.mode = RoutingModeGFW
	check(true, "GEOSITE,ads")
	opts.blockAds = false
	check(true, "MATCH-GFW")
	if len(cache.entries) != 3 || ads.calls != 3 {
		t.Fatal("cache mixed routing options or retained a domain miss")
	}
	for i := 0; i <= domainMatchCacheLimit; i++ {
		cache.store(domainMatchKey{host: strconv.Itoa(i)}, domainMatchResult{action: actionDirect})
	}
	if len(cache.entries) != domainMatchCacheLimit {
		t.Fatalf("unexpected cache size %d", len(cache.entries))
	}
}

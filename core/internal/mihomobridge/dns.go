// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

const (
	DNSType              = "mihomo-dns"
	probeTimeout         = 1200 * time.Millisecond
	probeCacheTTL        = 10 * time.Minute
	probeCacheMaxEntries = 2048
)

func RegisterDNS(registry *dns.TransportRegistry) {
	dns.RegisterTransport(registry, DNSType, newDNSTransport)
}

type dnsOptions struct {
	Direct  string `json:"direct"`
	Remote  string `json:"remote"`
	Routing string `json:"routing"`
}

type probeCacheEntry struct {
	direct  bool
	expires time.Time
}

type probeCall struct {
	done   chan struct{}
	direct bool
	hit    bool
}

type routingDNSTransport struct {
	dns.TransportAdapter
	ctx       context.Context
	manager   adapter.DNSTransportManager
	outbounds adapter.OutboundManager
	options   dnsOptions
	direct    adapter.DNSTransport
	remote    adapter.DNSTransport

	probeMu    sync.RWMutex
	probeCache map[string]probeCacheEntry
	inFlight   map[string]*probeCall
}

func newDNSTransport(ctx context.Context, _ log.ContextLogger, tag string, options dnsOptions) (adapter.DNSTransport, error) {
	if options.Direct == "" || options.Remote == "" || options.Direct == options.Remote ||
		options.Direct == tag || options.Remote == tag {
		return nil, fmt.Errorf("Mihomo DNS requires separate direct and remote transports")
	}
	return &routingDNSTransport{
		TransportAdapter: dns.NewTransportAdapter(DNSType, tag, []string{options.Direct, options.Remote}),
		ctx:              ctx,
		manager:          service.FromContext[adapter.DNSTransportManager](ctx),
		outbounds:        service.FromContext[adapter.OutboundManager](ctx),
		options:          options,
		probeCache:       make(map[string]probeCacheEntry),
		inFlight:         make(map[string]*probeCall),
	}, nil
}

func (t *routingDNSTransport) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	t.direct, _ = t.manager.Transport(t.options.Direct)
	t.remote, _ = t.manager.Transport(t.options.Remote)
	if t.direct == nil || t.remote == nil {
		return fmt.Errorf("Mihomo DNS transports are unavailable")
	}
	return nil
}

func (t *routingDNSTransport) Close() error {
	return nil
}

func (t *routingDNSTransport) Reset() {
	t.probeMu.Lock()
	clear(t.probeCache)
	t.probeMu.Unlock()
}

func (t *routingDNSTransport) currentPolicyAndOptions() (*routingPolicy, matchOptions) {
	if t.outbounds != nil && t.options.Routing != "" {
		if out, loaded := t.outbounds.Outbound(t.options.Routing); loaded {
			if route, ok := out.(*routingOutbound); ok {
				if policy := route.policy.Load(); policy != nil {
					return policy, route.matchOpts
				}
				return nil, route.matchOpts
			}
		}
	}
	policy, _ := bundledPolicy()
	return policy, matchOptions{mode: RoutingModeBypassCN}
}

func (t *routingDNSTransport) lookupProbeCache(host string) (direct bool, hit bool) {
	t.probeMu.RLock()
	entry, ok := t.probeCache[host]
	t.probeMu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return false, false
	}
	return entry.direct, true
}

func (t *routingDNSTransport) storeProbeCache(host string, direct bool) {
	t.probeMu.Lock()
	if t.probeCache == nil {
		t.probeCache = make(map[string]probeCacheEntry)
	}
	if len(t.probeCache) >= probeCacheMaxEntries {
		now := time.Now()
		for k, v := range t.probeCache {
			if now.After(v.expires) {
				delete(t.probeCache, k)
			}
		}
		if len(t.probeCache) >= probeCacheMaxEntries {
			clear(t.probeCache)
		}
	}
	t.probeCache[host] = probeCacheEntry{
		direct:  direct,
		expires: time.Now().Add(probeCacheTTL),
	}
	t.probeMu.Unlock()
}

func extractAnswerIPs(msg *mDNS.Msg) []netip.Addr {
	if msg == nil || msg.Rcode != mDNS.RcodeSuccess {
		return nil
	}
	var addrs []netip.Addr
	for _, rr := range msg.Answer {
		switch rec := rr.(type) {
		case *mDNS.A:
			if addr, ok := netip.AddrFromSlice(rec.A); ok {
				addrs = append(addrs, addr.Unmap())
			}
		case *mDNS.AAAA:
			if addr, ok := netip.AddrFromSlice(rec.AAAA); ok {
				addrs = append(addrs, addr.Unmap())
			}
		}
	}
	return addrs
}

func allDirectIPs(policy *routingPolicy, addrs []netip.Addr) bool {
	if policy == nil || len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		if !policy.isDirectIP(addr) {
			return false
		}
	}
	return true
}

func nxdomainResponse(query *mDNS.Msg) *mDNS.Msg {
	resp := new(mDNS.Msg)
	resp.SetReply(query)
	resp.Rcode = mDNS.RcodeNameError
	return resp
}

// selectTransport is a synchronous helper for deterministic domain split selection.
func (t *routingDNSTransport) selectTransport(message *mDNS.Msg) adapter.DNSTransport {
	policy, opts := t.currentPolicyAndOptions()
	if message != nil && len(message.Question) > 0 && policy != nil {
		host := strings.ToLower(strings.TrimSuffix(message.Question[0].Name, "."))
		if action, matched, _ := policy.matchDomainAction(host, opts); matched {
			if action == actionDirect {
				return t.direct
			}
			return t.remote
		}
		if normalizeRoutingMode(opts.mode) == RoutingModeGFW {
			return t.direct
		}
		if direct, ok := t.lookupProbeCache(host); ok && direct {
			return t.direct
		}
	}
	return t.remote
}

func (t *routingDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if message == nil || len(message.Question) == 0 {
		return t.remote.Exchange(ctx, message)
	}
	q := message.Question[0]
	host := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	policy, opts := t.currentPolicyAndOptions()

	if policy != nil {
		if action, matched, _ := policy.matchDomainAction(host, opts); matched {
			switch action {
			case actionReject:
				return nxdomainResponse(message), nil
			case actionDirect:
				return t.direct.Exchange(ctx, message)
			default:
				return t.remote.Exchange(ctx, message)
			}
		}

		// GFW mode: unmatched domains always resolve directly.
		if normalizeRoutingMode(opts.mode) == RoutingModeGFW {
			return t.direct.Exchange(ctx, message)
		}

		// Bypass-CN mode: for completely unlisted domains on A/AAAA queries, probe dns-direct
		// once (deduplicated across concurrent A/AAAA lookups) to eliminate the FakeDNS GEOIP,cn
		// blindspot and prevent FakeIPv6 from hijacking IPv4-only domestic domains.
		if q.Qtype == mDNS.TypeA || q.Qtype == mDNS.TypeAAAA {
			directResp, isDirect, decided := t.probeUnlistedDomain(ctx, policy, host, message, q.Qtype)
			if decided {
				if isDirect {
					if directResp != nil {
						return directResp, nil
					}
					return t.direct.Exchange(ctx, message)
				}
				return t.remote.Exchange(ctx, message)
			}
		}
	}
	return t.remote.Exchange(ctx, message)
}

func (t *routingDNSTransport) probeUnlistedDomain(
	ctx context.Context,
	policy *routingPolicy,
	host string,
	message *mDNS.Msg,
	qtype uint16,
) (directResp *mDNS.Msg, isDirect bool, decided bool) {
	if direct, hit := t.lookupProbeCache(host); hit {
		return nil, direct, true
	}

	// Deduplicate concurrent A / AAAA probes for the same host.
	t.probeMu.Lock()
	if t.inFlight == nil {
		t.inFlight = make(map[string]*probeCall)
	}
	if call, waiting := t.inFlight[host]; waiting {
		t.probeMu.Unlock()
		select {
		case <-call.done:
			return nil, call.direct, call.hit
		case <-ctx.Done():
			return nil, false, false
		}
	}
	call := &probeCall{done: make(chan struct{})}
	t.inFlight[host] = call
	t.probeMu.Unlock()

	defer func() {
		t.probeMu.Lock()
		delete(t.inFlight, host)
		t.probeMu.Unlock()
		close(call.done)
	}()

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	resp, err := t.direct.Exchange(probeCtx, message)
	cancel()
	if err == nil && resp != nil {
		addrs := extractAnswerIPs(resp)
		if allDirectIPs(policy, addrs) {
			t.storeProbeCache(host, true)
			call.direct = true
			call.hit = true
			return resp, true, true
		}
		if len(addrs) > 0 {
			t.storeProbeCache(host, false)
			call.direct = false
			call.hit = true
			return nil, false, true
		}
		// If AAAA returned empty NOERROR, probe TypeA once so an IPv4-only domestic domain
		// is recognized as direct instead of receiving a FakeIPv6 from dns-fake.
		if qtype == mDNS.TypeAAAA && resp.Rcode == mDNS.RcodeSuccess {
			aQuery := new(mDNS.Msg)
			aQuery.SetQuestion(message.Question[0].Name, mDNS.TypeA)
			aCtx, aCancel := context.WithTimeout(ctx, probeTimeout)
			aResp, aErr := t.direct.Exchange(aCtx, aQuery)
			aCancel()
			if aErr == nil && aResp != nil {
				aAddrs := extractAnswerIPs(aResp)
				if allDirectIPs(policy, aAddrs) {
					t.storeProbeCache(host, true)
					call.direct = true
					call.hit = true
					return resp, true, true
				}
				if len(aAddrs) > 0 {
					t.storeProbeCache(host, false)
					call.direct = false
					call.hit = true
					return nil, false, true
				}
			}
		}
	}
	return nil, false, false
}

func (t *routingDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		resp, err := t.Exchange(ctx, message)
		callback(resp, err)
	}()
}

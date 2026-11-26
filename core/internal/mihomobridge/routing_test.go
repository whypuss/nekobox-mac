package mihomobridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	MC "github.com/metacubex/mihomo/constant"
	mDNS "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func TestBundledMihomoRoutingPolicy(t *testing.T) {
	policy, err := bundledPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, ip     string
		fake, direct bool
	}{
		{host: "WWW.BAIDU.COM.", direct: true},
		{host: "github.com", ip: "114.114.114.114"},
		{host: "local-placeholder.invalid", direct: true},
		{host: "neko-routing-fixture-37ff1e4d.com"},
		{host: "neko-unlisted-domestic-37ff1e4d.com", ip: "114.114.114.114", direct: true},
		{host: "neko-unlisted-domestic-37ff1e4d.com", ip: "114.114.114.114", fake: true, direct: false},
		{ip: "114.114.114.114", direct: true},
		{ip: "8.8.8.8"},
		{ip: "192.168.1.2", direct: true},
		{ip: "fc00::1", fake: true},
		{host: "baidu.com", ip: "198.18.0.1", fake: true, direct: true},
	} {
		ip, _ := netip.ParseAddr(tc.ip)
		if got, _ := policy.match(&MC.Metadata{Host: tc.host, DstIP: ip}, tc.fake); got != tc.direct {
			t.Errorf("%s / %s: direct = %v, want %v", tc.host, tc.ip, got, tc.direct)
		}
	}
}

func TestMihomoRuleRefreshKeepsLastValidCache(t *testing.T) {
	bundledRevision, err := bundledRules.ReadFile("rules/revision.txt")
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.TrimSpace(string(bundledRevision))
	var invalid atomic.Bool
	var ruleRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		current := revision
		if invalid.Load() {
			current = strings.Repeat("0", 40)
		}
		if req.URL.Path == "/ref" {
			fmt.Fprintf(w, `{"sha":"%s"}`, current)
			return
		}
		for _, rule := range ruleFiles {
			if req.URL.Path != "/"+current+"/"+rule.source {
				continue
			}
			ruleRequests.Add(1)
			if invalid.Load() && rule.name == "cn-ip.mrs" {
				fmt.Fprint(w, "invalid MRS")
				return
			}
			data, err := bundledRules.ReadFile("rules/" + rule.name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(data)
			return
		}
		http.NotFound(w, req)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "mihomo.json")
	refresh := func(current string) (*routingPolicy, error) {
		return updateRuleCache(context.Background(), server.Client(), path, server.URL+"/ref", server.URL+"/", current)
	}
	updatedPolicy, err := refresh("")
	if err != nil {
		t.Fatal(err)
	}
	if updatedPolicy == nil || updatedPolicy.updatedAt.IsZero() {
		t.Fatal("download did not record the update time")
	}
	if policy, err := refresh(revision); err != nil || policy != nil || ruleRequests.Load() != int32(len(ruleFiles)) {
		t.Fatalf("unchanged revision downloaded rule files again: policy=%v, requests=%d, err=%v", policy, ruleRequests.Load(), err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	invalid.Store(true)
	if _, err := refresh(revision); err == nil {
		t.Fatal("invalid update was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("last good cache was lost: %v", err)
	}
	if cached, err := readRuleCache(path); err != nil {
		t.Fatal(err)
	} else if cached.revision != revision || !cached.updatedAt.Equal(updatedPolicy.updatedAt) || cached.checkedAt.Before(cached.updatedAt) {
		t.Fatal("the cache did not retain its rule identity and update time")
	}

	// Unchanged bundled revision should still persist a cache file so restarts do not re-query immediately.
	invalid.Store(false)
	freshPath := filepath.Join(t.TempDir(), "fresh-mihomo.json")
	if policy, err := updateRuleCache(context.Background(), server.Client(), freshPath, server.URL+"/ref", server.URL+"/", revision); err != nil || policy != nil {
		t.Fatalf("unexpected fresh unchanged refresh: policy=%v, err=%v", policy, err)
	}
	if cached, err := readRuleCache(freshPath); err != nil || cached.revision != revision || !cached.updatedAt.IsZero() || cached.checkedAt.IsZero() {
		t.Fatalf("unchanged revision did not persist bundled cache timestamp: cached=%v, err=%v", cached, err)
	}
}

type stubDNSTransport struct {
	adapter.DNSTransport
	tag string
}

func (s *stubDNSTransport) Tag() string { return s.tag }

func TestMihomoDNSSplitSelection(t *testing.T) {
	direct := &stubDNSTransport{tag: "dns-direct"}
	remote := &stubDNSTransport{tag: "dns-remote"}
	transport := &routingDNSTransport{direct: direct, remote: remote}
	query := func(domain string) string {
		msg := new(mDNS.Msg)
		msg.SetQuestion(mDNS.Fqdn(domain), mDNS.TypeA)
		return transport.selectTransport(msg).Tag()
	}
	if got := query("www.taobao.com"); got != "dns-direct" {
		t.Fatalf("CN domain used %s, want dns-direct", got)
	}
	if got := query("local-placeholder.invalid"); got != "dns-direct" {
		t.Fatalf("private domain used %s, want dns-direct", got)
	}
	if got := query("github.com"); got != "dns-remote" {
		t.Fatalf("foreign domain used %s, want dns-remote", got)
	}
	if got := query("neko-routing-fixture-37ff1e4d.com"); got != "dns-remote" {
		t.Fatalf("unknown domain used %s, want dns-remote", got)
	}
}

func TestMihomoDNSTransportRegistration(t *testing.T) {
	outbounds := include.OutboundRegistry()
	RegisterRouting(outbounds)
	dnsTransports := include.DNSTransportRegistry()
	RegisterDNS(dnsTransports)
	ctx := box.Context(context.Background(), include.InboundRegistry(), outbounds, include.EndpointRegistry(),
		dnsTransports, include.ServiceRegistry(), include.CertificateProviderRegistry())
	config := `{"log":{"disabled":true},
		"dns":{
			"servers":[
				{"type":"local","tag":"dns-direct"},
				{"type":"local","tag":"dns-remote"},
				{"type":"mihomo-dns","tag":"dns-meta","direct":"dns-direct","remote":"dns-remote","routing":"meta-auto"}
			],
			"final":"dns-meta"
		},
		"outbounds":[
			{"type":"direct","tag":"direct"},
			{"type":"block","tag":"proxy"},
			{"type":"mihomo-routing","tag":"meta-auto","proxy":"proxy","direct":"direct"}
		],
		"route":{"final":"meta-auto"}}`
	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	if _, ok := instance.Outbound().Outbound("meta-auto"); !ok {
		t.Fatal("meta-auto outbound was not registered")
	}
}

func TestMihomoRoutingOutbound(t *testing.T) {
	registry := include.OutboundRegistry()
	RegisterRouting(registry)
	ctx := box.Context(context.Background(), include.InboundRegistry(), registry, include.EndpointRegistry(),
		include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	config := `{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"proxy"},
		{"type":"mihomo-routing","tag":"meta-auto","proxy":"proxy","direct":"direct"}],"route":{"final":"meta-auto"}}`
	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	dialer := instance.Outbound().Default()
	loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	defer loopback.Close()
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	address := M.ParseSocksaddr(strings.TrimPrefix(loopback.URL, "http://"))
	appContext := adapter.WithContext(testCtx, &adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{UserId: 10042},
	})
	conn, err := dialer.DialContext(appContext, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if foreign, err := dialer.DialContext(appContext, "tcp", M.ParseSocksaddr("github.com:443")); err == nil {
		foreign.Close()
		t.Fatal("foreign domain did not use the block fixture as proxy")
	}
	var status struct {
		Source    string
		Revision  string
		Decisions []routingDecision
	}
	if err := json.Unmarshal([]byte(RoutingStatus(instance.Outbound())), &status); err != nil {
		t.Fatal(err)
	}
	if status.Source != ruleSource || status.Revision == "" || len(status.Decisions) != 2 {
		t.Fatalf("unexpected routing status: %+v", status)
	}
	proxyAttempt, direct := status.Decisions[0], status.Decisions[1]
	if proxyAttempt.UID != 10042 || proxyAttempt.Destination != "github.com" ||
		(proxyAttempt.Rule != "GEOSITE,geolocation-!cn" && proxyAttempt.Rule != "GEOSITE,gfw") ||
		proxyAttempt.Direct || proxyAttempt.Succeeded {
		t.Fatalf("unexpected proxy attempt: %+v", proxyAttempt)
	}
	if direct.UID != 10042 || !direct.Direct || !direct.Succeeded {
		t.Fatalf("unexpected direct connection: %+v", direct)
	}
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var payload [32]byte
		if n, peer, err := echo.ReadFrom(payload[:]); err == nil {
			echo.WriteTo(payload[:n], peer)
		}
	}()
	target := M.ParseSocksaddr(echo.LocalAddr().String())
	packets, err := dialer.ListenPacket(testCtx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	if err := packets.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := packets.WriteTo([]byte("meta"), target.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	var payload [32]byte
	n, _, err := packets.ReadFrom(payload[:])
	if err != nil || string(payload[:n]) != "meta" {
		t.Fatalf("UDP reply through the direct route: %q, %v", payload[:n], err)
	}
}

func TestRecentMihomoDecisionsKeepDistinctAppsAndBoundHistory(t *testing.T) {
	var route routingOutbound
	for uid := int32(10000); uid < 10020; uid++ {
		decision := routingDecision{UID: uid, Destination: "example.org", Rule: "MATCH"}
		route.recordDecision(decision, true)
		route.recordDecision(decision, true)
	}
	history := route.recentDecisions()
	if len(history) != recentDecisionLimit || history[0].UID != 10019 || history[len(history)-1].UID != 10008 {
		t.Fatalf("unexpected recent decisions: %+v", history)
	}
}

func TestEnhancedMetaRuleSetsAndModes(t *testing.T) {
	policy, err := bundledPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.ruleSetCount != len(metaCubeXSpec.files) {
		t.Fatalf("expected all %d bundled MRS rule sets loaded, got %d", len(metaCubeXSpec.files), policy.ruleSetCount)
	}

	// Priority CN direct sets override geolocation-!cn.
	if act, rule := policy.matchAction(&MC.Metadata{Host: "apps.mzstatic.com"}, false, matchOptions{mode: RoutingModeBypassCN}); act != actionDirect {
		t.Fatalf("apple-cn domain should be direct, got action=%s rule=%s", act, rule)
	}
	if act, rule := policy.matchAction(&MC.Metadata{Host: "steamserver.net"}, false, matchOptions{mode: RoutingModeBypassCN}); act != actionDirect {
		t.Fatalf("steam@cn domain should be direct, got action=%s rule=%s", act, rule)
	}
	if act, rule := policy.matchAction(&MC.Metadata{Host: "dl.google.com"}, false, matchOptions{mode: RoutingModeBypassCN}); act != actionDirect {
		t.Fatalf("google-cn domain should be direct, got action=%s rule=%s", act, rule)
	}

	// AI & Telegram IP force proxy.
	if act, rule := policy.matchAction(&MC.Metadata{Host: "api.openai.com"}, false, matchOptions{mode: RoutingModeBypassCN}); act != actionProxy || rule != "GEOSITE,ai" {
		t.Fatalf("AI domain should route to proxy via GEOSITE,ai, got action=%s rule=%s", act, rule)
	}
	tgIP, _ := netip.ParseAddr("149.154.167.50")
	if act, rule := policy.matchAction(&MC.Metadata{DstIP: tgIP}, false, matchOptions{mode: RoutingModeBypassCN}); act != actionProxy || rule != "GEOIP,telegram" {
		t.Fatalf("Telegram IP should route to proxy via GEOIP,telegram, got action=%s rule=%s", act, rule)
	}

	// GFW mode keeps unknown domestic domains direct while still proxying AI & GFW domains (both "gfw" and UI "gfw_only").
	for _, gfwModeVal := range []string{RoutingModeGFW, "gfw_only"} {
		gfwOpts := matchOptions{mode: gfwModeVal}
		if act, rule := policy.matchAction(&MC.Metadata{Host: "neko-unlisted-domestic-37ff1e4d.com"}, true, gfwOpts); act != actionDirect || rule != "MATCH-GFW" {
			t.Fatalf("GFW mode (%s) should direct unknown domains, got action=%s rule=%s", gfwModeVal, act, rule)
		}
		if act, _ := policy.matchAction(&MC.Metadata{Host: "api.openai.com"}, true, gfwOpts); act != actionProxy {
			t.Fatalf("GFW mode (%s) should proxy AI domains, got %s", gfwModeVal, act)
		}
	}

	// Optional ad blocking rejects only when blockAds=true.
	if act, _ := policy.matchAction(&MC.Metadata{Host: "pagead2.googlesyndication.com"}, false, matchOptions{mode: RoutingModeBypassCN, blockAds: true}); act != actionReject {
		t.Fatalf("expected ad domain to be rejected when blockAds=true, got %s", act)
	}
	if act, _ := policy.matchAction(&MC.Metadata{Host: "pagead2.googlesyndication.com"}, false, matchOptions{mode: RoutingModeBypassCN, blockAds: false}); act == actionReject {
		t.Fatalf("ad domain must not be rejected when blockAds=false")
	}
}

type mockExchangeDNS struct {
	adapter.DNSTransport
	tag     string
	answers map[string]string
	noAAAA  map[string]bool
	calls   int
}

func (m *mockExchangeDNS) Tag() string { return m.tag }

func (m *mockExchangeDNS) Exchange(_ context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	m.calls++
	resp := new(mDNS.Msg)
	resp.SetReply(msg)
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		host := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		if q.Qtype == mDNS.TypeAAAA && m.noAAAA[host] {
			return resp, nil
		}
		if ipStr, ok := m.answers[host]; ok {
			rr, err := mDNS.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ipStr))
			if err == nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
	}
	return resp, nil
}

func TestMihomoDNSFakeIPChinaProbeAndAdBlock(t *testing.T) {
	direct := &mockExchangeDNS{
		tag: "dns-direct",
		answers: map[string]string{
			"unlisted-cn-bank-37ff1e4d.org":      "114.114.114.114",
			"ipv4-only-cn-bank-37ff1e4d.org":     "114.114.114.114",
			"unlisted-foreign-site-37ff1e4d.org": "8.8.8.8",
		},
		noAAAA: map[string]bool{
			"ipv4-only-cn-bank-37ff1e4d.org": true,
		},
	}
	remote := &mockExchangeDNS{
		tag: "dns-remote",
		answers: map[string]string{
			"unlisted-cn-bank-37ff1e4d.org":      "198.18.0.10",
			"ipv4-only-cn-bank-37ff1e4d.org":     "198.18.0.12",
			"unlisted-foreign-site-37ff1e4d.org": "198.18.0.11",
		},
	}
	tr := &routingDNSTransport{
		direct:     direct,
		remote:     remote,
		probeCache: make(map[string]probeCacheEntry),
		inFlight:   make(map[string]*probeCall),
	}

	// Unlisted CN domain: probe detects 114.114.114.114 in cn-ip.mrs and returns REAL CN IP instead of FakeIP!
	cnQuery := new(mDNS.Msg)
	cnQuery.SetQuestion("unlisted-cn-bank-37ff1e4d.org.", mDNS.TypeA)
	cnResp, err := tr.Exchange(context.Background(), cnQuery)
	if err != nil {
		t.Fatal(err)
	}
	cnIPs := extractAnswerIPs(cnResp)
	if len(cnIPs) != 1 || cnIPs[0].String() != "114.114.114.114" {
		t.Fatalf("expected real CN IP from direct DNS probe, got %v", cnIPs)
	}

	// Unlisted IPv4-only CN domain queried for AAAA must NOT fall through to remote/FakeIPv6!
	remoteBefore := remote.calls
	aaaaQuery := new(mDNS.Msg)
	aaaaQuery.SetQuestion("ipv4-only-cn-bank-37ff1e4d.org.", mDNS.TypeAAAA)
	aaaaResp, err := tr.Exchange(context.Background(), aaaaQuery)
	if err != nil {
		t.Fatal(err)
	}
	if aaaaResp.Rcode != mDNS.RcodeSuccess || len(aaaaResp.Answer) != 0 {
		t.Fatalf("expected empty NOERROR direct AAAA response, got rcode=%d answers=%d", aaaaResp.Rcode, len(aaaaResp.Answer))
	}
	if remote.calls != remoteBefore {
		t.Fatalf("IPv4-only unlisted CN domain AAAA must not fall through to remote/FakeIPv6")
	}

	// Unlisted foreign domain: probe sees 8.8.8.8 (not CN), falls through to remote/FakeIP!
	foreignQuery := new(mDNS.Msg)
	foreignQuery.SetQuestion("unlisted-foreign-site-37ff1e4d.org.", mDNS.TypeA)
	foreignResp, err := tr.Exchange(context.Background(), foreignQuery)
	if err != nil {
		t.Fatal(err)
	}
	foreignIPs := extractAnswerIPs(foreignResp)
	if len(foreignIPs) != 1 || foreignIPs[0].String() != "198.18.0.11" {
		t.Fatalf("expected remote/FakeIP for unlisted foreign domain, got %v", foreignIPs)
	}
}

func TestMihomoRoutingOutboundSystemProxyDirectDNSProbe(t *testing.T) {
	policy, err := bundledPolicy()
	if err != nil {
		t.Fatalf("load bundled policy: %v", err)
	}
	directDNS := &mockExchangeDNS{
		tag: "dns-direct",
		answers: map[string]string{
			"unlisted-cn-site-37ff1e4d.org":       "114.114.114.114",
			"unlisted-overseas-site-37ff1e4d.org": "8.8.8.8",
			"intranet-app-37ff1e4d.org":           "192.168.10.5",
		},
	}
	directOut := &stubOutbound{tag: "bypass"}
	proxyOut := &stubOutbound{tag: "proxy"}

	o := &routingOutbound{
		matchOpts:  matchOptions{mode: RoutingModeBypassCN},
		direct:     directOut,
		proxy:      proxyOut,
		directDNS:  directDNS,
		probeCache: make(map[string]routeProbeCacheEntry),
		inFlight:   make(map[string]*routeProbeCall),
	}
	o.policy.Store(policy)

	// Unlisted domestic domain passed by name (mixed/system_proxy mode: no DstIP) must resolve via dns-direct and bypass directly.
	out, decision := o.outboundFor(context.Background(), nil, M.Socksaddr{Fqdn: "unlisted-cn-site-37ff1e4d.org", Port: 443}, true)
	if out != directOut || !decision.Direct || decision.Rule != "GEOIP,cn" {
		t.Fatalf("expected unlisted CN domain to route direct via GEOIP,cn, got out=%v decision=%+v", out, decision)
	}

	// Unlisted intranet domain resolving to RFC1918 IP must bypass as PRIVATE-IP.
	outPriv, decPriv := o.outboundFor(context.Background(), nil, M.Socksaddr{Fqdn: "intranet-app-37ff1e4d.org", Port: 443}, true)
	if outPriv != directOut || !decPriv.Direct || decPriv.Rule != "PRIVATE-IP" {
		t.Fatalf("expected unlisted intranet domain to route direct via PRIVATE-IP, got out=%v decision=%+v", outPriv, decPriv)
	}

	// Unlisted overseas domain must still route via proxy.
	out2, decision2 := o.outboundFor(context.Background(), nil, M.Socksaddr{Fqdn: "unlisted-overseas-site-37ff1e4d.org", Port: 443}, true)
	if out2 != proxyOut || decision2.Direct {
		t.Fatalf("expected unlisted overseas domain to route via proxy, got out=%v decision=%+v", out2, decision2)
	}
}

type stubOutbound struct {
	adapter.Outbound
	tag string
}

func (s *stubOutbound) Tag() string { return s.tag }

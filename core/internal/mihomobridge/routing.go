// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	MC "github.com/metacubex/mihomo/constant"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const RoutingType = "mihomo-routing"
const recentDecisionLimit = 12

var errBlockedByMeta = errors.New("connection blocked by Meta ad filter")

type cacheKey struct{}

func WithRuleCache(ctx context.Context, directory string) context.Context {
	return context.WithValue(ctx, cacheKey{}, directory)
}

func RegisterRouting(registry *outbound.Registry) {
	outbound.Register(registry, RoutingType, newRoutingOutbound)
}

type routingOptions struct {
	Proxy      string `json:"proxy"`
	Direct     string `json:"direct"`
	RuleSource string `json:"rule_source,omitempty"`
	Mode       string `json:"mode,omitempty"`
	BlockAds   bool   `json:"block_ads,omitempty"`
}

type routingOutbound struct {
	outbound.Adapter
	ctx        context.Context
	manager    adapter.OutboundManager
	logger     log.ContextLogger
	options    routingOptions
	sourceID   string
	matchOpts  matchOptions
	proxy      adapter.Outbound
	direct     adapter.Outbound
	policy     atomic.Pointer[routingPolicy]
	refreshMu  sync.Mutex
	decisionMu sync.Mutex
	decisions  []routingDecision
}

type routingDecision struct {
	Destination string `json:"destination"`
	Rule        string `json:"rule"`
	Direct      bool   `json:"direct"`
	Action      string `json:"action,omitempty"`
	At          int64  `json:"at"`
	UID         int32  `json:"uid"`
	Succeeded   bool   `json:"succeeded"`
}

func newRoutingOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options routingOptions) (adapter.Outbound, error) {
	if options.Proxy == "" || options.Direct == "" || options.Proxy == options.Direct || options.Proxy == tag || options.Direct == tag {
		return nil, fmt.Errorf("Mihomo routing requires separate proxy and direct outbounds")
	}
	return &routingOutbound{
		Adapter:  outbound.NewAdapter(RoutingType, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{options.Proxy, options.Direct}),
		ctx:      ctx,
		manager:  service.FromContext[adapter.OutboundManager](ctx),
		logger:   logger,
		options:  options,
		sourceID: normalizeRuleSource(options.RuleSource),
		matchOpts: matchOptions{
			mode:     normalizeRoutingMode(options.Mode),
			blockAds: options.BlockAds,
		},
	}, nil
}

func (o *routingOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		o.proxy, _ = o.manager.Outbound(o.options.Proxy)
		o.direct, _ = o.manager.Outbound(o.options.Direct)
		if o.proxy == nil || o.direct == nil {
			return fmt.Errorf("Mihomo routing outbounds are unavailable")
		}
		dir, _ := o.ctx.Value(cacheKey{}).(string)
		policy, err := readCachedPolicyForSource(dir, o.sourceID)
		if err != nil {
			policy, err = bundledPolicy()
			if err != nil {
				return err
			}
		}
		o.policy.Store(policy)
	case adapter.StartStatePostStart:
		if file := o.cacheFile(); file != "" {
			ctx, cancel := context.WithCancel(o.ctx)
			done := make(chan struct{})
			scope.Add(func() error {
				cancel()
				<-done
				return nil
			})
			go func() {
				defer close(done)
				o.refreshRules(ctx, file)
			}()
		}
	}
	return nil
}

func (o *routingOutbound) outboundFor(inbound *adapter.InboundContext, dest M.Socksaddr) (adapter.Outbound, routingDecision) {
	policy := o.policy.Load()
	meta := MC.Metadata{Host: dest.Fqdn, DstIP: dest.Addr.Unmap(), DstPort: dest.Port}
	fakeIP := false
	if inbound != nil {
		if meta.Host == "" {
			meta.Host = inbound.Domain
		}
		fakeIP = inbound.FakeIP
	}
	action, rule := actionProxy, "MATCH"
	if policy != nil {
		action, rule = policy.matchAction(&meta, fakeIP, o.matchOpts)
	}
	decision := routingDecision{
		Destination: meta.Host,
		Rule:        rule,
		Direct:      action == actionDirect,
		Action:      action.String(),
		UID:         -1,
	}
	if decision.Destination == "" {
		decision.Destination = dest.AddrString()
	}
	if inbound != nil && inbound.ProcessInfo != nil {
		decision.UID = inbound.ProcessInfo.UserId
	}
	switch action {
	case actionDirect:
		return o.direct, decision
	case actionReject:
		return nil, decision
	default:
		return o.proxy, decision
	}
}

func (o *routingOutbound) recordDecision(decision routingDecision, succeeded bool) {
	decision.At = time.Now().UnixMilli()
	decision.Succeeded = succeeded
	o.decisionMu.Lock()
	defer o.decisionMu.Unlock()

	if count := len(o.decisions); count > 0 {
		last := o.decisions[count-1]
		last.At = decision.At
		if last == decision {
			o.decisions[count-1] = decision
			return
		}
	}
	if len(o.decisions) == recentDecisionLimit {
		copy(o.decisions, o.decisions[1:])
		o.decisions[len(o.decisions)-1] = decision
		return
	}
	o.decisions = append(o.decisions, decision)
}

func (o *routingOutbound) recentDecisions() []routingDecision {
	o.decisionMu.Lock()
	defer o.decisionMu.Unlock()
	decisions := slices.Clone(o.decisions)
	slices.Reverse(decisions)
	return decisions
}

func (p *routingPolicy) status(decisions []routingDecision, opts matchOptions) string {
	repo := p.sourceRepo
	if repo == "" {
		repo = ruleSource
	}
	sourceID := p.sourceID
	if sourceID == "" {
		sourceID = RuleSourceMetaCubeX
	}
	status := struct {
		Source       string            `json:"source"`
		SourceID     string            `json:"source_id"`
		Mode         string            `json:"mode"`
		BlockAds     bool              `json:"block_ads"`
		RuleSets     int               `json:"rule_sets"`
		Revision     string            `json:"revision"`
		UpdatedAt    int64             `json:"updated_at,omitempty"`
		CheckedAt    int64             `json:"checked_at,omitempty"`
		Decision     *routingDecision  `json:"decision,omitempty"`
		Decisions    []routingDecision `json:"decisions,omitempty"`
	}{
		Source:    repo,
		SourceID:  sourceID,
		Mode:      normalizeRoutingMode(opts.mode),
		BlockAds:  opts.blockAds,
		RuleSets:  p.ruleSetCount,
		Revision:  p.revision,
		Decisions: decisions,
	}
	if !p.updatedAt.IsZero() {
		status.UpdatedAt = p.updatedAt.UnixMilli()
	}
	if !p.checkedAt.IsZero() {
		status.CheckedAt = p.checkedAt.UnixMilli()
	}
	if len(decisions) > 0 {
		status.Decision = &decisions[0]
	}
	data, _ := json.Marshal(status)
	return string(data)
}

func CachedRoutingStatus(directory string) string {
	return CachedRoutingStatusForSource(directory, RuleSourceMetaCubeX)
}

func CachedRoutingStatusForSource(directory, sourceID string) string {
	normalized := normalizeRuleSource(sourceID)
	if directory != "" {
		if policy, err := readCachedPolicyForSource(directory, normalized); err == nil {
			return policy.status(nil, matchOptions{mode: RoutingModeBypassCN})
		}
	}
	if policy, err := bundledPolicy(); err == nil {
		return policy.status(nil, matchOptions{mode: RoutingModeBypassCN})
	}
	return ""
}

func RoutingStatus(manager adapter.OutboundManager) string {
	for _, out := range manager.Outbounds() {
		route, ok := out.(*routingOutbound)
		if !ok {
			continue
		}
		policy := route.policy.Load()
		if policy == nil {
			continue
		}
		return policy.status(route.recentDecisions(), route.matchOpts)
	}
	return ""
}

func RefreshRulesNow(manager adapter.OutboundManager) (string, error) {
	if manager == nil {
		return "", fmt.Errorf("outbound manager is unavailable")
	}
	for _, out := range manager.Outbounds() {
		route, ok := out.(*routingOutbound)
		if !ok {
			continue
		}
		file := route.cacheFile()
		if file == "" {
			return "", fmt.Errorf("rule cache directory is unavailable")
		}
		ctx, cancel := context.WithTimeout(route.ctx, 60*time.Second)
		defer cancel()
		if _, err := route.runRefreshOnce(ctx, file, true); err != nil {
			return "", err
		}
		if policy := route.policy.Load(); policy != nil {
			return policy.status(route.recentDecisions(), route.matchOpts), nil
		}
	}
	return "", fmt.Errorf("Meta automatic routing is not active")
}

func (o *routingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	out, decision := o.outboundFor(adapter.ContextFrom(ctx), destination)
	if out == nil {
		o.recordDecision(decision, true)
		return nil, errBlockedByMeta
	}
	conn, err := out.DialContext(ctx, network, destination)
	o.recordDecision(decision, err == nil)
	return conn, err
}

func (o *routingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	out, decision := o.outboundFor(adapter.ContextFrom(ctx), destination)
	if out == nil {
		o.recordDecision(decision, true)
		return nil, errBlockedByMeta
	}
	conn, err := out.ListenPacket(ctx, destination)
	o.recordDecision(decision, err == nil)
	return conn, err
}

// Count traffic under the selected node or bypass tag when the route uses the
// Mihomo dispatcher. The embedded tracker also handles unmodified flow routes.
func TrackSelectedOutbound(tracker adapter.ConnectionTracker) adapter.ConnectionTracker {
	return routingTracker{tracker}
}

type routingTracker struct{ adapter.ConnectionTracker }

func (t routingTracker) RoutedConnection(ctx context.Context, conn net.Conn, meta adapter.InboundContext, rule adapter.Rule, next adapter.Outbound) net.Conn {
	if route, ok := next.(*routingOutbound); ok {
		resolved, _ := route.outboundFor(&meta, meta.Destination)
		if resolved != nil {
			next = resolved
		}
	}
	return t.ConnectionTracker.RoutedConnection(ctx, conn, meta, rule, next)
}

func (t routingTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, meta adapter.InboundContext, rule adapter.Rule, next adapter.Outbound) N.PacketConn {
	if route, ok := next.(*routingOutbound); ok {
		resolved, _ := route.outboundFor(&meta, meta.Destination)
		if resolved != nil {
			next = resolved
		}
	}
	return t.ConnectionTracker.RoutedPacketConnection(ctx, conn, meta, rule, next)
}

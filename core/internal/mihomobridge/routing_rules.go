// SPDX-License-Identifier: GPL-3.0-or-later
package mihomobridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	MC "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/provider"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

const (
	RuleSourceMetaCubeX = "metacubex"
	RuleSourceDustinWin = "dustinwin"

	RoutingModeBypassCN = "bypass_cn"
	RoutingModeGFW      = "gfw"

	ruleSource         = "MetaCubeX/meta-rules-dat"
	legacyCacheName    = "mihomo-routing-rules.json"
	maxRuleBytes       = 4 << 20
	maxCacheBytes      = 24 << 20
	updateInterval     = 24 * time.Hour
	retryInterval      = time.Hour
	rateLimitInterval  = 6 * time.Hour
	initialCheckDelay  = 15 * time.Second
)

type routeAction uint8

const (
	actionProxy routeAction = iota
	actionDirect
	actionReject
)

func (a routeAction) String() string {
	switch a {
	case actionDirect:
		return "direct"
	case actionReject:
		return "reject"
	default:
		return "proxy"
	}
}

type matchOptions struct {
	mode     string
	blockAds bool
}

func normalizeRuleSource(id string) string {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case RuleSourceDustinWin:
		return RuleSourceDustinWin
	default:
		return RuleSourceMetaCubeX
	}
}

func normalizeRoutingMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case RoutingModeGFW, "gfw_only":
		return RoutingModeGFW
	default:
		return RoutingModeBypassCN
	}
}

//go:embed rules/*.mrs rules/revision.txt
var bundledRules embed.FS

type ruleFileSpec struct {
	name     string
	source   string
	behavior P.RuleBehavior
	required bool
}

type ruleSourceSpec struct {
	id          string
	repo        string
	branch      string
	cacheName   string
	commitURL   string
	rawBase     string
	files       []ruleFileSpec
}

var metaCubeXSpec = ruleSourceSpec{
	id:        RuleSourceMetaCubeX,
	repo:      "MetaCubeX/meta-rules-dat",
	branch:    "meta",
	cacheName: "mihomo-routing-rules-metacubex.json",
	commitURL: "https://api.github.com/repos/MetaCubeX/meta-rules-dat/commits/meta",
	rawBase:   "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/",
	files: []ruleFileSpec{
		{name: "private-domain.mrs", source: "geo/geosite/private.mrs", behavior: P.Domain, required: true},
		{name: "apple-cn.mrs", source: "geo/geosite/apple-cn.mrs", behavior: P.Domain},
		{name: "microsoft-cn.mrs", source: "geo/geosite/microsoft@cn.mrs", behavior: P.Domain},
		{name: "google-cn.mrs", source: "geo/geosite/google-cn.mrs", behavior: P.Domain},
		{name: "steam-cn.mrs", source: "geo/geosite/steam@cn.mrs", behavior: P.Domain},
		{name: "games-cn.mrs", source: "geo/geosite/category-games@cn.mrs", behavior: P.Domain},
		{name: "bank-cn.mrs", source: "geo/geosite/category-bank-cn.mrs", behavior: P.Domain},
		{name: "cn-domain.mrs", source: "geo/geosite/cn.mrs", behavior: P.Domain, required: true},
		{name: "ai-domain.mrs", source: "geo/geosite/category-ai-!cn.mrs", behavior: P.Domain},
		{name: "gfw-domain.mrs", source: "geo/geosite/gfw.mrs", behavior: P.Domain},
		{name: "outside-cn.mrs", source: "geo/geosite/geolocation-!cn.mrs", behavior: P.Domain, required: true},
		{name: "ads-domain.mrs", source: "geo/geosite/category-ads-all.mrs", behavior: P.Domain},
		{name: "private-ip.mrs", source: "geo/geoip/private.mrs", behavior: P.IPCIDR},
		{name: "cn-ip.mrs", source: "geo/geoip/cn.mrs", behavior: P.IPCIDR, required: true},
		{name: "telegram-ip.mrs", source: "geo/geoip/telegram.mrs", behavior: P.IPCIDR},
		{name: "google-ip.mrs", source: "geo/geoip/google.mrs", behavior: P.IPCIDR},
		{name: "netflix-ip.mrs", source: "geo/geoip/netflix.mrs", behavior: P.IPCIDR},
	},
}

var dustinWinSpec = ruleSourceSpec{
	id:        RuleSourceDustinWin,
	repo:      "DustinWin/ruleset_geodata",
	branch:    "mihomo-ruleset",
	cacheName: "mihomo-routing-rules-dustinwin.json",
	commitURL: "https://api.github.com/repos/DustinWin/ruleset_geodata/commits/mihomo-ruleset",
	rawBase:   "https://raw.githubusercontent.com/DustinWin/ruleset_geodata/",
	files: []ruleFileSpec{
		{name: "private-domain.mrs", source: "private.mrs", behavior: P.Domain, required: true},
		{name: "apple-cn.mrs", source: "apple-cn.mrs", behavior: P.Domain},
		{name: "microsoft-cn.mrs", source: "microsoft-cn.mrs", behavior: P.Domain},
		{name: "google-cn.mrs", source: "google-cn.mrs", behavior: P.Domain},
		{name: "games-cn.mrs", source: "games-cn.mrs", behavior: P.Domain},
		{name: "cn-domain.mrs", source: "cn.mrs", behavior: P.Domain, required: true},
		{name: "ai-domain.mrs", source: "ai.mrs", behavior: P.Domain},
		{name: "gfw-domain.mrs", source: "gfw.mrs", behavior: P.Domain},
		{name: "outside-cn.mrs", source: "proxy.mrs", behavior: P.Domain, required: true},
		{name: "ads-domain.mrs", source: "ads.mrs", behavior: P.Domain},
		{name: "private-ip.mrs", source: "privateip.mrs", behavior: P.IPCIDR},
		{name: "cn-ip.mrs", source: "cnip.mrs", behavior: P.IPCIDR, required: true},
		{name: "telegram-ip.mrs", source: "telegramip.mrs", behavior: P.IPCIDR},
		{name: "google-ip.mrs", source: "mediaip.mrs", behavior: P.IPCIDR},
		{name: "netflix-ip.mrs", source: "netflixip.mrs", behavior: P.IPCIDR},
	},
}

// Keep ruleFiles alias pointing to default MetaCubeX file specs for existing tests.
var ruleFiles = metaCubeXSpec.files

func ruleSpecFor(sourceID string) ruleSourceSpec {
	if normalizeRuleSource(sourceID) == RuleSourceDustinWin {
		return dustinWinSpec
	}
	return metaCubeXSpec
}

type ruleMatcher interface {
	Match(*MC.Metadata, MC.RuleMatchHelper) bool
	FromMrs(io.Reader, int) error
}

const domainMatchCacheLimit = 1024

type domainMatchKey struct {
	host string
	matchOptions
	fakeIP bool
}

type domainMatchResult struct {
	action routeAction
	rule   string
}

type domainMatchCache struct {
	mu      sync.RWMutex
	entries map[domainMatchKey]domainMatchResult
}

func (c *domainMatchCache) store(key domainMatchKey, result domainMatchResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= domainMatchCacheLimit {
		if _, exists := c.entries[key]; exists {
			return
		}
		for victim := range c.entries {
			delete(c.entries, victim)
			break
		}
	}
	c.entries[key] = result
}

type routingPolicy struct {
	domainCache   *domainMatchCache
	sourceID      string
	sourceRepo    string
	ruleSetCount  int
	privateDomain ruleMatcher
	appleCN       ruleMatcher
	microsoftCN   ruleMatcher
	googleCN      ruleMatcher
	steamCN       ruleMatcher
	gamesCN       ruleMatcher
	bankCN        ruleMatcher
	chinaDomain   ruleMatcher
	aiDomain      ruleMatcher
	gfwDomain     ruleMatcher
	outsideChina  ruleMatcher
	adsDomain     ruleMatcher
	privateIP     ruleMatcher
	chinaIP       ruleMatcher
	telegramIP    ruleMatcher
	googleIP      ruleMatcher
	netflixIP     ruleMatcher
	revision      string
	updatedAt     time.Time
	checkedAt     time.Time
}

func matchIfPresent(matcher ruleMatcher, meta *MC.Metadata, helper MC.RuleMatchHelper) bool {
	return matcher != nil && matcher.Match(meta, helper)
}

func (p *routingPolicy) matchDomainAction(host string, opts matchOptions) (routeAction, bool, string) {
	return p.cachedDomainAction(host, opts, false)
}

func (p *routingPolicy) cachedDomainAction(host string, opts matchOptions, fakeIP bool) (routeAction, bool, string) {
	if host == "" {
		return actionProxy, false, ""
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	key := domainMatchKey{host: host, matchOptions: opts, fakeIP: fakeIP}
	cache := p.domainCache
	if cache != nil {
		cache.mu.RLock()
		result, ok := cache.entries[key]
		cache.mu.RUnlock()
		if ok {
			return result.action, true, result.rule
		}
	}
	action, matched, rule := p.matchDomainRules(host, opts)
	if matched && cache != nil {
		cache.store(key, domainMatchResult{action: action, rule: rule})
	}
	return action, matched, rule
}

func (p *routingPolicy) matchDomainRules(host string, opts matchOptions) (routeAction, bool, string) {
	meta := MC.Metadata{Host: host}
	var helper MC.RuleMatchHelper

	// 1. Optional Ad Blocking
	if opts.blockAds && matchIfPresent(p.adsDomain, &meta, helper) {
		return actionReject, true, "GEOSITE,ads"
	}

	// 2. Private / LAN domains
	if matchIfPresent(p.privateDomain, &meta, helper) {
		return actionDirect, true, "GEOSITE,private"
	}

	// 3. Priority CN Direct overrides (placed BEFORE geolocation-!cn so Apple/Microsoft/Steam/Games/Bank CN stay direct)
	switch {
	case matchIfPresent(p.appleCN, &meta, helper):
		return actionDirect, true, "GEOSITE,apple-cn"
	case matchIfPresent(p.microsoftCN, &meta, helper):
		return actionDirect, true, "GEOSITE,microsoft@cn"
	case matchIfPresent(p.googleCN, &meta, helper):
		return actionDirect, true, "GEOSITE,google-cn"
	case matchIfPresent(p.steamCN, &meta, helper):
		return actionDirect, true, "GEOSITE,steam@cn"
	case matchIfPresent(p.gamesCN, &meta, helper):
		return actionDirect, true, "GEOSITE,games@cn"
	case matchIfPresent(p.bankCN, &meta, helper):
		return actionDirect, true, "GEOSITE,bank-cn"
	}

	// 4. Priority Proxy domains (AI & GFW)
	switch {
	case matchIfPresent(p.aiDomain, &meta, helper):
		return actionProxy, true, "GEOSITE,ai"
	case matchIfPresent(p.gfwDomain, &meta, helper):
		return actionProxy, true, "GEOSITE,gfw"
	}

	// 5. General CN vs Outside-CN
	switch {
	case matchIfPresent(p.outsideChina, &meta, helper):
		// If a domain is in BOTH cn and geolocation-!cn (e.g. dual-listed), cn-specific rules above already handled CN CDNs.
		return actionProxy, true, "GEOSITE,geolocation-!cn"
	case matchIfPresent(p.chinaDomain, &meta, helper):
		return actionDirect, true, "GEOSITE,cn"
	default:
		return actionProxy, false, ""
	}
}

// matchDomain preserves backwards-compatible signature for existing tests.
func (p *routingPolicy) matchDomain(host string) (direct bool, matched bool, rule string) {
	action, ok, rule := p.matchDomainAction(host, matchOptions{mode: RoutingModeBypassCN})
	return action == actionDirect, ok, rule
}

func (p *routingPolicy) isDirectIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	meta := MC.Metadata{DstIP: ip}
	var helper MC.RuleMatchHelper
	if matchIfPresent(p.privateIP, &meta, helper) {
		return true
	}
	if matchIfPresent(p.telegramIP, &meta, helper) ||
		matchIfPresent(p.googleIP, &meta, helper) ||
		matchIfPresent(p.netflixIP, &meta, helper) {
		return false
	}
	return matchIfPresent(p.chinaIP, &meta, helper)
}

func (p *routingPolicy) matchAction(meta *MC.Metadata, fakeIP bool, opts matchOptions) (routeAction, string) {
	ip := meta.DstIP
	var helper MC.RuleMatchHelper
	if !fakeIP && ip.IsValid() {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || matchIfPresent(p.privateIP, meta, helper) {
			return actionDirect, "PRIVATE-IP"
		}
	}
	if action, matched, rule := p.cachedDomainAction(meta.Host, opts, fakeIP); matched {
		return action, rule
	}
	if !fakeIP && ip.IsValid() {
		switch {
		case matchIfPresent(p.telegramIP, meta, helper):
			return actionProxy, "GEOIP,telegram"
		case matchIfPresent(p.googleIP, meta, helper):
			return actionProxy, "GEOIP,google"
		case matchIfPresent(p.netflixIP, meta, helper):
			return actionProxy, "GEOIP,netflix"
		case matchIfPresent(p.chinaIP, meta, helper):
			return actionDirect, "GEOIP,cn"
		}
	}
	if normalizeRoutingMode(opts.mode) == RoutingModeGFW {
		return actionDirect, "MATCH-GFW"
	}
	return actionProxy, "MATCH"
}

// match preserves backwards-compatible signature for existing tests.
func (p *routingPolicy) match(meta *MC.Metadata, fakeIP bool) (bool, string) {
	action, rule := p.matchAction(meta, fakeIP, matchOptions{mode: RoutingModeBypassCN})
	return action == actionDirect, rule
}

// Read the MRS envelope and use Mihomo's strategies for the actual rule data.
func readMRS(data []byte, behavior P.RuleBehavior) (ruleMatcher, error) {
	if len(data) == 0 || len(data) > maxRuleBytes {
		return nil, fmt.Errorf("invalid MRS size")
	}
	reader, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderMaxMemory(32<<20))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var header struct {
		Magic      [4]byte
		Behavior   byte
		Count      int64
		ExtraBytes int64
	}
	if err = binary.Read(reader, binary.BigEndian, &header); err != nil {
		return nil, err
	}
	if header.Magic != provider.MrsMagicBytes || header.Behavior != behavior.Byte() ||
		header.Count <= 0 || header.Count > 2_000_000 || header.ExtraBytes < 0 || header.ExtraBytes > 65536 {
		return nil, fmt.Errorf("invalid MRS header")
	}
	if _, err = io.CopyN(io.Discard, reader, header.ExtraBytes); err != nil {
		return nil, err
	}
	var matcher ruleMatcher = provider.NewDomainStrategy()
	if behavior == P.IPCIDR {
		matcher = provider.NewIPCidrStrategy()
	}
	if err = matcher.FromMrs(reader, int(header.Count)); err != nil {
		return nil, err
	}
	return matcher, nil
}

type ruleSnapshot struct {
	SourceID   string            `json:"source_id,omitempty"`
	SourceRepo string            `json:"source_repo,omitempty"`
	Revision   string            `json:"revision"`
	UpdatedAt  int64             `json:"updated_at,omitempty"`
	Files      map[string][]byte `json:"files"`
}

func (s ruleSnapshot) policy() (*routingPolicy, error) {
	revision, err := hex.DecodeString(s.Revision)
	if err != nil || len(revision) != 20 {
		return nil, fmt.Errorf("invalid rule revision")
	}
	spec := ruleSpecFor(s.SourceID)
	repo := s.SourceRepo
	if repo == "" {
		repo = spec.repo
	}

	parsed := make(map[string]ruleMatcher, len(spec.files))
	loadedCount := 0
	for _, rule := range spec.files {
		raw := s.Files[rule.name]
		if len(raw) == 0 {
			if rule.required {
				return nil, fmt.Errorf("%s: missing required rule file", rule.name)
			}
			continue
		}
		matcher, err := readMRS(raw, rule.behavior)
		if err != nil {
			if rule.required {
				return nil, fmt.Errorf("%s: %w", rule.name, err)
			}
			continue
		}
		parsed[rule.name] = matcher
		loadedCount++
	}
	policy := &routingPolicy{
		domainCache:   &domainMatchCache{entries: make(map[domainMatchKey]domainMatchResult)},
		sourceID:      spec.id,
		sourceRepo:    repo,
		ruleSetCount:  loadedCount,
		privateDomain: parsed["private-domain.mrs"],
		appleCN:       parsed["apple-cn.mrs"],
		microsoftCN:   parsed["microsoft-cn.mrs"],
		googleCN:      parsed["google-cn.mrs"],
		steamCN:       parsed["steam-cn.mrs"],
		gamesCN:       parsed["games-cn.mrs"],
		bankCN:        parsed["bank-cn.mrs"],
		chinaDomain:   parsed["cn-domain.mrs"],
		aiDomain:      parsed["ai-domain.mrs"],
		gfwDomain:     parsed["gfw-domain.mrs"],
		outsideChina:  parsed["outside-cn.mrs"],
		adsDomain:     parsed["ads-domain.mrs"],
		privateIP:     parsed["private-ip.mrs"],
		chinaIP:       parsed["cn-ip.mrs"],
		telegramIP:    parsed["telegram-ip.mrs"],
		googleIP:      parsed["google-ip.mrs"],
		netflixIP:     parsed["netflix-ip.mrs"],
		revision:      s.Revision,
	}
	if s.UpdatedAt > 0 {
		policy.updatedAt = time.UnixMilli(s.UpdatedAt)
	}
	return policy, nil
}

func bundledSnapshot() (ruleSnapshot, error) {
	revision, err := bundledRules.ReadFile("rules/revision.txt")
	if err != nil {
		return ruleSnapshot{}, err
	}
	snapshot := ruleSnapshot{
		SourceID:   metaCubeXSpec.id,
		SourceRepo: metaCubeXSpec.repo,
		Revision:   strings.TrimSpace(string(revision)),
		Files:      make(map[string][]byte, len(metaCubeXSpec.files)),
	}
	for _, rule := range metaCubeXSpec.files {
		data, err := bundledRules.ReadFile("rules/" + rule.name)
		if err != nil {
			if rule.required {
				return ruleSnapshot{}, err
			}
			continue
		}
		snapshot.Files[rule.name] = data
	}
	return snapshot, nil
}

var bundledPolicy = sync.OnceValues(func() (*routingPolicy, error) {
	snapshot, err := bundledSnapshot()
	if err != nil {
		return nil, err
	}
	return snapshot.policy()
})

func cacheFilePath(directory, sourceID string) string {
	if directory == "" {
		return ""
	}
	return filepath.Join(directory, ruleSpecFor(sourceID).cacheName)
}

func (o *routingOutbound) cacheFile() string {
	if dir, _ := o.ctx.Value(cacheKey{}).(string); dir != "" {
		return cacheFilePath(dir, o.sourceID)
	}
	return ""
}

func readRuleCache(path string) (*routingPolicy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var snapshot ruleSnapshot
	if err = json.NewDecoder(io.LimitReader(file, maxCacheBytes)).Decode(&snapshot); err != nil {
		return nil, err
	}
	policy, err := snapshot.policy()
	if err != nil {
		return nil, err
	}
	if stat, err := file.Stat(); err == nil {
		policy.checkedAt = stat.ModTime()
	}
	return policy, nil
}

func readCachedPolicyForSource(directory, sourceID string) (*routingPolicy, error) {
	if directory == "" {
		return nil, os.ErrNotExist
	}
	if policy, err := readRuleCache(cacheFilePath(directory, sourceID)); err == nil {
		return policy, nil
	}
	// Backwards-compatible fallback to v1.5.3 legacy filename for MetaCubeX.
	if normalizeRuleSource(sourceID) == RuleSourceMetaCubeX {
		if policy, err := readRuleCache(filepath.Join(directory, legacyCacheName)); err == nil {
			// Only reuse legacy cache if it already has the upgraded rules; otherwise bundled is newer.
			if policy.ruleSetCount >= len(metaCubeXSpec.files)-2 {
				return policy, nil
			}
		}
	}
	return nil, os.ErrNotExist
}

func fetchRules(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Nekobox-Next")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rule download: %s", res.Status)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		return nil, fmt.Errorf("rule download exceeds size limit")
	}
	return data, err
}

// updateRuleCacheForSpec returns a new policy only when the upstream revision changes
// (or when forceDownload is true and no full cache exists for this source).
func updateRuleCacheForSpec(
	ctx context.Context,
	client *http.Client,
	path string,
	spec ruleSourceSpec,
	revisionURL, rawBase, currentRevision string,
	forceDownload bool,
) (*routingPolicy, error) {
	body, err := fetchRules(ctx, client, revisionURL, 1<<20)
	if err != nil {
		return nil, err
	}
	var revision struct{ SHA string }
	if err = json.Unmarshal(body, &revision); err != nil {
		return nil, err
	}
	hash, err := hex.DecodeString(revision.SHA)
	if err != nil || len(hash) != 20 {
		return nil, fmt.Errorf("invalid upstream rule revision")
	}
	if !forceDownload && revision.SHA == currentRevision {
		now := time.Now()
		if err := os.Chtimes(path, now, now); err != nil && os.IsNotExist(err) {
			if spec.id == RuleSourceMetaCubeX {
				if snapshot, snapErr := bundledSnapshot(); snapErr == nil && snapshot.Revision == currentRevision {
					_ = saveRuleCache(path, snapshot)
				}
			}
		}
		return nil, nil
	}
	snapshot := ruleSnapshot{
		SourceID:   spec.id,
		SourceRepo: spec.repo,
		Revision:   revision.SHA,
		Files:      make(map[string][]byte, len(spec.files)),
	}
	for _, rule := range spec.files {
		data, err := fetchRules(ctx, client, rawBase+revision.SHA+"/"+rule.source, maxRuleBytes)
		if err != nil {
			if rule.required {
				return nil, fmt.Errorf("%s: %w", rule.name, err)
			}
			continue
		}
		snapshot.Files[rule.name] = data
	}
	snapshot.UpdatedAt = time.Now().UnixMilli()
	policy, err := snapshot.policy()
	if err != nil {
		return nil, err
	}
	if err = saveRuleCache(path, snapshot); err != nil {
		return nil, err
	}
	policy.checkedAt = policy.updatedAt
	return policy, nil
}

// updateRuleCache preserves backwards-compatible helper signature for existing tests.
func updateRuleCache(ctx context.Context, client *http.Client, path, revisionURL, rawBase, currentRevision string) (*routingPolicy, error) {
	return updateRuleCacheForSpec(ctx, client, path, metaCubeXSpec, revisionURL, rawBase, currentRevision, false)
}

func saveRuleCache(path string, snapshot ruleSnapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mihomo-rules-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	writeErr := json.NewEncoder(tmp).Encode(snapshot)
	closeErr := tmp.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), path)
}

func (o *routingOutbound) buildRefreshClient() (*http.Client, func()) {
	var tlsConfig *tls.Config
	if pool := adapter.RootPoolFromContext(o.ctx); pool != nil {
		tlsConfig = &tls.Config{RootCAs: pool}
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return o.proxy.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 12 * time.Second,
		IdleConnTimeout:     15 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 45 * time.Second}, transport.CloseIdleConnections
}

func (o *routingOutbound) runRefreshOnce(ctx context.Context, file string, manual bool) (*routingPolicy, error) {
	o.refreshMu.Lock()
	defer o.refreshMu.Unlock()

	spec := ruleSpecFor(o.sourceID)
	current := o.policy.Load()
	currentRev := ""
	needInitialSourceFetch := false
	if current != nil {
		if current.sourceID == spec.id {
			currentRev = current.revision
		} else {
			// Currently running on bundled MetaCubeX fallback while user selected another source (e.g. DustinWin).
			needInitialSourceFetch = true
		}
	}

	client, cleanup := o.buildRefreshClient()
	defer cleanup()

	policy, err := updateRuleCacheForSpec(
		ctx,
		client,
		file,
		spec,
		spec.commitURL,
		spec.rawBase,
		currentRev,
		needInitialSourceFetch,
	)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		o.policy.Store(policy)
		o.clearRouteProbeCache()
		o.logger.InfoContext(ctx, "Mihomo rule cache updated (", spec.repo, " @ ", policy.revision[:12], ", ", policy.ruleSetCount, " sets)")
		return policy, nil
	}
	if current != nil {
		refreshed := *current
		refreshed.checkedAt = time.Now()
		o.policy.Store(&refreshed)
		return &refreshed, nil
	}
	return nil, nil
}

func (o *routingOutbound) refreshRules(ctx context.Context, file string) {
	current := o.policy.Load()
	spec := ruleSpecFor(o.sourceID)
	delay := initialCheckDelay
	if current != nil && current.sourceID == spec.id && !current.checkedAt.IsZero() {
		delay = max(min(time.Until(current.checkedAt.Add(updateInterval)), updateInterval), initialCheckDelay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		_, err := o.runRefreshOnce(ctx, file, false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			o.logger.WarnContext(ctx, "Mihomo rule refresh: ", err)
			msg := err.Error()
			if strings.Contains(msg, "403") || strings.Contains(msg, "429") {
				timer.Reset(rateLimitInterval)
			} else {
				timer.Reset(retryInterval)
			}
			continue
		}
		timer.Reset(updateInterval)
	}
}

// RefreshCachedRules downloads the latest rules for sourceID when VPN is disconnected
// (trying local SOCKS5 if available, falling back to direct HTTPS) and returns status JSON.
func RefreshCachedRules(directory, sourceID string, socksPort int, rootCAs *x509.CertPool) (string, error) {
	if directory == "" {
		return "", fmt.Errorf("rule cache directory is unavailable")
	}
	spec := ruleSpecFor(sourceID)
	path := cacheFilePath(directory, spec.id)

	currentRev := ""
	needFetch := false
	if cached, err := readCachedPolicyForSource(directory, spec.id); err == nil {
		currentRev = cached.revision
	} else if spec.id == RuleSourceMetaCubeX {
		if bundled, err := bundledPolicy(); err == nil {
			currentRev = bundled.revision
		}
	} else {
		needFetch = true
	}

	dialer := &net.Dialer{Timeout: 12 * time.Second}
	var tlsConfig *tls.Config
	if rootCAs != nil {
		tlsConfig = &tls.Config{RootCAs: rootCAs}
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if socksPort > 0 {
				if socksConn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(socksPort)); err == nil {
					if _, err = socks.ClientHandshake5(socksConn, socks5.CommandConnect, M.ParseSocksaddr(addr), "", ""); err == nil {
						return socksConn, nil
					}
					_ = socksConn.Close()
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 12 * time.Second,
		DisableKeepAlives:   true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 45 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	policy, err := updateRuleCacheForSpec(ctx, client, path, spec, spec.commitURL, spec.rawBase, currentRev, needFetch)
	if err != nil {
		return "", err
	}
	if policy != nil {
		return policy.status(nil, matchOptions{mode: RoutingModeBypassCN}), nil
	}
	return CachedRoutingStatusForSource(directory, spec.id), nil
}

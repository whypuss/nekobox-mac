// SPDX-License-Identifier: GPL-3.0-or-later
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Profile represents a proxy node in Nekobox-Mac, covering all protocols supported
// by the sing-box + Xray-core + Mihomo tri-core engine.
type Profile struct {
	ID      int64  `json:"id"`
	GroupID int64  `json:"groupId"`
	Name    string `json:"name"`
	Type    string `json:"type"` // vless, vmess, trojan, trojan-go, shadowsocks, ssr, hysteria2, hysteria, tuic, anytls, wireguard, amneziawg, masque, mieru, snell, trusttunnel, sudoku, shadowquic, socks, http, ssh, naive, shadowtls, xray, mihomo, custom, full-config
	Core    string `json:"core"` // auto, sing-box, xray, mihomo

	Address string `json:"address"`
	Port    int    `json:"port"`

	// Protocol-specific fields stored flexibly to preserve 100% of fields across edits
	Params map[string]any `json:"params,omitempty"`

	// Raw outbound / full config overrides
	RawOutbound      map[string]any `json:"rawOutbound,omitempty"`
	CustomOutbound   string         `json:"customOutbound,omitempty"`
	CustomFullConfig string         `json:"customFullConfig,omitempty"`
	ShareURI         string         `json:"shareUri,omitempty"`

	// Runtime / persisted telemetry
	LatencyMs int   `json:"latencyMs"` // 0 = untested, >0 = ms, -1 = error
	LastError string `json:"lastError,omitempty"`
	TxBytes   int64 `json:"txBytes"`
	RxBytes   int64 `json:"rxBytes"`
	Order     int   `json:"order"`
	UpdatedAt int64 `json:"updatedAt"`
}

// Group represents either a local group or a remote subscription group.
type Group struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	IsDefault     bool   `json:"isDefault"`
	Type          string `json:"type"` // basic, subscription
	Order         int    `json:"order"`
	FrontProxyID  int64  `json:"frontProxyId,omitempty"`
	LandingProxyID int64 `json:"landingProxyId,omitempty"`

	// Subscription metadata
	SubscriptionURL      string `json:"subscriptionUrl,omitempty"`
	UserAgent            string `json:"userAgent,omitempty"`
	AutoUpdate           bool   `json:"autoUpdate,omitempty"`
	AutoUpdateInterval   int    `json:"autoUpdateInterval,omitempty"` // minutes
	Deduplication        bool   `json:"deduplication,omitempty"`
	LastUpdated          int64  `json:"lastUpdated,omitempty"`
	SubscriptionUserInfo string `json:"subscriptionUserInfo,omitempty"`
	UploadBytes          int64  `json:"uploadBytes,omitempty"`
	DownloadBytes        int64  `json:"downloadBytes,omitempty"`
	TotalBytes           int64  `json:"totalBytes,omitempty"`
	ExpireTimestamp      int64  `json:"expireTimestamp,omitempty"`
}

// RouteRule represents a custom routing rule (#1 highest priority).
type RouteRule struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Domains     string `json:"domains,omitempty"`     // newline/comma separated: domain, full:, domain:, keyword:, regexp:, geosite:
	IPs         string `json:"ips,omitempty"`         // newline/comma separated: CIDR, geoip:
	Ports       string `json:"ports,omitempty"`       // e.g. 80,443,1000:2000
	Network     string `json:"network,omitempty"`     // "", "tcp", "udp"
	Protocol    string `json:"protocol,omitempty"`    // sniffed protocol: http, tls, quic, dns, bittorrent
	ProcessName string `json:"processName,omitempty"` // macOS executable name(s)
	Outbound    string `json:"outbound"`              // proxy, direct, block, or profile:<id>
	Order       int    `json:"order"`
}

// AppProxyConfig holds macOS per-app routing & Meta smart routing preferences.
type AppProxyConfig struct {
	Scope           string            `json:"scope"`           // smart (all apps), include (only selected)
	AppActions      map[string]string `json:"appActions"`      // bundleId -> "default" | "bypass" | "force_proxy"
	AppProcessMap   map[string]string `json:"appProcessMap"`   // bundleId -> executable process name
	MetaAutoRouting bool              `json:"metaAutoRouting"` // default true
	MetaRuleSource  string            `json:"metaRuleSource"`  // metacubex | dustinwin
	MetaRoutingMode string            `json:"metaRoutingMode"` // bypass_cn | gfw_only
	MetaBlockAds    bool              `json:"metaBlockAds"`
}

// PowerSaverConfig mirrors Nekobox-Next's Power Saver page adapted for macOS.
type PowerSaverConfig struct {
	MixedTunStack    bool `json:"mixedTunStack"`    // true = mixed stack (kernel TCP + gVisor UDP), false = gvisor
	SmartFindProcess bool `json:"smartFindProcess"` // on-demand process lookup
	PauseOnHidden    bool `json:"pauseOnHidden"`    // pause foreground traffic polling when window hidden/locked
	SleepCoreOnIdle  bool `json:"sleepCoreOnIdle"`  // call box.Sleep() on macOS system sleep, Wake() on wake
}

// Settings holds all user preferences, matching Nekobox-Next 1:1.
type Settings struct {
	// General & UI
	ClassicUI             bool   `json:"classicUi"`             // false = Liquid Glass 3.0, true = 1:1 Classic
	AppTheme              int    `json:"appTheme"`              // 1..21, default 2 (PINK_SSR #fb7299)
	NightMode             string `json:"nightMode"`             // system, dark, light
	Language              string `json:"language"`              // auto, zh-CN, zh-TW, en
	ShowAllGroup          bool   `json:"showAllGroup"`          // default true
	AutoConnect           bool   `json:"autoConnect"`           // connect on launch
	LaunchAtLogin         bool   `json:"launchAtLogin"`         // macOS LaunchAgent
	HideDockIcon          bool   `json:"hideDockIcon"`          // menu bar only
	AutoCheckUpdates      bool   `json:"autoCheckUpdates"`      // default true
	IgnoredUpdateVersion  string `json:"ignoredUpdateVersion,omitempty"`

	// Liquid Glass 3.0 Motion & Visual Intensity (0..5)
	LiquidJellyLevel   int  `json:"liquidJellyLevel"`   // default 1
	LiquidBlurLevel    int  `json:"liquidBlurLevel"`    // default 3
	LiquidAmbientLevel int  `json:"liquidAmbientLevel"` // default 1
	LiquidScrollLevel  int  `json:"liquidScrollLevel"`  // default 1
	LiquidHaptics      bool `json:"liquidHaptics"`      // default true

	// Service Mode & macOS Proxy
	ServiceMode        string `json:"serviceMode"`        // system_proxy, tun, mixed_only
	AutoSetSystemProxy bool   `json:"autoSetSystemProxy"` // auto configure macOS networksetup on connect
	MixedPort          int    `json:"mixedPort"`          // default 2080
	AllowLAN           bool   `json:"allowLan"`           // bind 0.0.0.0 instead of 127.0.0.1
	MTU                int    `json:"mtu"`                // default 9000 for macOS utun

	// Routing & DNS
	IPv6Mode               string `json:"ipv6Mode"`               // disable, enable, prefer, only (default enable)
	TrafficSniffing        int    `json:"trafficSniffing"`        // 0=off, 1=sniff, 2=sniff+override
	ResolveDestination     bool   `json:"resolveDestination"`
	RemoteDNS              string `json:"remoteDns"`              // default https://dns.google/dns-query
	DirectDNS              string `json:"directDns"`              // default https://223.5.5.5/dns-query
	DomainStrategyDirect   string `json:"domainStrategyDirect"`   // auto, prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only
	DomainStrategyServer   string `json:"domainStrategyServer"`
	EnableDNSRouting       bool   `json:"enableDnsRouting"`       // default true
	EnableFakeDNS          bool   `json:"enableFakeDns"`          // default true

	// Misc & Diagnostics
	ConnectionTestURL        string `json:"connectionTestUrl"`        // default http://cp.cloudflare.com/
	ConnectionTestConcurrent int    `json:"connectionTestConcurrent"` // 1,3,5,8,12,16 (default 5)
	EnableClashAPI           bool   `json:"enableClashApi"`           // default true
	ClashAPIPort             int    `json:"clashApiPort"`             // default 9090
	DashboardURL             string `json:"dashboardUrl"`             // default /ui/
	LogLevel                 string `json:"logLevel"`                 // panic, warn, info, debug, trace
	GlobalAllowInsecure      bool   `json:"globalAllowInsecure"`
	AllowInsecureOnRequest   bool   `json:"allowInsecureOnRequest"`
	NetworkChangeReset       bool   `json:"networkChangeReset"`
	WakeResetConnections     bool   `json:"wakeResetConnections"`
	StunServer               string `json:"stunServer"`               // default stun.voipgate.com:3478
}

// State is the full persisted snapshot stored in state.json.
type State struct {
	Version         int              `json:"version"`
	SelectedProfile int64            `json:"selectedProfile"`
	SelectedGroup   int64            `json:"selectedGroup"` // 0 = All
	NextID          int64            `json:"nextId"`
	Groups          []Group          `json:"groups"`
	Profiles        []Profile        `json:"profiles"`
	Rules           []RouteRule      `json:"rules"`
	AppProxy        AppProxyConfig   `json:"appProxy"`
	PowerSaver      PowerSaverConfig `json:"powerSaver"`
	Settings        Settings         `json:"settings"`
}

// BackupPayload supports selective export/import matching Nekobox-Next BackupFragment.
type BackupPayload struct {
	Format      string            `json:"format"`
	ExportedAt  int64             `json:"exportedAt"`
	Groups      []Group           `json:"groups,omitempty"`
	Profiles    []Profile         `json:"profiles,omitempty"`
	Rules       []RouteRule       `json:"rules,omitempty"`
	AppProxy    *AppProxyConfig   `json:"appProxy,omitempty"`
	PowerSaver  *PowerSaverConfig `json:"powerSaver,omitempty"`
	Settings    *Settings         `json:"settings,omitempty"`
}

func DefaultSettings() Settings {
	return Settings{
		ClassicUI:                false,
		AppTheme:                 2, // PINK_SSR (#fb7299)
		NightMode:                "system",
		Language:                 "auto",
		ShowAllGroup:             true,
		AutoConnect:              false,
		LaunchAtLogin:            false,
		HideDockIcon:             false,
		AutoCheckUpdates:         true,
		LiquidJellyLevel:         1,
		LiquidBlurLevel:          3,
		LiquidAmbientLevel:       1,
		LiquidScrollLevel:        1,
		LiquidHaptics:            true,
		ServiceMode:              "system_proxy",
		AutoSetSystemProxy:       true,
		MixedPort:                2080,
		AllowLAN:                 false,
		MTU:                      9000,
		IPv6Mode:                 "enable",
		TrafficSniffing:          1,
		ResolveDestination:       false,
		RemoteDNS:                "https://dns.google/dns-query",
		DirectDNS:                "https://223.5.5.5/dns-query",
		DomainStrategyDirect:     "auto",
		DomainStrategyServer:     "auto",
		EnableDNSRouting:         true,
		EnableFakeDNS:            true,
		ConnectionTestURL:        "http://cp.cloudflare.com/",
		ConnectionTestConcurrent: 5,
		EnableClashAPI:           true,
		ClashAPIPort:             9090,
		DashboardURL:             "/ui/",
		LogLevel:                 "info",
		GlobalAllowInsecure:      false,
		AllowInsecureOnRequest:   false,
		NetworkChangeReset:       true,
		WakeResetConnections:     false,
		StunServer:               "stun.voipgate.com:3478",
	}
}

func DefaultAppProxy() AppProxyConfig {
	return AppProxyConfig{
		Scope:           "smart",
		AppActions:      map[string]string{},
		AppProcessMap:   map[string]string{},
		MetaAutoRouting: true,
		MetaRuleSource:  "metacubex",
		MetaRoutingMode: "bypass_cn",
		MetaBlockAds:    false,
	}
}

func DefaultPowerSaver() PowerSaverConfig {
	return PowerSaverConfig{
		MixedTunStack:    true,
		SmartFindProcess: true,
		PauseOnHidden:    true,
		SleepCoreOnIdle:  true,
	}
}

func DefaultState() State {
	return State{
		Version:       1,
		SelectedGroup: 0,
		NextID:        100,
		Groups: []Group{
			{
				ID:        1,
				Name:      "默认",
				IsDefault: true,
				Type:      "basic",
				Order:     0,
			},
		},
		Profiles:   []Profile{},
		Rules:      []RouteRule{},
		AppProxy:   DefaultAppProxy(),
		PowerSaver: DefaultPowerSaver(),
		Settings:   DefaultSettings(),
	}
}

type Store struct {
	mu       sync.RWMutex
	filePath string
	state    State
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	fp := filepath.Join(dataDir, "state.json")
	s := &Store{
		filePath: fp,
		state:    DefaultState(),
	}
	if data, err := os.ReadFile(fp); err == nil && len(data) > 0 {
		var loaded State
		if err := json.Unmarshal(data, &loaded); err == nil {
			s.state = mergeDefaults(loaded)
		}
	}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func mergeDefaults(st State) State {
	def := DefaultState()
	if st.NextID < 100 {
		st.NextID = 100
	}
	if len(st.Groups) == 0 {
		st.Groups = def.Groups
	}
	hasDefault := false
	for _, g := range st.Groups {
		if g.IsDefault || g.ID == 1 {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		st.Groups = append([]Group{def.Groups[0]}, st.Groups...)
	}
	if st.Profiles == nil {
		st.Profiles = []Profile{}
	}
	if st.Rules == nil {
		st.Rules = []RouteRule{}
	}
	if st.AppProxy.AppActions == nil {
		st.AppProxy.AppActions = map[string]string{}
	}
	if st.AppProxy.AppProcessMap == nil {
		st.AppProxy.AppProcessMap = map[string]string{}
	}
	if st.AppProxy.Scope == "" {
		st.AppProxy.Scope = "smart"
	}
	if st.AppProxy.MetaRuleSource == "" {
		st.AppProxy.MetaRuleSource = "metacubex"
	}
	if st.AppProxy.MetaRoutingMode == "" {
		st.AppProxy.MetaRoutingMode = "bypass_cn"
	}
	if st.Settings.AppTheme < 1 || st.Settings.AppTheme > 21 {
		st.Settings.AppTheme = 2
	}
	if st.Settings.NightMode == "" {
		st.Settings.NightMode = "system"
	}
	if st.Settings.ServiceMode == "" {
		st.Settings.ServiceMode = "system_proxy"
	}
	if st.Settings.MixedPort <= 0 {
		st.Settings.MixedPort = 2080
	}
	if st.Settings.MTU <= 0 {
		st.Settings.MTU = 9000
	}
	if st.Settings.IPv6Mode == "" {
		st.Settings.IPv6Mode = "enable"
	}
	if st.Settings.RemoteDNS == "" {
		st.Settings.RemoteDNS = "https://dns.google/dns-query"
	}
	if st.Settings.DirectDNS == "" {
		st.Settings.DirectDNS = "https://223.5.5.5/dns-query"
	}
	if st.Settings.ConnectionTestURL == "" {
		st.Settings.ConnectionTestURL = "http://cp.cloudflare.com/"
	}
	if st.Settings.ConnectionTestConcurrent <= 0 {
		st.Settings.ConnectionTestConcurrent = 5
	}
	if st.Settings.ClashAPIPort <= 0 {
		st.Settings.ClashAPIPort = 9090
	}
	if st.Settings.DashboardURL == "" {
		st.Settings.DashboardURL = "/ui/"
	}
	if st.Settings.LogLevel == "" {
		st.Settings.LogLevel = "info"
	}
	if st.Settings.StunServer == "" {
		st.Settings.StunServer = "stun.voipgate.com:3478"
	}
	return st
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, _ := json.Marshal(s.state)
	var cp State
	_ = json.Unmarshal(raw, &cp)
	return cp
}

func (s *Store) nextIDLocked() int64 {
	s.state.NextID++
	return s.state.NextID
}

func (s *Store) GetProfile(id int64) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.state.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

func (s *Store) AddProfiles(groupID int64, list []Profile) ([]Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if groupID <= 0 {
		groupID = s.defaultGroupIDLocked()
	}
	now := time.Now().UnixMilli()
	maxOrder := 0
	for _, p := range s.state.Profiles {
		if p.GroupID == groupID && p.Order > maxOrder {
			maxOrder = p.Order
		}
	}
	added := make([]Profile, 0, len(list))
	for _, p := range list {
		p.ID = s.nextIDLocked()
		p.GroupID = groupID
		maxOrder++
		p.Order = maxOrder
		p.UpdatedAt = now
		if p.Core == "" {
			p.Core = "auto"
		}
		if p.Params == nil {
			p.Params = map[string]any{}
		}
		s.state.Profiles = append(s.state.Profiles, p)
		added = append(added, p)
	}
	if s.state.SelectedProfile == 0 && len(added) > 0 {
		s.state.SelectedProfile = added[0].ID
	}
	return added, s.saveLocked()
}

func (s *Store) UpdateProfile(p Profile) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Profiles {
		if s.state.Profiles[i].ID == p.ID {
			p.UpdatedAt = time.Now().UnixMilli()
			if p.GroupID <= 0 {
				p.GroupID = s.state.Profiles[i].GroupID
			}
			if p.Core == "" {
				p.Core = "auto"
			}
			s.state.Profiles[i] = p
			return p, s.saveLocked()
		}
	}
	return Profile{}, errors.New("profile not found")
}

func (s *Store) DeleteProfile(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, p := range s.state.Profiles {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.New("profile not found")
	}
	s.state.Profiles = slices.Delete(s.state.Profiles, idx, idx+1)
	if s.state.SelectedProfile == id {
		if len(s.state.Profiles) > 0 {
			s.state.SelectedProfile = s.state.Profiles[0].ID
		} else {
			s.state.SelectedProfile = 0
		}
	}
	return s.saveLocked()
}

func (s *Store) DeleteProfilesByFilter(groupID int64, mode string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]Profile, 0, len(s.state.Profiles))
	seen := map[string]bool{}
	removed := 0
	for _, p := range s.state.Profiles {
		inScope := groupID == 0 || p.GroupID == groupID
		if !inScope {
			kept = append(kept, p)
			continue
		}
		switch mode {
		case "unavailable":
			if p.LatencyMs < 0 {
				removed++
				continue
			}
		case "duplicates":
			key := fmt.Sprintf("%s|%s|%d|%v", p.Type, p.Address, p.Port, p.Name)
			if seen[key] {
				removed++
				continue
			}
			seen[key] = true
		case "all":
			removed++
			continue
		}
		kept = append(kept, p)
	}
	s.state.Profiles = kept
	stillExists := false
	for _, p := range kept {
		if p.ID == s.state.SelectedProfile {
			stillExists = true
			break
		}
	}
	if !stillExists {
		if len(kept) > 0 {
			s.state.SelectedProfile = kept[0].ID
		} else {
			s.state.SelectedProfile = 0
		}
	}
	return removed, s.saveLocked()
}

func (s *Store) SelectProfile(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.state.Profiles {
		if p.ID == id {
			s.state.SelectedProfile = id
			return s.saveLocked()
		}
	}
	return errors.New("profile not found")
}

func (s *Store) SetProfileLatency(id int64, ms int, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Profiles {
		if s.state.Profiles[i].ID == id {
			s.state.Profiles[i].LatencyMs = ms
			s.state.Profiles[i].LastError = lastErr
			_ = s.saveLocked()
			return
		}
	}
}

func (s *Store) AddProfileTraffic(id int64, txDelta, rxDelta int64) {
	if id <= 0 || (txDelta == 0 && rxDelta == 0) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Profiles {
		if s.state.Profiles[i].ID == id {
			s.state.Profiles[i].TxBytes += txDelta
			s.state.Profiles[i].RxBytes += rxDelta
			return
		}
	}
}

func (s *Store) ClearTraffic(groupID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Profiles {
		if groupID == 0 || s.state.Profiles[i].GroupID == groupID {
			s.state.Profiles[i].TxBytes = 0
			s.state.Profiles[i].RxBytes = 0
			s.state.Profiles[i].LatencyMs = 0
			s.state.Profiles[i].LastError = ""
		}
	}
	return s.saveLocked()
}

func (s *Store) SortProfiles(groupID int64, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var targets []Profile
	var others []Profile
	for _, p := range s.state.Profiles {
		if groupID == 0 || p.GroupID == groupID {
			targets = append(targets, p)
		} else {
			others = append(others, p)
		}
	}
	slices.SortStableFunc(targets, func(a, b Profile) int {
		switch by {
		case "latency":
			la, lb := a.LatencyMs, b.LatencyMs
			if la <= 0 {
				la = 1 << 30
			}
			if lb <= 0 {
				lb = 1 << 30
			}
			if la != lb {
				if la < lb {
					return -1
				}
				return 1
			}
		case "name":
			if a.Name < b.Name {
				return -1
			}
			if a.Name > b.Name {
				return 1
			}
		case "type":
			if a.Type < b.Type {
				return -1
			}
			if a.Type > b.Type {
				return 1
			}
		}
		if a.ID < b.ID {
			return -1
		}
		return 1
	})
	for i := range targets {
		targets[i].Order = i + 1
	}
	s.state.Profiles = append(others, targets...)
	return s.saveLocked()
}

func (s *Store) defaultGroupIDLocked() int64 {
	for _, g := range s.state.Groups {
		if g.IsDefault {
			return g.ID
		}
	}
	if len(s.state.Groups) > 0 {
		return s.state.Groups[0].ID
	}
	return 1
}

func (s *Store) UpsertGroup(g Group) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.Name == "" {
		g.Name = "新分组"
	}
	if g.Type == "" {
		if g.SubscriptionURL != "" {
			g.Type = "subscription"
		} else {
			g.Type = "basic"
		}
	}
	if g.ID == 0 {
		g.ID = s.nextIDLocked()
		g.Order = len(s.state.Groups)
		s.state.Groups = append(s.state.Groups, g)
		return g, s.saveLocked()
	}
	for i := range s.state.Groups {
		if s.state.Groups[i].ID == g.ID {
			g.IsDefault = s.state.Groups[i].IsDefault
			s.state.Groups[i] = g
			return g, s.saveLocked()
		}
	}
	return Group{}, errors.New("group not found")
}

func (s *Store) ReplaceGroupProfiles(groupID int64, profiles []Profile, metaUpdate func(*Group)) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	groupIdx := -1
	for i := range s.state.Groups {
		if s.state.Groups[i].ID == groupID {
			groupIdx = i
			break
		}
	}
	if groupIdx < 0 {
		return 0, errors.New("group not found")
	}

	// Preserve existing profile IDs and custom overrides matched by name
	existingByName := map[string]Profile{}
	kept := make([]Profile, 0, len(s.state.Profiles))
	for _, p := range s.state.Profiles {
		if p.GroupID == groupID {
			existingByName[p.Name] = p
		} else {
			kept = append(kept, p)
		}
	}

	now := time.Now().UnixMilli()
	for i := range profiles {
		profiles[i].GroupID = groupID
		profiles[i].Order = i + 1
		profiles[i].UpdatedAt = now
		if profiles[i].Core == "" {
			profiles[i].Core = "auto"
		}
		if old, ok := existingByName[profiles[i].Name]; ok {
			profiles[i].ID = old.ID
			profiles[i].TxBytes = old.TxBytes
			profiles[i].RxBytes = old.RxBytes
			if profiles[i].CustomOutbound == "" {
				profiles[i].CustomOutbound = old.CustomOutbound
			}
			if profiles[i].CustomFullConfig == "" {
				profiles[i].CustomFullConfig = old.CustomFullConfig
			}
		} else {
			profiles[i].ID = s.nextIDLocked()
		}
	}
	s.state.Profiles = append(kept, profiles...)
	if metaUpdate != nil {
		metaUpdate(&s.state.Groups[groupIdx])
	}
	s.state.Groups[groupIdx].LastUpdated = now
	if s.state.SelectedProfile == 0 && len(profiles) > 0 {
		s.state.SelectedProfile = profiles[0].ID
	}
	return len(profiles), s.saveLocked()
}

func (s *Store) DeleteGroup(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, g := range s.state.Groups {
		if g.ID == id {
			if g.IsDefault {
				return errors.New("cannot delete default group")
			}
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.New("group not found")
	}
	s.state.Groups = slices.Delete(s.state.Groups, idx, idx+1)
	kept := make([]Profile, 0, len(s.state.Profiles))
	for _, p := range s.state.Profiles {
		if p.GroupID != id {
			kept = append(kept, p)
		}
	}
	s.state.Profiles = kept
	if s.state.SelectedGroup == id {
		s.state.SelectedGroup = 0
	}
	return s.saveLocked()
}

func (s *Store) UpsertRule(r RouteRule) (RouteRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Outbound == "" {
		r.Outbound = "proxy"
	}
	if r.ID == 0 {
		r.ID = s.nextIDLocked()
		r.Order = len(s.state.Rules)
		s.state.Rules = append(s.state.Rules, r)
		return r, s.saveLocked()
	}
	for i := range s.state.Rules {
		if s.state.Rules[i].ID == r.ID {
			s.state.Rules[i] = r
			return r, s.saveLocked()
		}
	}
	return RouteRule{}, errors.New("rule not found")
}

func (s *Store) DeleteRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.state.Rules {
		if r.ID == id {
			s.state.Rules = slices.Delete(s.state.Rules, i, i+1)
			return s.saveLocked()
		}
	}
	return errors.New("rule not found")
}

func (s *Store) ReorderRules(ids []int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := map[int64]RouteRule{}
	for _, r := range s.state.Rules {
		byID[r.ID] = r
	}
	reordered := make([]RouteRule, 0, len(s.state.Rules))
	used := map[int64]bool{}
	for idx, id := range ids {
		if r, ok := byID[id]; ok {
			r.Order = idx
			reordered = append(reordered, r)
			used[id] = true
		}
	}
	for _, r := range s.state.Rules {
		if !used[r.ID] {
			r.Order = len(reordered)
			reordered = append(reordered, r)
		}
	}
	s.state.Rules = reordered
	return s.saveLocked()
}

func (s *Store) UpdateAppProxy(cfg AppProxyConfig) (AppProxyConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.AppActions == nil {
		cfg.AppActions = map[string]string{}
	}
	if cfg.AppProcessMap == nil {
		cfg.AppProcessMap = map[string]string{}
	}
	if cfg.Scope == "" {
		cfg.Scope = "smart"
	}
	if cfg.MetaRuleSource == "" {
		cfg.MetaRuleSource = "metacubex"
	}
	if cfg.MetaRoutingMode == "" {
		cfg.MetaRoutingMode = "bypass_cn"
	}
	s.state.AppProxy = cfg
	return cfg, s.saveLocked()
}

func (s *Store) UpdatePowerSaver(cfg PowerSaverConfig) (PowerSaverConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.PowerSaver = cfg
	return cfg, s.saveLocked()
}

func (s *Store) UpdateSettings(st Settings) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Settings = st
	s.state = mergeDefaults(s.state)
	return s.state.Settings, s.saveLocked()
}

func (s *Store) SetSelectedGroup(groupID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.SelectedGroup = groupID
	return s.saveLocked()
}

func (s *Store) ExportBackup(includeProfiles, includeRules, includeSettings bool) BackupPayload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := BackupPayload{
		Format:     "nekobox-mac-backup-v1",
		ExportedAt: time.Now().UnixMilli(),
	}
	if includeProfiles {
		out.Groups = slices.Clone(s.state.Groups)
		out.Profiles = slices.Clone(s.state.Profiles)
	}
	if includeRules {
		out.Rules = slices.Clone(s.state.Rules)
		ap := s.state.AppProxy
		out.AppProxy = &ap
	}
	if includeSettings {
		ps := s.state.PowerSaver
		st := s.state.Settings
		out.PowerSaver = &ps
		out.Settings = &st
	}
	return out
}

func (s *Store) ImportBackup(b BackupPayload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(b.Groups) > 0 {
		s.state.Groups = b.Groups
	}
	if len(b.Profiles) > 0 {
		s.state.Profiles = b.Profiles
		var maxID int64 = s.state.NextID
		for _, g := range s.state.Groups {
			if g.ID > maxID {
				maxID = g.ID
			}
		}
		for _, p := range s.state.Profiles {
			if p.ID > maxID {
				maxID = p.ID
			}
		}
		s.state.NextID = maxID + 10
		if s.state.SelectedProfile == 0 && len(s.state.Profiles) > 0 {
			s.state.SelectedProfile = s.state.Profiles[0].ID
		}
	}
	if b.Rules != nil {
		s.state.Rules = b.Rules
	}
	if b.AppProxy != nil {
		s.state.AppProxy = *b.AppProxy
	}
	if b.PowerSaver != nil {
		s.state.PowerSaver = *b.PowerSaver
	}
	if b.Settings != nil {
		s.state.Settings = *b.Settings
	}
	s.state = mergeDefaults(s.state)
	return s.saveLocked()
}

func (s *Store) ResetSettings() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Settings = DefaultSettings()
	s.state.PowerSaver = DefaultPowerSaver()
	s.state.AppProxy = DefaultAppProxy()
	return s.saveLocked()
}

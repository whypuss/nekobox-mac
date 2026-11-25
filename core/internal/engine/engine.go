// SPDX-License-Identifier: GPL-3.0-or-later
package engine

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing-box/include"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	xray "github.com/xtls/xray-core/core"

	"nekobox-mac/internal/configbuilder"
	"nekobox-mac/internal/device"
	"nekobox-mac/internal/hysteriapin"
	"nekobox-mac/internal/macos"
	"nekobox-mac/internal/mihomobridge"
	"nekobox-mac/internal/parser"
	"nekobox-mac/internal/store"
	"nekobox-mac/internal/stun"
	"nekobox-mac/internal/urltest"
	"nekobox-mac/internal/xraybridge"
)

var AppVersion = "1.6.2-mac"

type State string

const (
	StateStopped    State = "stopped"
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
	StateStopping   State = "stopping"
)

type LogEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type StatusSnapshot struct {
	State          State                   `json:"state"`
	ActiveProfile  int64                   `json:"activeProfile"`
	ActiveName     string                  `json:"activeName"`
	ActiveType     string                  `json:"activeType"`
	ActiveCore     string                  `json:"activeCore"`
	ServiceMode    string                  `json:"serviceMode"`
	MixedPort      int                     `json:"mixedPort"`
	ClashAPIPort   int                     `json:"clashApiPort"`
	ClashAPISecret string                  `json:"clashApiSecret,omitempty"`
	TxRate         int64                   `json:"txRate"`
	RxRate         int64                   `json:"rxRate"`
	TxTotal        int64                   `json:"txTotal"`
	RxTotal        int64                   `json:"rxTotal"`
	LastLatencyMs  int                     `json:"lastLatencyMs"`
	LastError      string                  `json:"lastError,omitempty"`
	StartedAt      int64                   `json:"startedAt,omitempty"`
	SystemProxy    macos.SystemProxyStatus `json:"systemProxy"`
	SystemInfo     macos.SystemInfo        `json:"systemInfo"`
	PausedPolling  bool                    `json:"pausedPolling"`
	CoreSleeping   bool                    `json:"coreSleeping"`
}

type CoreVersions struct {
	App     string `json:"app"`
	SingBox string `json:"singBox"`
	Xray    string `json:"xray"`
	Mihomo  string `json:"mihomo"`
	Go      string `json:"go"`
	Arch    string `json:"arch"`
	OS      string `json:"os"`
}

type Engine struct {
	store     *store.Store
	dataDir   string
	assetsDir string
	yacdDir   string

	opMu            sync.Mutex
	mu              sync.Mutex
	state           State
	box             *box.Box
	boxCancel       context.CancelFunc
	v2api           *v2rayapi.StatsService
	pauseManager    pause.Manager
	activeProfile   int64
	activeName      string
	activeType      string
	activeCore      string
	activeMode      string
	activePort      int
	sysProxyManaged bool
	startedAt       int64
	lastError     string
	lastLatencyMs int
	txRate        int64
	rxRate        int64
	txTotal       int64
	rxTotal       int64
	coreSleeping  bool
	statsStop     chan struct{}
	pausedPolling atomic.Bool

	logMu      sync.RWMutex
	logs       []LogEntry
	nextLogID  int64

	subMu      sync.Mutex
	subs       map[chan StatusSnapshot]struct{}
	logSubs    map[chan LogEntry]struct{}
	rootCAs    *x509.CertPool
}

func New(st *store.Store, dataDir, bundledYacdZip string) (*Engine, error) {
	assetsDir := filepath.Join(dataDir, "assets")
	yacdDir := filepath.Join(dataDir, "yacd")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		return nil, err
	}

	// Register socket dial hooks (no-op on macOS userland; sing-box handles auto_detect_interface)
	mihomobridge.Install(nil)
	_ = xraybridge.Install(nil)

	device.ConfigureBackgroundRuntime()

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	e := &Engine{
		store:     st,
		dataDir:   dataDir,
		assetsDir: assetsDir,
		yacdDir:   yacdDir,
		state:     StateStopped,
		logs:      make([]LogEntry, 0, 512),
		subs:      map[chan StatusSnapshot]struct{}{},
		logSubs:   map[chan LogEntry]struct{}{},
		rootCAs:   pool,
	}

	if bundledYacdZip != "" {
		if err := extractYacdSafe(bundledYacdZip, yacdDir); err != nil {
			e.appendLog("warn", "MetaCubeXD 面板解压跳过: "+err.Error())
		} else {
			e.appendLog("info", "MetaCubeXD Web 面板已就绪")
		}
	}

	e.appendLog("info", fmt.Sprintf("Nekobox-Mac %s 已初始化 (%s / sing-box %s / Xray %s / Mihomo %s)",
		AppVersion, runtime.GOARCH, constant.Version, xray.Version(), mihomobridge.Version()))
	return e, nil
}

func (e *Engine) DataDir() string {
	return e.dataDir
}

func (e *Engine) AssetsDir() string {
	return e.assetsDir
}

func (e *Engine) YacdDir() string {
	return e.yacdDir
}

func (e *Engine) Versions() CoreVersions {
	si := macos.GetSystemInfo()
	return CoreVersions{
		App:     AppVersion,
		SingBox: constant.Version,
		Xray:    xray.Version(),
		Mihomo:  mihomobridge.Version(),
		Go:      runtime.Version(),
		Arch:    si.ChipLabel,
		OS:      si.OSVersion,
	}
}

func (e *Engine) SubscribeStatus() (chan StatusSnapshot, func()) {
	ch := make(chan StatusSnapshot, 16)
	e.subMu.Lock()
	e.subs[ch] = struct{}{}
	e.subMu.Unlock()
	return ch, func() {
		e.subMu.Lock()
		delete(e.subs, ch)
		e.subMu.Unlock()
	}
}

func (e *Engine) SubscribeLogs() (chan LogEntry, func()) {
	ch := make(chan LogEntry, 64)
	e.subMu.Lock()
	e.logSubs[ch] = struct{}{}
	e.subMu.Unlock()
	return ch, func() {
		e.subMu.Lock()
		delete(e.logSubs, ch)
		e.subMu.Unlock()
	}
}

func (e *Engine) broadcastStatus() {
	snap := e.Status()
	e.subMu.Lock()
	for ch := range e.subs {
		select {
		case ch <- snap:
		default:
		}
	}
	e.subMu.Unlock()
}

func (e *Engine) appendLog(level, msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	e.logMu.Lock()
	e.nextLogID++
	entry := LogEntry{
		ID:        e.nextLogID,
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Message:   msg,
	}
	if len(e.logs) >= 1500 {
		copy(e.logs, e.logs[1:])
		e.logs[len(e.logs)-1] = entry
	} else {
		e.logs = append(e.logs, entry)
	}
	e.logMu.Unlock()

	e.subMu.Lock()
	for ch := range e.logSubs {
		select {
		case ch <- entry:
		default:
		}
	}
	e.subMu.Unlock()
}

func (e *Engine) Logs() []LogEntry {
	e.logMu.RLock()
	defer e.logMu.RUnlock()
	cp := make([]LogEntry, len(e.logs))
	copy(cp, e.logs)
	return cp
}

func (e *Engine) ClearLogs() {
	e.logMu.Lock()
	e.logs = e.logs[:0]
	e.logMu.Unlock()
}

func (e *Engine) Status() StatusSnapshot {
	e.mu.Lock()
	st := e.store.Snapshot()
	snap := StatusSnapshot{
		State:         e.state,
		ActiveProfile: e.activeProfile,
		ActiveName:    e.activeName,
		ActiveType:    e.activeType,
		ActiveCore:    e.activeCore,
		ServiceMode:    e.activeMode,
		MixedPort:      st.Settings.MixedPort,
		ClashAPIPort:   st.Settings.ClashAPIPort,
		ClashAPISecret: st.Settings.ClashAPISecret,
		TxRate:         e.txRate,
		RxRate:        e.rxRate,
		TxTotal:       e.txTotal,
		RxTotal:       e.rxTotal,
		LastLatencyMs: e.lastLatencyMs,
		LastError:     e.lastError,
		StartedAt:     e.startedAt,
		PausedPolling: e.pausedPolling.Load(),
		CoreSleeping:  e.coreSleeping,
	}
	if snap.ServiceMode == "" {
		snap.ServiceMode = st.Settings.ServiceMode
	}
	e.mu.Unlock()
	snap.SystemProxy = macos.GetSystemProxyStatus()
	snap.SystemInfo = macos.GetSystemInfo()
	return snap
}

func (e *Engine) SetPollingPaused(paused bool) {
	e.pausedPolling.Store(paused)
	e.broadcastStatus()
}

func (e *Engine) Sleep() {
	e.mu.Lock()
	pm := e.pauseManager
	allow := e.store.Snapshot().PowerSaver.SleepCoreOnIdle
	if pm != nil && allow {
		pm.DevicePause()
		e.coreSleeping = true
		e.appendLog("info", "系统进入休眠，已暂停核心后台定时器 (box.Sleep)")
	}
	e.mu.Unlock()
	e.broadcastStatus()
}

func (e *Engine) Wake() {
	e.mu.Lock()
	pm := e.pauseManager
	b := e.box
	reset := e.store.Snapshot().Settings.WakeResetConnections
	if pm != nil && e.coreSleeping {
		pm.DeviceWake()
		e.coreSleeping = false
		e.appendLog("info", "系统唤醒，核心已毫秒级恢复 (box.Wake)")
	}
	if reset && b != nil {
		b.Network().ResetNetwork(context.Background())
		e.appendLog("info", "已按设置重置唤醒后的网络连接")
	}
	e.mu.Unlock()
	e.broadcastStatus()
}

// Start launches the sing-box + Xray + Mihomo tri-core instance for the selected profile.
func (e *Engine) Start(profileID int64) (err error) {
	defer device.DeferPanicToError("engine.Start", func(perr error) { err = perr })

	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	if e.state == StateConnected || e.state == StateConnecting {
		e.stopLocked(false)
	}
	st := e.store.Snapshot()
	if profileID <= 0 {
		profileID = st.SelectedProfile
	}
	var target store.Profile
	found := false
	for _, p := range st.Profiles {
		if p.ID == profileID {
			target = p
			found = true
			break
		}
	}
	if !found {
		e.lastError = "请先添加并选择一个代理节点"
		e.mu.Unlock()
		e.broadcastStatus()
		return errors.New(e.lastError)
	}

	e.state = StateConnecting
	e.lastError = ""
	e.activeProfile = target.ID
	e.activeName = target.Name
	e.activeType = target.Type
	e.activeCore = target.Core
	e.mu.Unlock()
	e.broadcastStatus()

	enableTUN := st.Settings.ServiceMode == "tun"
	actualMode := st.Settings.ServiceMode
	if enableTUN && !macos.CanUseTUN() {
		e.appendLog("warn", "TUN 模式需要管理员权限 (root)，当前自动切换为系统代理 + Mixed 本地代理模式运行")
		enableTUN = false
		actualMode = "system_proxy"
	}

	cfgStr, err := configbuilder.BuildSingBoxConfig(st, target, configbuilder.BuildOptions{
		ForTest:   false,
		EnableTUN: enableTUN,
		DataDir:   e.dataDir,
		YacdDir:   e.yacdDir,
		AssetsDir: e.assetsDir,
	})
	if err != nil {
		e.failStart(err)
		return err
	}

	instance, cancel, pm, err := e.createBox(cfgStr, false)
	if err != nil {
		e.failStart(err)
		return err
	}

	v2api := v2rayapi.NewStatsService(option.V2RayStatsServiceOptions{
		Enabled:   true,
		Outbounds: []string{configbuilder.TagProxy, configbuilder.TagDirect, configbuilder.TagBypass, configbuilder.TagMeta},
	})
	instance.Router().AppendTracker(mihomobridge.TrackSelectedOutbound(v2api))

	if err := instance.Start(); err != nil {
		cancel()
		_ = instance.Close()
		e.failStart(err)
		return err
	}

	// Configure macOS System Proxy if enabled
	sysProxyManaged := false
	if actualMode == "system_proxy" || (actualMode != "mixed_only" && st.Settings.AutoSetSystemProxy) {
		if svcs, err := macos.EnableSystemProxy("127.0.0.1", st.Settings.MixedPort); err != nil {
			e.appendLog("warn", "配置 macOS 系统代理失败: "+err.Error())
		} else {
			sysProxyManaged = true
			e.appendLog("info", fmt.Sprintf("已配置 macOS 系统代理 127.0.0.1:%d (%s)", st.Settings.MixedPort, strings.Join(svcs, ", ")))
		}
	}

	e.mu.Lock()
	e.box = instance
	e.boxCancel = cancel
	e.v2api = v2api
	e.pauseManager = pm
	e.state = StateConnected
	e.activeMode = actualMode
	e.activePort = st.Settings.MixedPort
	e.sysProxyManaged = sysProxyManaged
	e.startedAt = time.Now().UnixMilli()
	e.txRate, e.rxRate = 0, 0
	e.txTotal, e.rxTotal = 0, 0
	e.lastLatencyMs = 0
	e.statsStop = make(chan struct{})
	stopCh := e.statsStop
	e.mu.Unlock()

	_ = e.store.SelectProfile(target.ID)
	e.appendLog("info", fmt.Sprintf("已连接节点 [%s] (%s · %s) | 本地端口 %d | 模式 %s",
		target.Name, strings.ToUpper(target.Type), target.Core, st.Settings.MixedPort, actualMode))
	e.broadcastStatus()

	go e.pollTrafficLoop(stopCh, target.ID)
	go debug.FreeOSMemory()
	return nil
}

func (e *Engine) failStart(err error) {
	e.mu.Lock()
	e.state = StateStopped
	e.lastError = err.Error()
	e.mu.Unlock()
	e.appendLog("error", "连接失败: "+err.Error())
	e.broadcastStatus()
}

func (e *Engine) Stop() error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	e.stopLocked(true)
	e.mu.Unlock()
	e.broadcastStatus()
	return nil
}

func (e *Engine) stopLocked(disableSysProxy bool) {
	if e.statsStop != nil {
		close(e.statsStop)
		e.statsStop = nil
	}
	if e.boxCancel != nil {
		e.boxCancel()
		e.boxCancel = nil
	}
	if e.box != nil {
		_ = e.box.Close()
		e.box = nil
	}
	e.v2api = nil
	e.pauseManager = nil
	e.coreSleeping = false
	e.txRate, e.rxRate = 0, 0
	wasConnected := e.state != StateStopped
	wasManagingProxy := e.sysProxyManaged
	e.state = StateStopped
	if wasConnected {
		_ = e.store.Flush()
	}
	if disableSysProxy && wasManagingProxy {
		e.sysProxyManaged = false
		if err := macos.DisableSystemProxy(); err != nil && wasConnected {
			e.appendLog("warn", "清理 macOS 系统代理时遇到提示: "+err.Error())
		} else if wasConnected {
			e.appendLog("info", "已断开连接并清理 macOS 系统代理")
		}
	}
}

func (e *Engine) pollTrafficLoop(stopCh chan struct{}, profileID int64) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if e.pausedPolling.Load() && e.store.Snapshot().PowerSaver.PauseOnHidden {
				continue
			}
			e.mu.Lock()
			api := e.v2api
			if api == nil || e.state != StateConnected {
				e.mu.Unlock()
				continue
			}
			var proxyUp, proxyDown, directUp, directDown int64
			for _, tag := range []string{configbuilder.TagProxy, configbuilder.TagDirect, configbuilder.TagBypass} {
				var tUp, tDown int64
				if resp, err := api.GetStats(context.Background(), &v2rayapi.GetStatsRequest{
					Name:   "outbound>>>" + tag + ">>>traffic>>>uplink",
					Reset_: true,
				}); err == nil && resp != nil {
					tUp = resp.GetStat().GetValue()
				}
				if resp, err := api.GetStats(context.Background(), &v2rayapi.GetStatsRequest{
					Name:   "outbound>>>" + tag + ">>>traffic>>>downlink",
					Reset_: true,
				}); err == nil && resp != nil {
					tDown = resp.GetStat().GetValue()
				}
				if tag == configbuilder.TagProxy {
					proxyUp += tUp
					proxyDown += tDown
				} else {
					directUp += tUp
					directDown += tDown
				}
			}
			up := proxyUp + directUp
			down := proxyDown + directDown
			e.txRate = up
			e.rxRate = down
			e.txTotal += up
			e.rxTotal += down
			e.mu.Unlock()
			if proxyUp > 0 || proxyDown > 0 {
				e.store.AddProfileTraffic(profileID, proxyUp, proxyDown)
			}
			e.broadcastStatus()
		}
	}
}

// TestActiveConnection runs a 1-RTT HTTP probe through the currently connected core.
func (e *Engine) TestActiveConnection() (int, error) {
	e.mu.Lock()
	b := e.box
	if b == nil || e.state != StateConnected {
		e.mu.Unlock()
		return 0, errors.New("当前未连接代理")
	}
	e.mu.Unlock()

	out, err := urltest.PickOutbound(b.Outbound())
	if err != nil {
		return 0, err
	}
	testURL := e.store.Snapshot().Settings.ConnectionTestURL
	ms, err := urltest.Test(out, testURL, 5000, e.rootCAs)
	if err != nil {
		return 0, err
	}
	e.mu.Lock()
	e.lastLatencyMs = int(ms)
	e.mu.Unlock()
	e.broadcastStatus()
	return int(ms), nil
}

// TestProfile tests a single profile in an isolated test sing-box instance (zero bbolt lock contention).
func (e *Engine) TestProfile(profileID int64) (int, error) {
	st := e.store.Snapshot()
	var target store.Profile
	found := false
	for _, p := range st.Profiles {
		if p.ID == profileID {
			target = p
			found = true
			break
		}
	}
	if !found {
		return -1, errors.New("节点不存在")
	}

	cfgStr, err := configbuilder.BuildSingBoxConfig(st, target, configbuilder.BuildOptions{
		ForTest:   true,
		AssetsDir: e.assetsDir,
	})
	if err != nil {
		e.store.SetProfileLatency(profileID, -1, err.Error())
		return -1, err
	}
	inst, cancel, _, err := e.createBox(cfgStr, true)
	if err != nil {
		e.store.SetProfileLatency(profileID, -1, err.Error())
		return -1, err
	}
	defer func() {
		cancel()
		_ = inst.Close()
	}()
	if err := inst.Start(); err != nil {
		e.store.SetProfileLatency(profileID, -1, err.Error())
		return -1, err
	}
	out, err := urltest.PickOutbound(inst.Outbound())
	if err != nil {
		e.store.SetProfileLatency(profileID, -1, err.Error())
		return -1, err
	}
	ms, err := urltest.Test(out, st.Settings.ConnectionTestURL, 5000, e.rootCAs)
	if err != nil {
		e.store.SetProfileLatency(profileID, -1, err.Error())
		return -1, err
	}
	e.store.SetProfileLatency(profileID, int(ms), "")
	return int(ms), nil
}

// TestProfilesBatch tests multiple profiles concurrently respecting ConnectionTestConcurrent.
func (e *Engine) TestProfilesBatch(ids []int64) map[int64]map[string]any {
	st := e.store.Snapshot()
	conc := st.Settings.ConnectionTestConcurrent
	if conc < 1 {
		conc = 5
	}
	if conc > 16 {
		conc = 16
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var resMu sync.Mutex
	results := make(map[int64]map[string]any, len(ids))

	for _, id := range ids {
		wg.Add(1)
		go func(pid int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := e.TestProfile(pid)
			resMu.Lock()
			if err != nil {
				results[pid] = map[string]any{"latencyMs": -1, "error": err.Error()}
			} else {
				results[pid] = map[string]any{"latencyMs": ms}
			}
			resMu.Unlock()
		}(id)
	}
	wg.Wait()
	return results
}

// MetaRoutingStatus returns live or cached Meta MRS routing diagnostics.
func (e *Engine) MetaRoutingStatus() map[string]any {
	e.mu.Lock()
	b := e.box
	connected := e.state == StateConnected
	e.mu.Unlock()

	var raw string
	if connected && b != nil {
		raw = mihomobridge.RoutingStatus(b.Outbound())
	}
	if raw == "" {
		src := e.store.Snapshot().AppProxy.MetaRuleSource
		raw = mihomobridge.CachedRoutingStatusForSource(e.assetsDir, src)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return map[string]any{"raw": raw}
	}
	return parsed
}

// RefreshMetaRules downloads the latest MRS rule set from MetaCubeX or DustinWin.
func (e *Engine) RefreshMetaRules() (map[string]any, error) {
	e.mu.Lock()
	b := e.box
	connected := e.state == StateConnected
	port := e.activePort
	e.mu.Unlock()

	var raw string
	var err error
	if connected && b != nil {
		raw, err = mihomobridge.RefreshRulesNow(b.Outbound())
	} else {
		src := e.store.Snapshot().AppProxy.MetaRuleSource
		raw, err = mihomobridge.RefreshCachedRules(e.assetsDir, src, port, e.rootCAs)
	}
	if err != nil {
		return nil, err
	}
	var parsed map[string]any
	_ = json.Unmarshal([]byte(raw), &parsed)
	e.appendLog("info", "Meta 分流规则集已刷新至最新版本")
	return parsed, nil
}

// RunStunTest runs Nekobox-Next's built-in STUN NAT discovery.
func (e *Engine) RunStunTest(server string) (map[string]any, error) {
	if strings.TrimSpace(server) == "" {
		server = e.store.Snapshot().Settings.StunServer
	}
	if server == "" {
		server = "stun.voipgate.com:3478"
	}
	client := stun.NewClient()
	client.SetServerAddr(server)
	natType, host, err, fakeFullCone := client.Discover()
	if err != nil {
		return nil, err
	}
	external := ""
	if host != nil {
		external = host.String()
	}
	natLabel := natType.String()
	if fakeFullCone {
		natLabel += " (Fake FullCone)"
	}
	res := map[string]any{
		"server":       server,
		"natType":      natLabel,
		"externalAddr": external,
	}
	if behavior, bErr := client.BehaviorTest(); bErr == nil && behavior != nil {
		res["mappingBehavior"] = behavior.MappingType.String()
		res["filteringBehavior"] = behavior.FilteringType.String()
		res["normalType"] = behavior.NormalType()
	}
	return res, nil
}

// UpdateSubscription fetches, parses, deduplicates, and updates a subscription group.
func (e *Engine) UpdateSubscription(groupID int64) (int, error) {
	st := e.store.Snapshot()
	var grp store.Group
	found := false
	for _, g := range st.Groups {
		if g.ID == groupID {
			grp = g
			found = true
			break
		}
	}
	if !found {
		return 0, errors.New("分组不存在")
	}
	subURL := strings.TrimSpace(grp.SubscriptionURL)
	if subURL == "" {
		return 0, errors.New("该分组未配置订阅链接")
	}
	if parser.IsDoHURL(subURL) {
		return 0, parser.ErrDoHSubscriptionURL
	}

	ua := grp.UserAgent
	if ua == "" {
		ua = "NekoBox/Mac/" + AppVersion + " (Prefer ClashMeta Format)"
	}

	body, headers, err := e.httpFetchWithFallback(subURL, ua, st.Settings.AllowInsecureOnRequest)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no 'dns' query parameter") {
			return 0, parser.ErrDoHSubscriptionURL
		}
		return 0, err
	}

	profiles, err := parser.ParseInput(body)
	if err != nil {
		return 0, err
	}
	if grp.Deduplication {
		profiles = parser.DeduplicateProfiles(profiles)
	}

	userinfo := headers.Get("Subscription-Userinfo")
	up, down, total, exp := parser.ParseSubscriptionUserinfo(userinfo)
	disp := headers.Get("Content-Disposition")

	count, err := e.store.ReplaceGroupProfiles(groupID, profiles, func(g *store.Group) {
		if userinfo != "" {
			g.SubscriptionUserInfo = userinfo
			g.UploadBytes = up
			g.DownloadBytes = down
			g.TotalBytes = total
			g.ExpireTimestamp = exp
		}
		if strings.HasPrefix(g.Name, "订阅") && disp != "" {
			if name := extractDispositionName(disp); name != "" {
				g.Name = name
			}
		}
	})
	if err != nil {
		return 0, err
	}
	e.appendLog("info", fmt.Sprintf("订阅 [%s] 更新成功，共 %d 个节点", grp.Name, count))
	return count, nil
}

func (e *Engine) httpFetchWithFallback(rawURL, ua string, insecure bool) (string, http.Header, error) {
	tryFetch := func(proxyURL *url.URL) (string, http.Header, error) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            e.rootCAs,
				InsecureSkipVerify: insecure,
			},
			DialContext: (&net.Dialer{Timeout: 12 * time.Second}).DialContext,
		}
		if proxyURL != nil {
			tr.Proxy = http.ProxyURL(proxyURL)
		}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			return "", nil, err
		}
		req.Header.Set("User-Agent", ua)
		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			return "", nil, err
		}
		if resp.StatusCode != http.StatusOK {
			preview := string(b)
			if len(preview) > 120 {
				preview = preview[:120] + "..."
			}
			return "", resp.Header, fmt.Errorf("HTTP %s: %s", resp.Status, preview)
		}
		return string(b), resp.Header, nil
	}

	e.mu.Lock()
	connected := e.state == StateConnected
	port := e.activePort
	e.mu.Unlock()

	if connected && port > 0 {
		pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
		if body, hdr, err := tryFetch(pu); err == nil {
			return body, hdr, nil
		}
	}
	return tryFetch(nil)
}

func (e *Engine) createBox(cfgStr string, forTest bool) (*box.Box, context.CancelFunc, pause.Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	outbounds := include.OutboundRegistry()
	hysteriapin.Register(outbounds)
	xraybridge.Register(outbounds)
	mihomobridge.Register(outbounds)
	mihomobridge.RegisterRouting(outbounds)
	ctx = mihomobridge.WithRuleCache(ctx, e.assetsDir)

	dnsTransports := include.DNSTransportRegistry()
	mihomobridge.RegisterDNS(dnsTransports)

	ctx = box.Context(
		ctx,
		include.InboundRegistry(),
		outbounds,
		include.EndpointRegistry(),
		dnsTransports,
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)

	options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(cfgStr))
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("decode sing-box config: %w", err)
	}

	var logWriter sblog.PlatformWriter = &engineLogWriter{e: e}
	if forTest {
		logWriter = nil
		if options.Experimental != nil {
			options.Experimental.CacheFile = nil
			options.Experimental.ClashAPI = nil
			options.Experimental.V2RayAPI = nil
		}
	} else {
		// Passing PlatformLogWriter != nil causes sing-box to always initialize cache-file.
		// Resolve cache.db (and any relative ExternalUI path) inside writable e.dataDir so
		// launching the .app bundle from Finder/LaunchServices (cwd="/") never hits EROFS.
		if options.Experimental == nil {
			options.Experimental = &option.ExperimentalOptions{}
		}
		if options.Experimental.CacheFile == nil {
			options.Experimental.CacheFile = &option.CacheFileOptions{Enabled: true}
		}
		cachePath := strings.TrimSpace(options.Experimental.CacheFile.Path)
		if cachePath == "" {
			cachePath = filepath.Join(e.dataDir, "cache.db")
		} else if !filepath.IsAbs(cachePath) {
			cachePath = filepath.Join(e.dataDir, cachePath)
		}
		if mkErr := os.MkdirAll(filepath.Dir(cachePath), 0o755); mkErr != nil {
			fallback := filepath.Join(e.dataDir, "cache.db")
			e.appendLog("warn", fmt.Sprintf("cache_file 目录不可写 (%s)，已自动回退至 %s", cachePath, fallback))
			cachePath = fallback
			_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
		}
		options.Experimental.CacheFile.Path = cachePath

		if options.Experimental.ClashAPI != nil {
			uiPath := strings.TrimSpace(options.Experimental.ClashAPI.ExternalUI)
			if uiPath != "" && !filepath.IsAbs(uiPath) {
				options.Experimental.ClashAPI.ExternalUI = filepath.Join(e.dataDir, uiPath)
			}
		}
	}

	inst, err := box.New(box.Options{
		Options:           options,
		Context:           ctx,
		PlatformLogWriter: logWriter,
	})
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("create sing-box service: %w", err)
	}
	return inst, cancel, service.FromContext[pause.Manager](ctx), nil
}

type engineLogWriter struct {
	e *Engine
}

func (w *engineLogWriter) DisableColors() bool { return true }
func (w *engineLogWriter) WriteMessage(level uint8, message string) {
	lvl := "info"
	switch level {
	case sblog.LevelPanic, sblog.LevelFatal, sblog.LevelError:
		lvl = "error"
	case sblog.LevelWarn:
		lvl = "warn"
	case sblog.LevelDebug, sblog.LevelTrace:
		lvl = "debug"
	}
	w.e.appendLog(lvl, message)
}

func extractDispositionName(disp string) string {
	for _, part := range strings.Split(disp, ";") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(p), "filename*=") {
			val := p[len("filename*="):]
			if idx := strings.Index(val, "''"); idx >= 0 {
				val = val[idx+2:]
			}
			if dec, err := url.QueryUnescape(strings.Trim(val, `"'`)); err == nil {
				return dec
			}
		}
		if strings.HasPrefix(strings.ToLower(p), "filename=") {
			return strings.Trim(p[len("filename="):], `"'`)
		}
	}
	return ""
}

func extractYacdSafe(zipPath, dstDir string) error {
	if _, err := os.Stat(filepath.Join(dstDir, "index.html")); err == nil {
		return nil
	}
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	cleanDst := filepath.Clean(dstDir) + string(os.PathSeparator)

	for _, f := range r.File {
		// Strip leading "yacd/" or single top-level folder if present
		rel := strings.TrimPrefix(f.Name, "yacd/")
		if rel == "" {
			continue
		}
		target := filepath.Join(dstDir, rel)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanDst) && filepath.Clean(target) != filepath.Clean(dstDir) {
			return fmt.Errorf("zip-slip blocked: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

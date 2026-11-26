// SPDX-License-Identifier: GPL-3.0-or-later
package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nekobox-mac/internal/engine"
	"nekobox-mac/internal/store"
)

func TestServerSecurityAuthOriginAndHostProtection(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	eng, err := engine.New(st, dataDir, "")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	const secretToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	srv := New(st, eng, "/Applications/Nekobox-Mac.app", secretToken)

	// 1. Unauthenticated /api/bootstrap must return 401
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19850/api/bootstrap", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
	if cors := rec.Header().Get("Access-Control-Allow-Origin"); cors != "" {
		t.Fatalf("unexpected permissive CORS header: %q", cors)
	}

	// 2. DNS rebinding host must return 403 even with token
	reqEvilHost := httptest.NewRequest(http.MethodGet, "http://evil.attacker.com:19850/api/status", nil)
	reqEvilHost.Header.Set("X-Neko-Token", secretToken)
	recEvilHost := httptest.NewRecorder()
	srv.ServeHTTP(recEvilHost, reqEvilHost)
	if recEvilHost.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for DNS rebinding Host, got %d", recEvilHost.Code)
	}

	// 3. Cross-origin webpage fetch must return 403
	reqEvilOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19850/api/connect", strings.NewReader("{}"))
	reqEvilOrigin.Header.Set("Origin", "https://malicious.example.com")
	reqEvilOrigin.Header.Set("X-Neko-Token", secretToken)
	recEvilOrigin := httptest.NewRecorder()
	srv.ServeHTTP(recEvilOrigin, reqEvilOrigin)
	if recEvilOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin request, got %d", recEvilOrigin.Code)
	}

	// 4. Valid X-Neko-Token succeeds
	reqOK := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19850/api/status", nil)
	reqOK.Header.Set("X-Neko-Token", secretToken)
	recOK := httptest.NewRecorder()
	srv.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid X-Neko-Token, got %d", recOK.Code)
	}

	// 5. Initial UI load with ?token= sets HttpOnly SameSite=Strict cookie and allows subsequent cookie auth
	reqBoot := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19850/?token="+secretToken, nil)
	recBoot := httptest.NewRecorder()
	srv.ServeHTTP(recBoot, reqBoot)
	cookies := recBoot.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "neko_token" || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected HttpOnly SameSite=Strict neko_token cookie, got %+v", cookies)
	}

	reqCookie := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19850/api/status", nil)
	reqCookie.AddCookie(cookies[0])
	recCookie := httptest.NewRecorder()
	srv.ServeHTTP(recCookie, reqCookie)
	if recCookie.Code != http.StatusOK {
		t.Fatalf("expected 200 with session cookie, got %d", recCookie.Code)
	}

	// 6. Disallowed URL scheme in /api/tools/open-url must fail
	reqBadScheme := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19850/api/tools/open-url", strings.NewReader(`{"url":"file:///System/Applications/Calculator.app"}`))
	reqBadScheme.Header.Set("X-Neko-Token", secretToken)
	recBadScheme := httptest.NewRecorder()
	srv.ServeHTTP(recBadScheme, reqBadScheme)
	if recBadScheme.Code == http.StatusOK {
		t.Fatalf("expected file:// scheme in open-url to be rejected")
	}

	// 7. Reject untrusted downloadUrl in /api/update/apply
	reqBadUpd := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19850/api/update/apply", strings.NewReader(`{"downloadUrl":"https://evil.example.com/fake.dmg"}`))
	reqBadUpd.Header.Set("X-Neko-Token", secretToken)
	recBadUpd := httptest.NewRecorder()
	srv.ServeHTTP(recBadUpd, reqBadUpd)
	if recBadUpd.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for untrusted update downloadUrl, got %d", recBadUpd.Code)
	}
}

func TestGroupShareAndIgnoreUpdateEndpoints(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	eng, err := engine.New(st, dataDir, "")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	const secretToken = "test-group-share-token"
	srv := New(st, eng, "/Applications/Nekobox-Mac.app", secretToken)

	// Create a second group and add profiles to both groups
	grp, err := st.UpsertGroup(store.Group{
		Name:            "主力分组",
		Type:            "subscription",
		SubscriptionURL: "https://sub.example.com/list",
	})
	if err != nil {
		t.Fatalf("upsert group: %v", err)
	}
	_, err = st.AddProfiles(grp.ID, []store.Profile{
		{
			Name:     "HK-01",
			Type:     "trojan",
			Address:  "hk1.example.com",
			Port:     443,
			Params:   map[string]any{"password": "pass1", "sni": "hk1.example.com"},
			ShareURI: "trojan://pass1@hk1.example.com:443?sni=hk1.example.com#HK-01",
		},
		{
			Name:     "JP-02",
			Type:     "vless",
			Address:  "jp2.example.com",
			Port:     443,
			Params:   map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "security": "tls"},
			ShareURI: "vless://11111111-2222-3333-4444-555555555555@jp2.example.com:443?encryption=none&security=tls#JP-02",
		},
	})
	if err != nil {
		t.Fatalf("add profiles: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:19850/api/groups/share?id=%d", grp.ID), nil)
	req.Header.Set("X-Neko-Token", secretToken)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/groups/share, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		GroupID         int64    `json:"groupId"`
		GroupName       string   `json:"groupName"`
		IsSubscription  bool     `json:"isSubscription"`
		SubscriptionURL string   `json:"subscriptionUrl"`
		Count           int      `json:"count"`
		URIs            []string `json:"uris"`
		RawText         string   `json:"rawText"`
		Base64Text      string   `json:"base64Text"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode share response: %v", err)
	}
	if resp.GroupID != grp.ID || resp.GroupName != "主力分组" || !resp.IsSubscription || resp.SubscriptionURL != "https://sub.example.com/list" {
		t.Fatalf("unexpected group metadata: %+v", resp)
	}
	if resp.Count != 2 || len(resp.URIs) != 2 {
		t.Fatalf("expected 2 shared URIs, got %+v", resp)
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.Base64Text)
	if err != nil || string(decoded) != resp.RawText {
		t.Fatalf("base64Text mismatch: got %q err=%v", string(decoded), err)
	}

	// Ignore update version persists to settings
	reqIgn := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19850/api/update/ignore", strings.NewReader(`{"version":"v1.6.9"}`))
	reqIgn.Header.Set("X-Neko-Token", secretToken)
	recIgn := httptest.NewRecorder()
	srv.ServeHTTP(recIgn, reqIgn)
	if recIgn.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/update/ignore, got %d", recIgn.Code)
	}
	if got := st.Snapshot().Settings.IgnoredUpdateVersion; got != "1.6.9" {
		t.Fatalf("expected normalized ignoredUpdateVersion=1.6.9, got %q", got)
	}
}

func TestPerAppBypassLiveHotReloadAndBundlePathMatching(t *testing.T) {
	// 1. Start a local mock upstream HTTP CONNECT proxy to detect whether traffic routed via "proxy" outbound.
	var proxyHits atomic.Int32
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream proxy: %v", err)
	}
	defer upstreamLn.Close()
	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				proxyHits.Add(1)
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf)
				// Respond to sing-box HTTP outbound CONNECT handshake
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				// Read inner HTTP request sent through the tunnel and reply with marker body
				_, _ = c.Read(buf)
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\nVIA_UPSTREAM_PROXY"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	uHost, uPortStr, _ := net.SplitHostPort(upstreamLn.Addr().String())
	var uPort int
	_, _ = fmt.Sscanf(uPortStr, "%d", &uPort)

	// Pick an unused local mixed port.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc mixed port: %v", err)
	}
	mixedPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	dataDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	settings := st.Snapshot().Settings
	settings.ServiceMode = "mixed_only"
	settings.AutoSetSystemProxy = false
	settings.MixedPort = mixedPort
	settings.EnableClashAPI = false
	settings.LogLevel = "debug"
	if _, err := st.UpdateSettings(settings); err != nil {
		t.Fatalf("update settings: %v", err)
	}
	// Disable Meta routing so default traffic goes to "proxy" unless matched by per-app bypass rule.
	ap := st.Snapshot().AppProxy
	ap.MetaAutoRouting = false
	if _, err := st.UpdateAppProxy(ap); err != nil {
		t.Fatalf("update app proxy: %v", err)
	}

	added, err := st.AddProfiles(1, []store.Profile{
		{
			Name:    "Mock HTTP Upstream",
			Type:    "http",
			Address: uHost,
			Port:    uPort,
		},
	})
	if err != nil || len(added) == 0 {
		t.Fatalf("add profile: %v", err)
	}

	eng, err := engine.New(st, dataDir, "")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer func() { _ = eng.Stop() }()

	if err := eng.Start(added[0].ID); err != nil {
		t.Fatalf("engine.Start: %v", err)
	}

	const secretToken = "test-bypass-hotreload-token"
	srv := New(st, eng, "/Applications/Nekobox-Mac.app", secretToken)

	mixedProxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	doViaMixed := func(targetURL string) (string, error) {
		tr := &http.Transport{
			Proxy:             http.ProxyURL(mixedProxyURL),
			DisableKeepAlives: true,
		}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		resp, err := client.Get(targetURL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}

	// Step A: Without bypass rule, request to non-private domain goes through upstream proxy.
	body, err := doViaMixed("http://bypass-e2e-probe.invalid/check")
	if err != nil || body != "VIA_UPSTREAM_PROXY" {
		t.Fatalf("before bypass: expected VIA_UPSTREAM_PROXY, got body=%q err=%v", body, err)
	}
	if proxyHits.Load() != 1 {
		t.Fatalf("before bypass: expected proxyHits=1, got %d", proxyHits.Load())
	}

	// Step B: Configure per-app "bypass" using ONLY the parent bundle directory (simulating Helper inside .app)
	// with a mismatched primary process name ("WrongPrimaryName") to prove process_path_regex catches Helpers,
	// and verify /api/app-proxy hot-reloads the running engine automatically.
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	bundleDir := filepath.Dir(exePath)

	bypassPayload := st.Snapshot().AppProxy
	bypassPayload.AppActions["com.test.helperapp"] = "bypass"
	bypassPayload.AppProcessMap["com.test.helperapp"] = "WrongPrimaryName"
	bypassPayload.AppPathMap["com.test.helperapp"] = bundleDir

	rawBody, _ := json.Marshal(bypassPayload)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19850/api/app-proxy", bytes.NewReader(rawBody))
	req.Header.Set("X-Neko-Token", secretToken)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/app-proxy failed: %d %s", rec.Code, rec.Body.String())
	}
	var apResp struct {
		Reloaded    bool   `json:"reloaded"`
		ReloadError string `json:"reloadError"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &apResp); err != nil {
		t.Fatalf("decode /api/app-proxy response: %v", err)
	}
	if !apResp.Reloaded || apResp.ReloadError != "" {
		t.Fatalf("expected automatic hot reload on /api/app-proxy, got %+v", apResp)
	}

	// Step C: Request again without manual reconnect — must bypass upstream proxy (direct outbound fails to resolve .invalid, proxyHits stays 1).
	hitsBeforeBypassReq := proxyHits.Load()
	bodyAfter, _ := doViaMixed("http://bypass-e2e-probe.invalid/check")
	if bodyAfter == "VIA_UPSTREAM_PROXY" || proxyHits.Load() != hitsBeforeBypassReq {
		t.Fatalf("after bypass hot-reload: request still hit upstream proxy! body=%q proxyHits=%d->%d logs=%+v",
			bodyAfter, hitsBeforeBypassReq, proxyHits.Load(), eng.Logs())
	}

	// Step D: Switch the same app back to force_proxy via /api/app-proxy — must immediately route back through proxy.
	bypassPayload.AppActions["com.test.helperapp"] = "force_proxy"
	rawBody2, _ := json.Marshal(bypassPayload)
	req2 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19850/api/app-proxy", bytes.NewReader(rawBody2))
	req2.Header.Set("X-Neko-Token", secretToken)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("POST /api/app-proxy (force_proxy) failed: %d %s", rec2.Code, rec2.Body.String())
	}

	bodyForce, err := doViaMixed("http://bypass-e2e-probe.invalid/check")
	if err != nil || bodyForce != "VIA_UPSTREAM_PROXY" {
		t.Fatalf("after switching back to force_proxy: expected VIA_UPSTREAM_PROXY, got body=%q err=%v", bodyForce, err)
	}
}

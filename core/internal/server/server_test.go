// SPDX-License-Identifier: GPL-3.0-or-later
package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// SPDX-License-Identifier: GPL-3.0-or-later
package server

import (
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
}

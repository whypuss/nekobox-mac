// SPDX-License-Identifier: GPL-3.0-or-later
package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nekobox-mac/internal/configbuilder"
	"nekobox-mac/internal/engine"
	"nekobox-mac/internal/macos"
	"nekobox-mac/internal/parser"
	"nekobox-mac/internal/store"
	"nekobox-mac/web"
)

type Server struct {
	store    *store.Store
	engine   *engine.Engine
	appPath  string
	apiToken string
	mux      *http.ServeMux
}

func New(st *store.Store, eng *engine.Engine, appPath string, apiToken string) *Server {
	s := &Server{
		store:    st,
		engine:   eng,
		appPath:  appPath,
		apiToken: strings.TrimSpace(apiToken),
		mux:      http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func isLoopbackHost(hostPort string) bool {
	if hostPort == "" {
		return true
	}
	h := hostPort
	if parsedHost, _, err := net.SplitHostPort(hostPort); err == nil {
		h = parsedHost
	}
	h = strings.Trim(strings.ToLower(h), "[]")
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || strings.ToLower(u.Scheme) != "http" {
		return false
	}
	return isLoopbackHost(u.Host)
}

func (s *Server) tokenMatches(candidate string) bool {
	if s.apiToken == "" {
		return true
	}
	if len(candidate) != len(s.apiToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.apiToken)) == 1
}

func (s *Server) isAuthorized(r *http.Request) bool {
	if s.apiToken == "" {
		return true
	}
	if hdr := strings.TrimSpace(r.Header.Get("X-Neko-Token")); hdr != "" && s.tokenMatches(hdr) {
		return true
	}
	if c, err := r.Cookie("neko_token"); err == nil && s.tokenMatches(c.Value) {
		return true
	}
	if q := strings.TrimSpace(r.URL.Query().Get("token")); q != "" && s.tokenMatches(q) {
		return true
	}
	return false
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Block DNS rebinding & cross-origin browser attacks against localhost API
	if !isLoopbackHost(r.Host) || !isAllowedOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin or host", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if s.apiToken != "" {
		if q := strings.TrimSpace(r.URL.Query().Get("token")); q != "" && s.tokenMatches(q) {
			http.SetCookie(w, &http.Cookie{
				Name:     "neko_token",
				Value:    s.apiToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/clash-api/") {
			if !s.isAuthorized(r) {
				writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized local API request"))
				return
			}
		}
	}

	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	// Health & Bootstrap
	s.mux.HandleFunc("/api/bootstrap", s.handleBootstrap)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/versions", s.handleVersions)
	s.mux.HandleFunc("/api/events", s.handleSSE)

	// Connection control
	s.mux.HandleFunc("/api/connect", s.handleConnect)
	s.mux.HandleFunc("/api/disconnect", s.handleDisconnect)
	s.mux.HandleFunc("/api/test-active", s.handleTestActive)
	s.mux.HandleFunc("/api/sysproxy", s.handleSysProxy)
	s.mux.HandleFunc("/api/power/sleep", s.handleSleep)
	s.mux.HandleFunc("/api/power/wake", s.handleWake)
	s.mux.HandleFunc("/api/power/polling", s.handlePolling)

	// Profiles
	s.mux.HandleFunc("/api/profiles/import", s.handleImportProfiles)
	s.mux.HandleFunc("/api/profiles/create", s.handleCreateProfile)
	s.mux.HandleFunc("/api/profiles/update", s.handleUpdateProfile)
	s.mux.HandleFunc("/api/profiles/delete", s.handleDeleteProfile)
	s.mux.HandleFunc("/api/profiles/select", s.handleSelectProfile)
	s.mux.HandleFunc("/api/profiles/share", s.handleShareProfile)
	s.mux.HandleFunc("/api/profiles/export-config", s.handleExportConfig)
	s.mux.HandleFunc("/api/profiles/test", s.handleTestProfiles)
	s.mux.HandleFunc("/api/profiles/sort", s.handleSortProfiles)
	s.mux.HandleFunc("/api/profiles/cleanup", s.handleCleanupProfiles)
	s.mux.HandleFunc("/api/profiles/clear-traffic", s.handleClearTraffic)

	// Groups & Subscriptions
	s.mux.HandleFunc("/api/groups/upsert", s.handleUpsertGroup)
	s.mux.HandleFunc("/api/groups/delete", s.handleDeleteGroup)
	s.mux.HandleFunc("/api/groups/select", s.handleSelectGroup)
	s.mux.HandleFunc("/api/groups/update-sub", s.handleUpdateSub)
	s.mux.HandleFunc("/api/groups/update-all", s.handleUpdateAllSubs)

	// Routing Rules
	s.mux.HandleFunc("/api/rules/upsert", s.handleUpsertRule)
	s.mux.HandleFunc("/api/rules/delete", s.handleDeleteRule)
	s.mux.HandleFunc("/api/rules/reorder", s.handleReorderRules)

	// App Proxy & Meta Smart Routing
	s.mux.HandleFunc("/api/macos/apps", s.handleMacApps)
	s.mux.HandleFunc("/api/macos/permissions", s.handleMacPermissions)
	s.mux.HandleFunc("/api/macos/open-settings", s.handleMacOpenSettings)
	s.mux.HandleFunc("/api/macos/install-app", s.handleMacInstallApp)
	s.mux.HandleFunc("/api/app-proxy", s.handleAppProxy)
	s.mux.HandleFunc("/api/meta/status", s.handleMetaStatus)
	s.mux.HandleFunc("/api/meta/refresh", s.handleMetaRefresh)

	// Power Saver & Settings
	s.mux.HandleFunc("/api/power-saver", s.handlePowerSaver)
	s.mux.HandleFunc("/api/settings", s.handleSettings)

	// Logs & Tools
	s.mux.HandleFunc("/api/logs", s.handleLogs)
	s.mux.HandleFunc("/api/logs/clear", s.handleClearLogs)
	s.mux.HandleFunc("/api/tools/stun", s.handleStun)
	s.mux.HandleFunc("/api/tools/open-url", s.handleOpenURL)
	s.mux.HandleFunc("/api/backup/export", s.handleBackupExport)
	s.mux.HandleFunc("/api/backup/import", s.handleBackupImport)
	s.mux.HandleFunc("/api/backup/reset", s.handleBackupReset)

	// Embedded MetaCubeXD Web Dashboard (/ui/)
	s.mux.HandleFunc("/ui/", s.handleYacd)
	s.mux.HandleFunc("/clash-api/", s.handleClashAPIProxy)

	// Embedded Nekobox-Mac 1:1 UI
	distFS, _ := fs.Sub(web.FS, "dist")
	s.mux.Handle("/", http.FileServer(http.FS(distFS)))
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	st := s.store.Snapshot()
	writeJSON(w, map[string]any{
		"state":       st,
		"status":      s.engine.Status(),
		"versions":    s.engine.Versions(),
		"logs":        s.engine.Logs(),
		"permissions": macos.InspectPermissions(s.appPath, st.Settings.ServiceMode),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.Status())
}

func (s *Server) handleVersions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.Versions())
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	statusCh, unsubStatus := s.engine.SubscribeStatus()
	defer unsubStatus()
	logCh, unsubLog := s.engine.SubscribeLogs()
	defer unsubLog()

	sendEvent := func(evt string, payload any) {
		b, _ := json.Marshal(payload)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt, b)
		flusher.Flush()
	}

	sendEvent("status", s.engine.Status())
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case st := <-statusCh:
			sendEvent("status", st)
		case lg := <-logCh:
			sendEvent("log", lg)
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProfileID int64 `json:"profileId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.engine.Start(body.ProfileID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, s.engine.Status())
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	_ = s.engine.Stop()
	writeJSON(w, s.engine.Status())
}

func (s *Server) handleTestActive(w http.ResponseWriter, r *http.Request) {
	ms, err := s.engine.TestActiveConnection()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"latencyMs": ms})
}

func (s *Server) handleSysProxy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.Enabled {
		port := s.store.Snapshot().Settings.MixedPort
		if _, err := macos.EnableSystemProxy("127.0.0.1", port); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		_ = macos.DisableSystemProxy()
	}
	writeJSON(w, macos.GetSystemProxyStatus())
}

func (s *Server) handleSleep(w http.ResponseWriter, r *http.Request) {
	s.engine.Sleep()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleWake(w http.ResponseWriter, r *http.Request) {
	s.engine.Wake()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handlePolling(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Paused bool `json:"paused"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.engine.SetPollingPaused(body.Paused)
	writeJSON(w, map[string]any{"paused": body.Paused})
}

func (s *Server) handleImportProfiles(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GroupID int64  `json:"groupId"`
		Text    string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	trimmed := strings.TrimSpace(body.Text)
	if parser.IsDoHURL(trimmed) {
		writeErr(w, http.StatusBadRequest, parser.ErrDoHSubscriptionURL)
		return
	}
	// If single HTTP/HTTPS URL looks like a remote subscription, create subscription group and fetch it
	if (strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://")) && !strings.Contains(trimmed, "\n") {
		grp, err := s.store.UpsertGroup(store.Group{
			Name:            fmt.Sprintf("订阅 #%d", len(s.store.Snapshot().Groups)+1),
			Type:            "subscription",
			SubscriptionURL: trimmed,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		count, err := s.engine.UpdateSubscription(grp.ID)
		if err != nil {
			_ = s.store.DeleteGroup(grp.ID)
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]any{
			"imported":     count,
			"subscription": true,
			"groupId":      grp.ID,
			"state":        s.store.Snapshot(),
		})
		return
	}

	profiles, err := parser.ParseInput(body.Text)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	added, err := s.store.AddProfiles(body.GroupID, profiles)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{
		"imported": len(added),
		"profiles": added,
		"state":    s.store.Snapshot(),
	})
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var p store.Profile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	added, err := s.store.AddProfiles(p.GroupID, []store.Profile{p})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"profile": added[0], "state": s.store.Snapshot()})
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	var p store.Profile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	updated, err := s.store.UpdateProfile(p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"profile": updated, "state": s.store.Snapshot()})
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	curStatus := s.engine.Status()
	if curStatus.State != engine.StateStopped && curStatus.ActiveProfile == body.ID {
		_ = s.engine.Stop()
	}
	if err := s.store.DeleteProfile(body.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"state": s.store.Snapshot(), "status": s.engine.Status()})
}

func (s *Server) handleSelectProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID        int64 `json:"id"`
		Reconnect bool  `json:"reconnect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SelectProfile(body.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.Reconnect && s.engine.Status().State == engine.StateConnected {
		if err := s.engine.Start(body.ID); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	writeJSON(w, map[string]any{"state": s.store.Snapshot(), "status": s.engine.Status()})
}

func (s *Server) handleShareProfile(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	p, ok := s.store.GetProfile(id)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("节点不存在"))
		return
	}
	writeJSON(w, map[string]any{"uri": parser.ExportShareURI(p), "name": p.Name})
}

func (s *Server) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	p, ok := s.store.GetProfile(id)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("节点不存在"))
		return
	}
	cfg, err := configbuilder.BuildSingBoxConfig(s.store.Snapshot(), p, configbuilder.BuildOptions{
		ForTest:   false,
		EnableTUN: s.store.Snapshot().Settings.ServiceMode == "tun",
		DataDir:   s.engine.DataDir(),
		YacdDir:   s.engine.YacdDir(),
		AssetsDir: s.engine.AssetsDir(),
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"config": cfg})
}

func (s *Server) handleTestProfiles(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	res := s.engine.TestProfilesBatch(body.IDs)
	writeJSON(w, map[string]any{"results": res, "state": s.store.Snapshot()})
}

func (s *Server) handleSortProfiles(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GroupID int64  `json:"groupId"`
		By      string `json:"by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SortProfiles(body.GroupID, body.By); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"state": s.store.Snapshot()})
}

func (s *Server) handleCleanupProfiles(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GroupID int64  `json:"groupId"`
		Mode    string `json:"mode"` // unavailable, duplicates, all
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	removed, err := s.store.DeleteProfilesByFilter(body.GroupID, body.Mode)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"removed": removed, "state": s.store.Snapshot()})
}

func (s *Server) handleClearTraffic(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GroupID int64 `json:"groupId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	_ = s.store.ClearTraffic(body.GroupID)
	writeJSON(w, map[string]any{"state": s.store.Snapshot()})
}

func (s *Server) handleUpsertGroup(w http.ResponseWriter, r *http.Request) {
	var g store.Group
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if g.SubscriptionURL != "" && parser.IsDoHURL(g.SubscriptionURL) {
		writeErr(w, http.StatusBadRequest, parser.ErrDoHSubscriptionURL)
		return
	}
	saved, err := s.store.UpsertGroup(g)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"group": saved, "state": s.store.Snapshot()})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.DeleteGroup(body.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	curStatus := s.engine.Status()
	if curStatus.State != engine.StateStopped && curStatus.ActiveProfile > 0 {
		if _, exists := s.store.GetProfile(curStatus.ActiveProfile); !exists {
			_ = s.engine.Stop()
		}
	}
	writeJSON(w, map[string]any{"state": s.store.Snapshot(), "status": s.engine.Status()})
}

func (s *Server) handleSelectGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	_ = s.store.SetSelectedGroup(body.ID)
	writeJSON(w, map[string]any{"state": s.store.Snapshot()})
}

func (s *Server) handleUpdateSub(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	count, err := s.engine.UpdateSubscription(body.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"count": count, "state": s.store.Snapshot()})
}

func (s *Server) handleUpdateAllSubs(w http.ResponseWriter, r *http.Request) {
	st := s.store.Snapshot()
	updated := 0
	var errs []string
	for _, g := range st.Groups {
		if g.SubscriptionURL == "" {
			continue
		}
		if _, err := s.engine.UpdateSubscription(g.ID); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", g.Name, err))
		} else {
			updated++
		}
	}
	writeJSON(w, map[string]any{"updated": updated, "errors": errs, "state": s.store.Snapshot()})
}

func (s *Server) handleUpsertRule(w http.ResponseWriter, r *http.Request) {
	var rule store.RouteRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.store.UpsertRule(rule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"rule": saved, "state": s.store.Snapshot()})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.DeleteRule(body.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"state": s.store.Snapshot()})
}

func (s *Server) handleReorderRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_ = s.store.ReorderRules(body.IDs)
	writeJSON(w, map[string]any{"state": s.store.Snapshot()})
}

func (s *Server) handleMacApps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"apps": macos.ListInstalledApps()})
}

func (s *Server) handleMacPermissions(w http.ResponseWriter, r *http.Request) {
	st := s.store.Snapshot()
	writeJSON(w, macos.InspectPermissions(s.appPath, st.Settings.ServiceMode))
}

func (s *Server) handleMacOpenSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pane string `json:"pane"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := macos.OpenSystemSettings(body.Pane); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleMacInstallApp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Relaunch bool `json:"relaunch"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	dest, err := macos.InstallToApplications(s.appPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if body.Relaunch && filepath.Clean(s.appPath) != filepath.Clean(dest) {
		go func() {
			time.Sleep(250 * time.Millisecond)
			_ = exec.Command("/usr/bin/open", "-n", "-a", dest).Start()
			time.Sleep(200 * time.Millisecond)
			if ppid := os.Getppid(); ppid > 1 {
				_ = syscall.Kill(ppid, syscall.SIGTERM)
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}()
	}
	writeJSON(w, map[string]any{"ok": true, "dest": dest})
}

func (s *Server) handleAppProxy(w http.ResponseWriter, r *http.Request) {
	var cfg store.AppProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.store.UpdateAppProxy(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"appProxy": saved, "state": s.store.Snapshot()})
}

func (s *Server) handleMetaStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.MetaRoutingStatus())
}

func (s *Server) handleMetaRefresh(w http.ResponseWriter, r *http.Request) {
	res, err := s.engine.RefreshMetaRules()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handlePowerSaver(w http.ResponseWriter, r *http.Request) {
	var cfg store.PowerSaverConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.store.UpdatePowerSaver(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"powerSaver": saved, "state": s.store.Snapshot()})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	prev := s.store.Snapshot().Settings
	var st store.Settings
	if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.store.UpdateSettings(st)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if prev.LaunchAtLogin != saved.LaunchAtLogin {
		_ = macos.SetLaunchAtLogin(saved.LaunchAtLogin, s.appPath)
	}
	writeJSON(w, map[string]any{"settings": saved, "state": s.store.Snapshot()})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"logs": s.engine.Logs()})
}

func (s *Server) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	s.engine.ClearLogs()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleStun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Server string `json:"server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	res, err := s.engine.RunStunTest(body.Server)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleOpenURL(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("missing url"))
		return
	}
	if err := macos.OpenURL(body.URL); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	incProfiles := q.Get("profiles") != "0"
	incRules := q.Get("rules") != "0"
	incSettings := q.Get("settings") != "0"
	payload := s.store.ExportBackup(incProfiles, incRules, incSettings)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="nekobox-mac-backup-%s.json"`, time.Now().Format("20060102-150405")))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func (s *Server) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var payload store.BackupPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("备份文件解析失败: %w", err))
		return
	}
	if err := s.store.ImportBackup(payload); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"state": s.store.Snapshot()})
}

func (s *Server) handleBackupReset(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ResetSettings(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"state": s.store.Snapshot()})
}

func (s *Server) handleYacd(w http.ResponseWriter, r *http.Request) {
	dir := s.engine.YacdDir()
	if _, err := os.Stat(dir); err != nil {
		http.Error(w, "MetaCubeXD dashboard assets not extracted", http.StatusNotFound)
		return
	}
	http.StripPrefix("/ui/", http.FileServer(http.Dir(dir))).ServeHTTP(w, r)
}

func (s *Server) handleClashAPIProxy(w http.ResponseWriter, r *http.Request) {
	port := s.store.Snapshot().Settings.ClashAPIPort
	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	proxy := httputil.NewSingleHostReverseProxy(target)
	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/clash-api")
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	proxy.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
}

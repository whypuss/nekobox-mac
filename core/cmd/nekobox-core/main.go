// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"nekobox-mac/internal/engine"
	"nekobox-mac/internal/server"
	"nekobox-mac/internal/store"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:19850", "local HTTP API and UI listen address")
	dataDir := flag.String("data-dir", defaultDataDir(), "persistent data directory")
	yacdZip := flag.String("yacd-zip", "", "path to bundled yacd.zip (MetaCubeXD)")
	appPath := flag.String("app-path", "/Applications/Nekobox-Mac.app", "path to Nekobox-Mac.app bundle")
	showVersion := flag.Bool("version", false, "print tri-core version info and exit")
	flag.Parse()

	st, err := store.Open(*dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	resolvedYacd := *yacdZip
	if resolvedYacd == "" {
		resolvedYacd = findBundledYacd()
	}

	eng, err := engine.New(st, *dataDir, resolvedYacd)
	if err != nil {
		log.Fatalf("init engine: %v", err)
	}

	if *showVersion {
		v := eng.Versions()
		fmt.Printf("Nekobox-Mac %s\nsing-box: %s\nXray-core: %s\nMihomo: %s\n%s (%s / %s)\n",
			v.App, v.SingBox, v.Xray, v.Mihomo, v.Go, v.Arch, v.OS)
		return
	}

	srv := server.New(st, eng, *appPath)
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}

	httpServer := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Auto-connect if configured
	if st.Snapshot().Settings.AutoConnect && st.Snapshot().SelectedProfile > 0 {
		go func() {
			time.Sleep(400 * time.Millisecond)
			_ = eng.Start(st.Snapshot().SelectedProfile)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Nekobox-Mac core listening on http://%s (data: %s)", ln.Addr().String(), *dataDir)
		if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("http server error: %v", err)
		}
	}()

	<-sigCh
	log.Println("Shutting down Nekobox-Mac core...")
	_ = eng.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./nekobox-mac-data"
	}
	return filepath.Join(home, "Library", "Application Support", "Nekobox-Mac")
}

func findBundledYacd() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "..", "Resources", "yacd.zip"),
		filepath.Join(dir, "yacd.zip"),
		filepath.Join(dir, "..", "..", "assets", "yacd.zip"),
		filepath.Join(dir, "..", "assets", "yacd.zip"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

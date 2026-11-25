// SPDX-License-Identifier: GPL-3.0-or-later
package engine

import (
	"os"
	"path/filepath"
	"testing"

	"nekobox-mac/internal/configbuilder"
	"nekobox-mac/internal/store"
)

func TestCreateBoxResolvesCacheFileInsideDataDirFromReadOnlyCwd(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	eng, err := New(st, dataDir, "")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	roDir := t.TempDir()
	if err := os.Chmod(roDir, 0o555); err != nil {
		t.Fatalf("chmod roDir: %v", err)
	}
	defer func() { _ = os.Chmod(roDir, 0o755) }()

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(roDir); err != nil {
		t.Fatalf("chdir roDir: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	// Case 1: Normal generated config from configbuilder with DataDir
	snap := st.Snapshot()
	snap.Settings.EnableClashAPI = false
	snap.Settings.MixedPort = 0
	snap.AppProxy.MetaAutoRouting = false
	profile := store.Profile{
		ID:      1,
		Name:    "test-socks",
		Type:    "socks",
		Address: "127.0.0.1",
		Port:    10808,
	}
	cfgStr, err := configbuilder.BuildSingBoxConfig(snap, profile, configbuilder.BuildOptions{
		ForTest:   false,
		EnableTUN: false,
		DataDir:   dataDir,
		AssetsDir: filepath.Join(dataDir, "assets"),
	})
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	inst, cancel, _, err := eng.createBox(cfgStr, false)
	if err != nil {
		t.Fatalf("createBox(generated): %v", err)
	}
	if err := inst.Start(); err != nil {
		cancel()
		_ = inst.Close()
		t.Fatalf("inst.Start(generated) failed in read-only cwd: %v", err)
	}
	cancel()
	_ = inst.Close()

	if _, err := os.Stat(filepath.Join(dataDir, "cache.db")); err != nil {
		t.Fatalf("expected cache.db inside dataDir: %v", err)
	}

	// Case 2: Custom full-config with relative cache.db path
	customCfg := `{
		"inbounds": [],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"experimental": {
			"cache_file": {"enabled": true, "path": "custom/cache.db"}
		}
	}`
	inst2, cancel2, _, err := eng.createBox(customCfg, false)
	if err != nil {
		t.Fatalf("createBox(custom relative cache_file): %v", err)
	}
	if err := inst2.Start(); err != nil {
		cancel2()
		_ = inst2.Close()
		t.Fatalf("inst2.Start(custom) failed in read-only cwd: %v", err)
	}
	cancel2()
	_ = inst2.Close()

	if _, err := os.Stat(filepath.Join(dataDir, "custom", "cache.db")); err != nil {
		t.Fatalf("expected custom/cache.db inside dataDir: %v", err)
	}

	// Case 3: Custom full-config with unwritable absolute cache_file path falls back to dataDir/cache.db
	roSub := filepath.Join(roDir, "sub", "cache.db")
	customROCfg := `{
		"inbounds": [],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"experimental": {
			"cache_file": {"enabled": true, "path": "` + roSub + `"}
		}
	}`
	inst3, cancel3, _, err := eng.createBox(customROCfg, false)
	if err != nil {
		t.Fatalf("createBox(custom unwritable absolute cache_file): %v", err)
	}
	if err := inst3.Start(); err != nil {
		cancel3()
		_ = inst3.Close()
		t.Fatalf("inst3.Start(unwritable fallback) failed: %v", err)
	}
	cancel3()
	_ = inst3.Close()
}

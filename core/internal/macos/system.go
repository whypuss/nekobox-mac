// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package macos

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const launchAgentLabel = "com.nekobox.mac"

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
}

// SetLaunchAtLogin installs or removes the macOS LaunchAgent plist for Nekobox-Mac.app.
func SetLaunchAtLogin(enabled bool, appPath string) error {
	plistPath := launchAgentPath()
	if !enabled {
		_ = exec.Command("/bin/launchctl", "unload", plistPath).Run()
		err := os.Remove(plistPath)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if appPath == "" {
		appPath = "/Applications/Nekobox-Mac.app"
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/open</string>
		<string>-a</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
</dict>
</plist>
`, launchAgentLabel, appPath)
	return os.WriteFile(plistPath, []byte(content), 0o644)
}

// IsLaunchAtLoginEnabled checks whether the LaunchAgent plist exists.
func IsLaunchAtLoginEnabled() bool {
	_, err := os.Stat(launchAgentPath())
	return err == nil
}

// CanUseTUN returns whether the current process has root privileges to open macOS utun interfaces.
func CanUseTUN() bool {
	return os.Geteuid() == 0
}

// SystemInfo returns macOS version, chip architecture, and TUN capability.
type SystemInfo struct {
	OSVersion string `json:"osVersion"`
	Arch      string `json:"arch"`
	ChipLabel string `json:"chipLabel"`
	IsRoot    bool   `json:"isRoot"`
	CanTUN    bool   `json:"canTun"`
}

func GetSystemInfo() SystemInfo {
	verOut, _ := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	ver := strings.TrimSpace(string(verOut))
	if ver == "" {
		ver = "macOS"
	}
	chipLabel := "Intel (x86_64)"
	if runtime.GOARCH == "arm64" {
		chipLabel = "Apple Silicon (arm64)"
	}
	return SystemInfo{
		OSVersion: "macOS " + ver,
		Arch:      runtime.GOARCH,
		ChipLabel: chipLabel,
		IsRoot:    os.Geteuid() == 0,
		CanTUN:    CanUseTUN(),
	}
}

// OpenURL opens a URL in the default macOS browser.
func OpenURL(rawURL string) error {
	return exec.Command("/usr/bin/open", rawURL).Start()
}

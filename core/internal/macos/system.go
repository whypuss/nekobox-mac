// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package macos

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const launchAgentLabel = "com.nekobox.mac"

var cachedOSVersion = sync.OnceValue(func() string {
	verOut, _ := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	ver := strings.TrimSpace(string(verOut))
	if ver == "" {
		return "macOS"
	}
	return "macOS " + ver
})

func xmlEscapeString(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

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
`, xmlEscapeString(launchAgentLabel), xmlEscapeString(appPath))
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
	chipLabel := "Intel (x86_64)"
	if runtime.GOARCH == "arm64" {
		chipLabel = "Apple Silicon (arm64)"
	}
	return SystemInfo{
		OSVersion: cachedOSVersion(),
		Arch:      runtime.GOARCH,
		ChipLabel: chipLabel,
		IsRoot:    os.Geteuid() == 0,
		CanTUN:    CanUseTUN(),
	}
}

// OpenURL opens a validated HTTP/HTTPS URL in the default macOS browser.
// Arbitrary local paths, file:// URIs, and custom schemes are rejected.
func OpenURL(rawURL string) error {
	trimmed := strings.TrimSpace(rawURL)
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return errors.New("invalid URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("disallowed URL scheme %q (only http/https permitted)", u.Scheme)
	}
	return exec.Command("/usr/bin/open", "--", u.String()).Start()
}

// ClearQuarantine strips com.apple.quarantine recursively from a writable .app bundle
// so once opened, macOS Gatekeeper never prompts or flags quarantine on subsequent launches.
func ClearQuarantine(appPath string) bool {
	if strings.TrimSpace(appPath) == "" {
		return false
	}
	if strings.HasPrefix(appPath, "/Volumes/") || strings.Contains(appPath, "/AppTranslocation/") {
		return false
	}
	if _, err := os.Stat(appPath); err != nil {
		return false
	}
	return exec.Command("/usr/bin/xattr", "-dr", "com.apple.quarantine", appPath).Run() == nil
}

// InstallToApplications copies the running .app bundle (e.g. from a mounted DMG) into
// /Applications/Nekobox-Mac.app without quarantine attributes so it launches cleanly.
func InstallToApplications(srcAppPath string) (string, error) {
	src := strings.TrimSpace(srcAppPath)
	if src == "" || !strings.HasSuffix(src, ".app") {
		return "", errors.New("未识别到有效的 .app 应用包路径")
	}
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("应用包不存在: %w", err)
	}
	dest := "/Applications/Nekobox-Mac.app"
	if filepath.Clean(src) == dest {
		_ = ClearQuarantine(dest)
		return dest, nil
	}
	_ = os.RemoveAll(dest)
	if out, err := exec.Command("/usr/bin/ditto", "--noqtn", src, dest).CombinedOutput(); err != nil {
		// Fallback to ~/Applications if /Applications requires admin
		home, _ := os.UserHomeDir()
		if home == "" {
			return "", fmt.Errorf("安装到 /Applications 失败: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		userAppsDir := filepath.Join(home, "Applications")
		_ = os.MkdirAll(userAppsDir, 0o755)
		dest = filepath.Join(userAppsDir, "Nekobox-Mac.app")
		_ = os.RemoveAll(dest)
		if out2, err2 := exec.Command("/usr/bin/ditto", "--noqtn", src, dest).CombinedOutput(); err2 != nil {
			return "", fmt.Errorf("复制应用包失败: %s (%w)", strings.TrimSpace(string(out2)), err2)
		}
	}
	_ = exec.Command("/usr/bin/xattr", "-cr", dest).Run()
	return dest, nil
}

// PermissionStatus reports real-time macOS Gatekeeper, install location,
// network proxy, local network, and TUN permission readiness.
type PermissionStatus struct {
	AppPath          string   `json:"appPath"`
	InApplications   bool     `json:"inApplications"`
	InReadOnlyVolume bool     `json:"inReadOnlyVolume"`
	HasQuarantine    bool     `json:"hasQuarantine"`
	IsSigned         bool     `json:"isSigned"`
	IsDeveloperID    bool     `json:"isDeveloperId"`
	IsRoot           bool     `json:"isRoot"`
	CanTUN           bool     `json:"canTun"`
	OSVersion        string   `json:"osVersion"`
	OSMajor          int      `json:"osMajor"`
	Arch             string   `json:"arch"`
	ChipLabel        string   `json:"chipLabel"`
	NetworkServices  []string `json:"networkServices"`
	NeedsGuide       bool     `json:"needsGuide"`
	BlockingIssues   []string `json:"blockingIssues"`
	Reasons          []string `json:"reasons"`
	QuarantineCmd    string   `json:"quarantineCmd"`
	TunLaunchCmd     string   `json:"tunLaunchCmd"`
}

func parseOSMajor(osVersion string) int {
	ver := strings.TrimSpace(strings.TrimPrefix(osVersion, "macOS"))
	parts := strings.Split(ver, ".")
	if len(parts) == 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0
	}
	return n
}

// InspectPermissions checks current macOS runtime permissions and security state.
func InspectPermissions(appPath, serviceMode string) PermissionStatus {
	si := GetSystemInfo()
	if strings.TrimSpace(appPath) == "" {
		appPath = "/Applications/Nekobox-Mac.app"
	}
	home, _ := os.UserHomeDir()
	userApps := filepath.Join(home, "Applications") + "/"

	inApps := strings.HasPrefix(appPath, "/Applications/") || strings.HasPrefix(appPath, userApps)
	inRO := strings.HasPrefix(appPath, "/Volumes/") || strings.Contains(appPath, "/AppTranslocation/")

	hasQuarantine := false
	if _, err := os.Stat(appPath); err == nil {
		if out, err := exec.Command("/usr/bin/xattr", "-p", "com.apple.quarantine", appPath).Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			// If running from a writable path, self-heal by stripping quarantine immediately.
			if !inRO && ClearQuarantine(appPath) {
				if out2, err2 := exec.Command("/usr/bin/xattr", "-p", "com.apple.quarantine", appPath).Output(); err2 == nil && len(strings.TrimSpace(string(out2))) > 0 {
					hasQuarantine = true
				}
			} else {
				// Quarantine flag bit 0x0040 (e.g. 00c1 / 01c1) means user already approved in Gatekeeper.
				qVal := strings.TrimSpace(string(out))
				fields := strings.SplitN(qVal, ";", 2)
				if len(fields) > 0 {
					if flags, parseErr := strconv.ParseUint(fields[0], 16, 32); parseErr == nil && (flags&0x40) != 0 {
						hasQuarantine = false
					} else {
						hasQuarantine = true
					}
				} else {
					hasQuarantine = true
				}
			}
		}
	}

	isSigned := false
	isDevID := false
	if _, err := os.Stat(appPath); err == nil {
		out, err := exec.Command("/usr/bin/codesign", "-dvv", appPath).CombinedOutput()
		text := string(out)
		if err == nil {
			isSigned = true
			if strings.Contains(text, "Authority=Developer ID Application:") {
				isDevID = true
			}
		}
	}

	svcs, _ := ActiveNetworkServices()
	if svcs == nil {
		svcs = []string{}
	}

	osMajor := parseOSMajor(si.OSVersion)
	var blocking []string
	var reasons []string

	if inRO {
		blocking = append(blocking, "readonly_volume")
		reasons = append(reasons, "readonly_volume")
	}
	if hasQuarantine {
		blocking = append(blocking, "quarantine")
		reasons = append(reasons, "quarantine")
	}
	if serviceMode == "tun" && !si.CanTUN {
		blocking = append(blocking, "tun_requires_admin")
		reasons = append(reasons, "tun_requires_admin")
	}
	if !isDevID {
		reasons = append(reasons, "adhoc_signature")
	}
	if osMajor >= 15 {
		reasons = append(reasons, "local_network")
	}
	reasons = append(reasons, "system_proxy")

	cmdTarget := "/Applications/Nekobox-Mac.app"
	if strings.HasSuffix(appPath, ".app") && !inRO {
		cmdTarget = appPath
	}

	return PermissionStatus{
		AppPath:          appPath,
		InApplications:   inApps,
		InReadOnlyVolume: inRO,
		HasQuarantine:    hasQuarantine,
		IsSigned:         isSigned,
		IsDeveloperID:    isDevID,
		IsRoot:           si.IsRoot,
		CanTUN:           si.CanTUN,
		OSVersion:        si.OSVersion,
		OSMajor:          osMajor,
		Arch:             si.Arch,
		ChipLabel:        si.ChipLabel,
		NetworkServices:  svcs,
		NeedsGuide:       len(blocking) > 0 || len(reasons) > 0,
		BlockingIssues:   blocking,
		Reasons:          reasons,
		QuarantineCmd:    fmt.Sprintf("xattr -dr com.apple.quarantine %q", cmdTarget),
		TunLaunchCmd:     fmt.Sprintf("sudo %q", filepath.Join(cmdTarget, "Contents", "MacOS", "Nekobox-Mac")),
	}
}

// OpenSystemSettings opens the requested macOS System Settings / Preferences pane.
func OpenSystemSettings(pane string) error {
	targets := map[string]string{
		"security":      "x-apple.systempreferences:com.apple.preference.security?General",
		"privacy":       "x-apple.systempreferences:com.apple.preference.security?Privacy",
		"local_network": "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork",
		"network":       "x-apple.systempreferences:com.apple.preference.network",
		"login_items":   "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
	}
	target, ok := targets[pane]
	if !ok {
		target = targets["security"]
	}
	return exec.Command("/usr/bin/open", target).Start()
}

// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package macos

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// InstalledApp describes a macOS .app bundle discovered on the system.
type InstalledApp struct {
	Name        string `json:"name"`
	BundleID    string `json:"bundleId"`
	ProcessName string `json:"processName"`
	Path        string `json:"path"`
	IsSystem    bool   `json:"isSystem"`
	Category    string `json:"category"` // china, overseas, other
}

var knownChinaBundlePrefixes = []string{
	"com.tencent.",
	"com.alibaba.",
	"com.taobao.",
	"com.alipay.",
	"com.netease.",
	"com.baidu.",
	"com.bytedance.",
	"com.ss.",
	"com.sina.",
	"com.wps.",
	"com.kingsoft.",
	"com.youku.",
	"com.iqiyi.",
	"com.bilibili.",
	"com.kugou.",
	"com.xunlei.",
	"com.dingtalk.",
	"com.feishu.",
	"com.larksuite.",
	"com.jd.",
	"com.meituan.",
	"com.zhihu.",
	"com.douban.",
	"com.sogou.",
	"com.360.",
	"com.xiaomi.",
	"com.huawei.",
}

var knownOverseasBundlePrefixes = []string{
	"com.google.",
	"org.chromium.",
	"com.openai.",
	"com.anthropic.",
	"ru.keepcoder.Telegram",
	"org.telegram.",
	"com.hnc.Discord",
	"com.tinyspeck.slackmacgap",
	"com.spotify.",
	"com.twitter.",
	"com.atebits.",
	"com.whatsapp.",
	"com.github.",
	"com.microsoft.VSCode",
	"com.todesktop.",
	"com.brave.",
	"org.mozilla.",
	"company.thebrowser.Browser",
	"com.linear.",
	"notion.id",
	"md.obsidian",
	"com.docker.",
	"com.raycast.",
	"com.figma.",
	"com.postmanlabs.",
}

// ListInstalledApps scans standard macOS application folders and extracts metadata from Info.plist.
func ListInstalledApps() []InstalledApp {
	home, _ := os.UserHomeDir()
	roots := []struct {
		dir      string
		isSystem bool
	}{
		{"/Applications", false},
		{filepath.Join(home, "Applications"), false},
		{"/System/Applications", true},
		{"/System/Applications/Utilities", true},
	}

	seen := map[string]bool{}
	var result []InstalledApp

	for _, root := range roots {
		entries, err := os.ReadDir(root.dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".app") {
				continue
			}
			appPath := filepath.Join(root.dir, entry.Name())
			plistPath := filepath.Join(appPath, "Contents", "Info.plist")
			if _, err := os.Stat(plistPath); err != nil {
				continue
			}
			app, ok := readAppBundle(appPath, plistPath, root.isSystem)
			if !ok || app.BundleID == "" || seen[app.BundleID] {
				continue
			}
			// Never include ourselves
			if app.BundleID == "com.nekobox.mac" {
				continue
			}
			seen[app.BundleID] = true
			result = append(result, app)
		}
	}

	slices.SortFunc(result, func(a, b InstalledApp) int {
		if a.IsSystem != b.IsSystem {
			if !a.IsSystem {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return result
}

func readAppBundle(appPath, plistPath string, isSystem bool) (InstalledApp, bool) {
	out, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", plistPath).Output()
	if err != nil {
		return InstalledApp{}, false
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		return InstalledApp{}, false
	}
	bundleID, _ := m["CFBundleIdentifier"].(string)
	execName, _ := m["CFBundleExecutable"].(string)
	displayName, _ := m["CFBundleDisplayName"].(string)
	if displayName == "" {
		displayName, _ = m["CFBundleName"].(string)
	}
	if displayName == "" {
		displayName = strings.TrimSuffix(filepath.Base(appPath), ".app")
	}
	if execName == "" {
		execName = displayName
	}

	category := "other"
	lowerID := strings.ToLower(bundleID)
	for _, p := range knownChinaBundlePrefixes {
		if strings.HasPrefix(lowerID, strings.ToLower(p)) {
			category = "china"
			break
		}
	}
	if category == "other" {
		for _, p := range knownOverseasBundlePrefixes {
			if strings.HasPrefix(lowerID, strings.ToLower(p)) {
				category = "overseas"
				break
			}
		}
	}

	return InstalledApp{
		Name:        displayName,
		BundleID:    bundleID,
		ProcessName: execName,
		Path:        appPath,
		IsSystem:    isSystem,
		Category:    category,
	}, true
}

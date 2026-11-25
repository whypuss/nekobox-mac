// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package macos

import "testing"

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.6.2-mac", "v1.6.2", 0},
		{"1.6.2-mac", "v1.6.3", -1},
		{"1.6.10", "1.6.2", 1},
		{"1.6.2", "2.0.0", -1},
		{"v1.7.0", "1.6.9-mac", 1},
	}
	for _, tc := range cases {
		if got := CompareSemver(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareSemver(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestIsAllowedUpdateURL(t *testing.T) {
	valid := []string{
		"https://github.com/whypuss/nekobox-mac/releases/download/v1.6.3/Nekobox-Mac-1.6.3-universal.dmg",
		"https://objects.githubusercontent.com/github-production-release-asset-123/test.dmg",
		"https://release-assets.githubusercontent.com/abc/test.dmg",
	}
	for _, u := range valid {
		if !IsAllowedUpdateURL(u) {
			t.Fatalf("expected valid update URL: %s", u)
		}
	}

	invalid := []string{
		"http://github.com/whypuss/nekobox-mac/releases/download/v1.6.3/test.dmg",
		"https://evil.example.com/Nekobox-Mac.dmg",
		"file:///tmp/test.dmg",
		"",
	}
	for _, u := range invalid {
		if IsAllowedUpdateURL(u) {
			t.Fatalf("expected invalid update URL to be rejected: %s", u)
		}
	}
}

func TestSelectBestDMGAsset(t *testing.T) {
	rel := &githubRelease{
		TagName: "v1.6.3",
	}
	rel.Assets = []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}{
		{Name: "Nekobox-Mac-1.6.3-arm64.dmg", Size: 40000000, BrowserDownloadURL: "https://github.com/whypuss/nekobox-mac/releases/download/v1.6.3/Nekobox-Mac-1.6.3-arm64.dmg"},
		{Name: "Nekobox-Mac-1.6.3-x64.dmg", Size: 41000000, BrowserDownloadURL: "https://github.com/whypuss/nekobox-mac/releases/download/v1.6.3/Nekobox-Mac-1.6.3-x64.dmg"},
		{Name: "Nekobox-Mac-1.6.3-universal.dmg", Size: 78000000, BrowserDownloadURL: "https://github.com/whypuss/nekobox-mac/releases/download/v1.6.3/Nekobox-Mac-1.6.3-universal.dmg"},
		{Name: "SHA256SUMS.txt", Size: 512, BrowserDownloadURL: "https://github.com/whypuss/nekobox-mac/releases/download/v1.6.3/SHA256SUMS.txt"},
	}

	asset, shaURL := selectBestDMGAsset(rel, "/nonexistent/Nekobox-Mac.app")
	if asset == nil {
		t.Fatalf("expected non-nil asset")
	}
	if shaURL == "" {
		t.Fatalf("expected non-empty SHA256SUMS.txt URL")
	}
	if asset.Arch != "arm64" && asset.Arch != "x64" {
		t.Fatalf("expected native arch dmg when binary is not universal, got %s", asset.Arch)
	}
}

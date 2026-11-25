// SPDX-License-Identifier: GPL-3.0-or-later
//go:build darwin

package macos

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultUpdateRepo = "whypuss/nekobox-mac"
)

// UpdateAsset describes a downloadable release DMG asset.
type UpdateAsset struct {
	Name        string `json:"name"`
	Arch        string `json:"arch"` // universal | arm64 | x64
	Size        int64  `json:"size"`
	DownloadURL string `json:"downloadUrl"`
}

// UpdateCheckResult is returned by /api/update/check.
type UpdateCheckResult struct {
	CurrentVersion   string       `json:"currentVersion"`
	LatestVersion    string       `json:"latestVersion"`
	LatestTag        string       `json:"latestTag"`
	HasUpdate        bool         `json:"hasUpdate"`
	ReleaseName      string       `json:"releaseName"`
	ReleaseNotes     string       `json:"releaseNotes"`
	ReleaseURL       string       `json:"releaseUrl"`
	PublishedAt      string       `json:"publishedAt"`
	Asset            *UpdateAsset `json:"asset,omitempty"`
	SHA256SumsURL    string       `json:"sha256SumsUrl,omitempty"`
	InstallTarget    string       `json:"installTarget"`
	CanInPlaceUpdate bool         `json:"canInPlaceUpdate"`
	CheckedAt        int64        `json:"checkedAt"`
}

// UpdateProgress reports real-time status of an active in-app upgrade.
type UpdateProgress struct {
	Active          bool   `json:"active"`
	Stage           string `json:"stage"` // idle | downloading | verifying | mounting | installing | relaunching | done | error
	TargetVersion   string `json:"targetVersion,omitempty"`
	AssetName       string `json:"assetName,omitempty"`
	DownloadedBytes int64  `json:"downloadedBytes"`
	TotalBytes      int64  `json:"totalBytes"`
	Percent         int    `json:"percent"`
	Message         string `json:"message,omitempty"`
	Error           string `json:"error,omitempty"`
	InstallTarget   string `json:"installTarget,omitempty"`
}

type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Assets      []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// Updater coordinates release checks and atomic in-place .app upgrades on macOS.
type Updater struct {
	repo string

	mu       sync.Mutex
	progress UpdateProgress
}

func NewUpdater(repo string) *Updater {
	if strings.TrimSpace(repo) == "" {
		repo = DefaultUpdateRepo
	}
	return &Updater{
		repo: repo,
		progress: UpdateProgress{
			Stage: "idle",
		},
	}
}

func (u *Updater) Status() UpdateProgress {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.progress
}

func (u *Updater) setProgress(fn func(*UpdateProgress)) {
	u.mu.Lock()
	fn(&u.progress)
	u.mu.Unlock()
}

// NormalizeVersion strips leading "v" and trailing suffixes like "-mac".
func NormalizeVersion(v string) string {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if idx := strings.IndexAny(s, "-+"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// CompareSemver compares two semantic version strings (e.g. "1.6.2-mac" vs "v1.6.3").
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareSemver(a, b string) int {
	pa := strings.Split(NormalizeVersion(a), ".")
	pb := strings.Split(NormalizeVersion(b), ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var ia, ib int
		if i < len(pa) {
			ia, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			ib, _ = strconv.Atoi(pb[i])
		}
		if ia < ib {
			return -1
		}
		if ia > ib {
			return 1
		}
	}
	return 0
}

// IsAllowedUpdateURL validates that a download URL belongs to GitHub official hosts over HTTPS.
func IsAllowedUpdateURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || strings.ToLower(parsed.Scheme) != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	switch host {
	case "github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com":
		return true
	default:
		return strings.HasSuffix(host, ".githubusercontent.com")
	}
}

func isUniversalBinary(appPath string) bool {
	if strings.TrimSpace(appPath) == "" {
		return false
	}
	bin := filepath.Join(appPath, "Contents", "MacOS", "Nekobox-Mac")
	out, err := exec.Command("/usr/bin/lipo", "-archs", bin).Output()
	if err != nil {
		return false
	}
	text := string(out)
	return strings.Contains(text, "arm64") && strings.Contains(text, "x86_64")
}

// ResolveInstallTarget chooses the destination .app bundle for in-place replacement.
func ResolveInstallTarget(appPath string) string {
	clean := filepath.Clean(strings.TrimSpace(appPath))
	if clean != "" && strings.HasSuffix(clean, ".app") &&
		!strings.HasPrefix(clean, "/Volumes/") &&
		!strings.Contains(clean, "/AppTranslocation/") {
		if isDirWritable(filepath.Dir(clean)) {
			return clean
		}
	}
	if isDirWritable("/Applications") {
		return "/Applications/Nekobox-Mac.app"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "Applications", "Nekobox-Mac.app")
	}
	return "/Applications/Nekobox-Mac.app"
}

func isDirWritable(dir string) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	tmp, err := os.CreateTemp(dir, ".nekobox-write-probe-*")
	if err != nil {
		return false
	}
	name := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(name)
	return true
}

func selectBestDMGAsset(rel *githubRelease, appPath string) (*UpdateAsset, string) {
	if rel == nil {
		return nil, ""
	}
	var shaURL string
	byArch := map[string]*UpdateAsset{}
	for _, a := range rel.Assets {
		lower := strings.ToLower(a.Name)
		if lower == "sha256sums.txt" {
			shaURL = a.BrowserDownloadURL
			continue
		}
		if !strings.HasSuffix(lower, ".dmg") {
			continue
		}
		arch := ""
		switch {
		case strings.Contains(lower, "-universal.dmg"):
			arch = "universal"
		case strings.Contains(lower, "-arm64.dmg"):
			arch = "arm64"
		case strings.Contains(lower, "-x64.dmg") || strings.Contains(lower, "-amd64.dmg") || strings.Contains(lower, "-x86_64.dmg"):
			arch = "x64"
		}
		if arch != "" {
			byArch[arch] = &UpdateAsset{
				Name:        a.Name,
				Arch:        arch,
				Size:        a.Size,
				DownloadURL: a.BrowserDownloadURL,
			}
		}
	}

	nativeArch := "x64"
	if runtime.GOARCH == "arm64" {
		nativeArch = "arm64"
	}

	// Prefer native architecture DMG (smaller & faster) unless current bundle is universal and native is absent,
	// or if running universal prefer native arch for fast download while universal remains fallback.
	order := []string{nativeArch, "universal"}
	if isUniversalBinary(appPath) {
		// Keep universal binary universal if universal DMG is present, unless missing.
		order = []string{"universal", nativeArch}
	}
	for _, k := range order {
		if asset, ok := byArch[k]; ok {
			return asset, shaURL
		}
	}
	for _, asset := range byArch {
		return asset, shaURL
	}
	return nil, shaURL
}

func makeUpdateHTTPClients(proxyPort int, timeout time.Duration) []*http.Client {
	direct := &http.Client{Timeout: timeout}
	clients := []*http.Client{direct}
	if proxyPort > 0 {
		proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
		if err == nil {
			proxied := &http.Client{
				Timeout: timeout,
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
			}
			// Try proxied first when local proxy is active, then fallback to direct
			clients = []*http.Client{proxied, direct}
		}
	}
	return clients
}

func doGitHubGet(ctx context.Context, rawURL string, proxyPort int, timeout time.Duration, accept string) (*http.Response, error) {
	var lastErr error
	for _, client := range makeUpdateHTTPClients(proxyPort, timeout) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Nekobox-Mac-Updater")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, lastErr
}

// Check queries GitHub Releases for the latest version of Nekobox-Mac.
func (u *Updater) Check(ctx context.Context, currentVersion, appPath string, proxyPort int) (*UpdateCheckResult, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.repo)
	resp, err := doGitHubGet(ctx, apiURL, proxyPort, 15*time.Second, "application/vnd.github+json")
	if err != nil {
		return nil, fmt.Errorf("检查更新失败: %w", err)
	}
	defer resp.Body.Close()

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析版本信息失败: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("未获取到有效版本号")
	}

	latestNorm := NormalizeVersion(rel.TagName)
	currentNorm := NormalizeVersion(currentVersion)
	hasUpdate := CompareSemver(currentNorm, latestNorm) < 0
	asset, shaURL := selectBestDMGAsset(&rel, appPath)
	installTarget := ResolveInstallTarget(appPath)

	return &UpdateCheckResult{
		CurrentVersion:   currentVersion,
		LatestVersion:    latestNorm,
		LatestTag:        rel.TagName,
		HasUpdate:        hasUpdate,
		ReleaseName:      rel.Name,
		ReleaseNotes:     rel.Body,
		ReleaseURL:       rel.HTMLURL,
		PublishedAt:      rel.PublishedAt,
		Asset:            asset,
		SHA256SumsURL:    shaURL,
		InstallTarget:    installTarget,
		CanInPlaceUpdate: asset != nil && asset.DownloadURL != "",
		CheckedAt:        time.Now().UnixMilli(),
	}, nil
}

// ApplyRequest describes the update package to download and install in-place.
type ApplyRequest struct {
	Version       string `json:"version"`
	AssetName     string `json:"assetName"`
	DownloadURL   string `json:"downloadUrl"`
	SHA256SumsURL string `json:"sha256SumsUrl"`
}

// StartApply launches an asynchronous in-place upgrade that downloads the DMG,
// verifies SHA-256 and code signature, atomically replaces Nekobox-Mac.app,
// preserves all user data in Application Support, and relaunches the new version.
func (u *Updater) StartApply(req ApplyRequest, currentVersion, appPath string, proxyPort int, beforeExit func()) error {
	u.mu.Lock()
	if u.progress.Active {
		u.mu.Unlock()
		return errors.New("已有更新任务正在进行中")
	}
	u.progress = UpdateProgress{
		Active:        true,
		Stage:         "downloading",
		TargetVersion: req.Version,
		AssetName:     req.AssetName,
		Message:       "正在准备下载安装包…",
		InstallTarget: ResolveInstallTarget(appPath),
	}
	u.mu.Unlock()

	go u.runApply(req, currentVersion, appPath, proxyPort, beforeExit)
	return nil
}

func (u *Updater) failUpdate(err error) {
	u.setProgress(func(p *UpdateProgress) {
		p.Active = false
		p.Stage = "error"
		p.Error = err.Error()
		p.Message = "更新失败：" + err.Error()
	})
}

func (u *Updater) runApply(req ApplyRequest, currentVersion, appPath string, proxyPort int, beforeExit func()) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// If caller didn't pass explicit download URL, resolve latest from GitHub first.
	if strings.TrimSpace(req.DownloadURL) == "" {
		info, err := u.Check(ctx, currentVersion, appPath, proxyPort)
		if err != nil {
			u.failUpdate(err)
			return
		}
		if info.Asset == nil || info.Asset.DownloadURL == "" {
			u.failUpdate(errors.New("最新 Release 未找到可用的 macOS DMG 安装包"))
			return
		}
		req.Version = info.LatestVersion
		req.AssetName = info.Asset.Name
		req.DownloadURL = info.Asset.DownloadURL
		req.SHA256SumsURL = info.SHA256SumsURL
	}

	if !IsAllowedUpdateURL(req.DownloadURL) {
		u.failUpdate(errors.New("拒绝非 GitHub 官方来源的更新下载地址"))
		return
	}
	if req.SHA256SumsURL != "" && !IsAllowedUpdateURL(req.SHA256SumsURL) {
		req.SHA256SumsURL = ""
	}

	destApp := ResolveInstallTarget(appPath)
	destParent := filepath.Dir(destApp)
	if err := os.MkdirAll(destParent, 0o755); err != nil {
		u.failUpdate(fmt.Errorf("无法创建安装目录 %s: %w", destParent, err))
		return
	}

	u.setProgress(func(p *UpdateProgress) {
		p.TargetVersion = req.Version
		p.AssetName = req.AssetName
		p.InstallTarget = destApp
		p.Stage = "downloading"
		p.Message = fmt.Sprintf("正在下载 %s…", req.AssetName)
	})

	tmpDir, err := os.MkdirTemp("", "nekobox-mac-update-*")
	if err != nil {
		u.failUpdate(fmt.Errorf("创建临时目录失败: %w", err))
		return
	}
	keepTmpForHelper := false
	defer func() {
		if !keepTmpForHelper {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	// 1. Download DMG with progress tracking
	dmgName := filepath.Base(req.AssetName)
	if dmgName == "" || dmgName == "." || !strings.HasSuffix(strings.ToLower(dmgName), ".dmg") {
		dmgName = "Nekobox-Mac-update.dmg"
	}
	dmgPath := filepath.Join(tmpDir, dmgName)
	actualHash, err := u.downloadFileWithProgress(ctx, req.DownloadURL, dmgPath, proxyPort)
	if err != nil {
		u.failUpdate(fmt.Errorf("下载安装包失败: %w", err))
		return
	}

	// 2. Verify SHA-256 against SHA256SUMS.txt when published
	u.setProgress(func(p *UpdateProgress) {
		p.Stage = "verifying"
		p.Percent = 100
		p.Message = "正在校验安装包 SHA-256 完整性…"
	})
	if req.SHA256SumsURL != "" {
		if expected, err := fetchExpectedSHA256(ctx, req.SHA256SumsURL, dmgName, proxyPort); err == nil && expected != "" {
			if !strings.EqualFold(expected, actualHash) {
				u.failUpdate(fmt.Errorf("SHA-256 校验失败（期望 %s，实际 %s）", expected, actualHash))
				return
			}
		}
	}
	_ = exec.Command("/usr/bin/xattr", "-cr", dmgPath).Run()

	// 3. Mount DMG quietly
	u.setProgress(func(p *UpdateProgress) {
		p.Stage = "mounting"
		p.Message = "正在挂载 DMG 镜像…"
	})
	mountPoint := filepath.Join(tmpDir, "mnt")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		u.failUpdate(err)
		return
	}
	if out, err := exec.Command("/usr/bin/hdiutil", "attach", dmgPath, "-mountpoint", mountPoint, "-nobrowse", "-noverify", "-quiet").CombinedOutput(); err != nil {
		u.failUpdate(fmt.Errorf("挂载 DMG 失败: %s (%w)", strings.TrimSpace(string(out)), err))
		return
	}
	defer func() {
		_ = exec.Command("/usr/bin/hdiutil", "detach", mountPoint, "-quiet").Run()
	}()

	srcApp := filepath.Join(mountPoint, "Nekobox-Mac.app")
	if _, err := os.Stat(srcApp); err != nil {
		// Fallback: locate first *.app inside mount point
		matches, _ := filepath.Glob(filepath.Join(mountPoint, "*.app"))
		if len(matches) == 0 {
			u.failUpdate(errors.New("DMG 镜像中未找到 Nekobox-Mac.app"))
			return
		}
		srcApp = matches[0]
	}

	// 4. Stage new app next to destination (same filesystem -> atomic rename)
	u.setProgress(func(p *UpdateProgress) {
		p.Stage = "installing"
		p.Message = "正在提取并校验新版应用（保留全部节点与配置）…"
	})
	stagedApp := destApp + ".nekobox-new"
	backupApp := destApp + ".nekobox-old"
	_ = os.RemoveAll(stagedApp)
	if out, err := exec.Command("/usr/bin/ditto", "--noqtn", srcApp, stagedApp).CombinedOutput(); err != nil {
		u.failUpdate(fmt.Errorf("复制新版应用失败（请确认 %s 可写）: %s (%w)", destParent, strings.TrimSpace(string(out)), err))
		return
	}
	_ = exec.Command("/usr/bin/xattr", "-cr", stagedApp).Run()
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", stagedApp).CombinedOutput(); err != nil {
		_ = os.RemoveAll(stagedApp)
		u.failUpdate(fmt.Errorf("新版应用签名校验未通过: %s (%w)", strings.TrimSpace(string(out)), err))
		return
	}

	// Detach DMG before launching swap helper
	_ = exec.Command("/usr/bin/hdiutil", "detach", mountPoint, "-quiet").Run()

	// 5. Prepare detached swap & relaunch helper script
	u.setProgress(func(p *UpdateProgress) {
		p.Stage = "relaunching"
		p.Message = "新版校验通过，正在原地覆盖并自动重启…"
	})

	parentPID := os.Getppid()
	selfPID := os.Getpid()
	helperPath := filepath.Join(tmpDir, "apply_update.sh")
	helperScript := `#!/bin/sh
set -u
PARENT_PID="$1"
SELF_PID="$2"
DEST="$3"
STAGED="$4"
BACKUP="$5"
TMPDIR_CLEAN="$6"

# Wait for existing Nekobox-Mac and core processes to exit cleanly (up to 15s)
i=0
while [ "$i" -lt 75 ]; do
  alive=0
  if [ "$PARENT_PID" -gt 1 ] && kill -0 "$PARENT_PID" 2>/dev/null; then
    alive=1
  fi
  if [ "$SELF_PID" -gt 1 ] && kill -0 "$SELF_PID" 2>/dev/null; then
    alive=1
  fi
  [ "$alive" -eq 0 ] && break
  sleep 0.2
  i=$((i + 1))
done

rm -rf "$BACKUP"
if [ -d "$DEST" ]; then
  if ! mv "$DEST" "$BACKUP"; then
    rm -rf "$STAGED" "$TMPDIR_CLEAN"
    exit 1
  fi
fi

if mv "$STAGED" "$DEST"; then
  rm -rf "$BACKUP"
  /usr/bin/xattr -cr "$DEST" 2>/dev/null || true
  /usr/bin/open -n -a "$DEST" >/dev/null 2>&1 || true
else
  # Roll back on swap failure
  if [ -d "$BACKUP" ]; then
    mv "$BACKUP" "$DEST" 2>/dev/null || true
  fi
fi

rm -rf "$TMPDIR_CLEAN"
`
	if err := os.WriteFile(helperPath, []byte(helperScript), 0o700); err != nil {
		_ = os.RemoveAll(stagedApp)
		u.failUpdate(fmt.Errorf("生成升级脚本失败: %w", err))
		return
	}

	cmd := exec.Command("/bin/sh", helperPath,
		strconv.Itoa(parentPID),
		strconv.Itoa(selfPID),
		destApp,
		stagedApp,
		backupApp,
		tmpDir,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(stagedApp)
		u.failUpdate(fmt.Errorf("启动升级接力进程失败: %w", err))
		return
	}
	keepTmpForHelper = true

	u.setProgress(func(p *UpdateProgress) {
		p.Stage = "done"
		p.Message = "升级已就绪，正在重启 Nekobox-Mac…"
	})

	// Give frontend a brief window to poll final "relaunching/done" status
	time.Sleep(450 * time.Millisecond)

	if beforeExit != nil {
		beforeExit()
	}

	// Gracefully terminate parent Cocoa shell and self so the swap helper can replace .app
	if parentPID > 1 {
		_ = syscall.Kill(parentPID, syscall.SIGTERM)
	}
	time.Sleep(250 * time.Millisecond)
	_ = syscall.Kill(selfPID, syscall.SIGTERM)
}

func (u *Updater) downloadFileWithProgress(ctx context.Context, rawURL, dstPath string, proxyPort int) (string, error) {
	resp, err := doGitHubGet(ctx, rawURL, proxyPort, 10*time.Minute, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	total := resp.ContentLength
	u.setProgress(func(p *UpdateProgress) {
		p.TotalBytes = total
		p.DownloadedBytes = 0
		p.Percent = 0
	})

	hasher := sha256.New()
	buf := make([]byte, 64*1024)
	var downloaded int64
	lastReport := time.Now()

	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return "", werr
			}
			_, _ = hasher.Write(buf[:n])
			downloaded += int64(n)

			if time.Since(lastReport) >= 120*time.Millisecond || rerr == io.EOF {
				lastReport = time.Now()
				pct := 0
				if total > 0 {
					pct = int((downloaded * 100) / total)
					if pct > 99 {
						pct = 99
					}
				}
				u.setProgress(func(p *UpdateProgress) {
					p.DownloadedBytes = downloaded
					p.TotalBytes = total
					p.Percent = pct
					if total > 0 {
						p.Message = fmt.Sprintf("正在下载安装包 (%d%%)…", pct)
					} else {
						p.Message = fmt.Sprintf("正在下载安装包 (%.1f MB)…", float64(downloaded)/(1024*1024))
					}
				})
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}

	if err := out.Sync(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func fetchExpectedSHA256(ctx context.Context, sumsURL, targetFilename string, proxyPort int) (string, error) {
	resp, err := doGitHubGet(ctx, sumsURL, proxyPort, 15*time.Second, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 256*1024))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == targetFilename {
			return strings.TrimSpace(fields[0]), nil
		}
	}
	return "", nil
}

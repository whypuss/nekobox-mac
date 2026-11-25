# Nekobox-Mac

[![Build & Release macOS](https://github.com/whypuss/nekobox-mac/actions/workflows/release-macos.yml/badge.svg)](https://github.com/whypuss/nekobox-mac/actions/workflows/release-macos.yml)
[![macOS 12+](https://img.shields.io/badge/macOS-12%2B%20(M%20%26%20Intel)-blue.svg)](https://github.com/whypuss/nekobox-mac/releases)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-orange.svg)](LICENSE)

专为 **macOS（Apple Silicon M 系列 + Intel x86_64）** 打造的原生三内核代理客户端，基于 [shixiaoheia/Nekobox-Next](https://github.com/shixiaoheia/Nekobox-Next) 源码完整移植并 1:1 复刻其 **Liquid Glass 3.0 液态玻璃** 与 **怀旧界面** 双风格 UI。

本项目**仅面向 macOS（macOS 12.0+）**，不包含 Windows、Linux 或 Android 平台冗余代码与构建脚本。

## 下载安装

前往 [GitHub Releases](https://github.com/whypuss/nekobox-mac/releases) 下载对应安装镜像：

| 芯片平台 | 架构标识 | 安装包说明 |
|---|---|---|
| Apple Silicon (M1/M2/M3/M4) + Intel x64 通用 | `universal` (`arm64` + `x86_64`) | `Nekobox-Mac-*-universal.dmg`（推荐，全系 Mac 通用原生） |
| Apple Silicon 独立版 | `arm64` | `Nekobox-Mac-*-arm64.dmg`（仅 M 系列芯片） |
| Intel Mac 独立版 | `x64` (`x86_64`) | `Nekobox-Mac-*-x64.dmg`（仅 Intel x64 芯片） |

### 免风险提示安装与直接打开（无需进系统设置点「强制打开」）

由于 macOS 浏览器（Safari / Chrome 等）会对所有网页下载的 `.dmg` 自动附加 `com.apple.quarantine` 隔离属性，未配置 Apple 付费公证证书（$99/年）时直接从浏览器下载拖拽打开会触发 Gatekeeper 提示。推荐任选以下方式实现**零风险提示直接打开**：

**方式 A：终端一键下载并免隔离安装（装完自动启动，全程零弹窗）**
```bash
curl -fsSL https://raw.githubusercontent.com/whypuss/nekobox-mac/main/scripts/install.sh | bash
```

**方式 B：若已手动把 DMG 拖入「应用程序」，一行命令永久解除风险提示并打开**
```bash
xattr -cr /Applications/Nekobox-Mac.app && open -a /Applications/Nekobox-Mac.app
```

> 注：软件一旦成功启动一次，内置自愈机制会自动清除包内残留的 `com.apple.quarantine` 标记；若在挂载的 DMG 中直接打开，也可点击软件弹窗内的「一键安装到应用程序并免风险启动」自动完成免隔离安装。

若要使浏览器直接下载的 `.dmg` 在任意 Mac 上无需终端即可双击零弹窗打开，可配置 Apple Developer ID Application 证书与 Apple 公证（Notarization）。本仓库构建脚本与 GitHub Actions 已原生支持：配置 `SIGN_IDENTITY`、`NOTARY_APPLE_ID`、`NOTARY_TEAM_ID`、`NOTARY_PASSWORD`（或 CI Secrets `APPLE_CERT_P12_BASE64`、`APPLE_CERT_PASSWORD`、`APPLE_SIGN_IDENTITY`、`APPLE_NOTARY_ID`、`APPLE_TEAM_ID`、`APPLE_NOTARY_PASSWORD`）即可自动完成 Hardened Runtime 签名、公证与票据装订（Staple）。

## 核心特性

- **原生三内核融合（直接复用 Nekobox-Next 核心代码）**
  - **sing-box `v1.14.4`**：主代理引擎、FakeDNS、IPv6 双栈（默认开启，支持四态切换）、`boxconfig.Normalize` 自动兼容 1.8–1.14 历史配置、Hysteria 2 `pinSHA256`。
  - **Xray-core `v26.11.9`**：通过 `xraybridge` 原生承接 XHTTP、mKCP、VLESS Encryption、FinalMask、REALITY 等特性。
  - **Mihomo (Clash.Meta) `v1.19.34`**：通过 `mihomobridge` 原生承接 AmneziaWG、ShadowsocksR、MASQUE（H3/H2/usque）、Mieru、Snell、TrustTunnel、Sudoku、ShadowQUIC，以及内置 17 套 `.mrs` 规则集的 Meta 智能分流 + `mihomo-dns`（支持 MetaCubeX / DustinWin 双规则源与绕过大陆 / GFW 精简模式）。
  - **内置 MetaCubeXD Web 面板 `v1.276.0`**：侧边栏「面板」一键查看实时连接与流量。
- **1:1 复刻 Nekobox-Next UI**
  - **Liquid Glass 3.0 液态玻璃界面（默认）**：三层双倒角液态玻璃卡片、主题色环境流光底色（0~5 档实时预览）、液态果冻物理触控回弹与 3D 微倾、毛玻璃弹窗模糊（0~5 档）、左侧抽屉导航、悬浮胶囊顶栏、分组标签栏、底部悬浮状态栏与右下角「纸飞机 / 盒中猫」一键连接 FAB。
  - **1:1 怀旧界面**：抽屉菜单一键秒切回原版 NekoBox 实色顶栏与经典卡片，完整支持全部 **21 套主题色**（默认樱花粉 `#fb7299`）与浅色 / 深色 / AMOLED 纯黑模式。
- **macOS 原生系统集成（无 Electron）**
  - 原生 Objective-C (`AppKit` + `WebKit`) 外壳 + 顶栏极简单色「盒中猫」`NSStatusItem` 菜单栏图标。
  - `networksetup` 自动配置与退出清理 HTTP/HTTPS/SOCKS5 系统代理，支持 TUN 虚拟网卡与仅本地混合端口模式。
  - 扫描本机 `/Applications`、`/System/Applications`、`~/Applications` 实现 macOS 分应用三态控制（默认分流 / 绕过直连 / 强制代理，对接 `process_name`）。
  - 监听 macOS 休眠与唤醒通知，联动 `box.Sleep()` / `box.Wake()` 与省电开关页面。
  - 支持 `LaunchAgent` 开机自启。

## 本地构建与 GitHub Actions 流水线

依赖：macOS 12+、Command Line Tools (`clang` / `lipo` / `codesign` / `iconutil` / `hdiutil`)、Go 1.27+。

```bash
# 编译 Universal 通用版 .app（同时包含 arm64 与 x86_64）
make universal

# 打包 Universal / arm64 / x64 三份 DMG 安装镜像
make dmg-all

# 运行三内核单元测试
make test
```

GitHub Actions（`.github/workflows/release-macos.yml`）仅运行于 `macos-latest` runner，推送 `main` 时自动执行单元测试并构建三架构 DMG Artifacts；推送 `v*` 标签时自动校验并发布 GitHub Release。

## 开源协议

本项目遵循 **GNU General Public License v3.0 (GPL-3.0)** 开源协议，基于并致敬 [shixiaoheia/Nekobox-Next](https://github.com/shixiaoheia/Nekobox-Next) 与 [MatsuriDayo/NekoBoxForAndroid](https://github.com/MatsuriDayo/NekoBoxForAndroid)。

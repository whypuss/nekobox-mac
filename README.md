# Nekobox-Mac

专为 **macOS（Apple Silicon M 系列 + Intel x86_64 通用二进制）** 打造的原生三内核代理客户端，基于 [shixiaoheia/Nekobox-Next](https://github.com/shixiaoheia/Nekobox-Next) 源码完整移植并 1:1 复刻其 **Liquid Glass 3.0 液态玻璃** 与 **怀旧界面** 双风格 UI。

本项目**仅面向 macOS（macOS 12.0+）**，不包含 Windows、Linux 或 Android 平台冗余代码与构建脚本。

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

## 支持架构

| 芯片平台 | 架构标识 | 产物说明 |
|---|---|---|
| Apple Silicon (M1/M2/M3/M4) + Intel 通用 | `universal` (`arm64` + `x86_64`) | 默认构建，一份 `.app` / `.dmg` 通用于所有 Mac |
| Apple Silicon 独立版 | `arm64` | 仅包含 M 系列芯片原生指令 |
| Intel Mac 独立版 | `amd64` (`x86_64`) | 仅包含 Intel 芯片原生指令 |

## 构建与打包

依赖：macOS 12+、Command Line Tools (`clang` / `lipo` / `codesign` / `iconutil` / `hdiutil`)、Go 1.27+。

```bash
# 1. 编译 Universal 通用版 .app（同时包含 arm64 与 x86_64）
make universal

# 2. 打包通用版 .dmg 安装镜像
make dmg

# 3. 单独构建 Apple Silicon (M系列) 或 Intel 版本
make arm64
make amd64

# 4. 运行核心单元测试
make test
```

产物输出路径：
- 应用包：`build/Nekobox-Mac.app`
- 安装镜像：`dist/Nekobox-Mac-1.6.1-universal.dmg`

## 开源协议

本项目遵循 **GNU General Public License v3.0 (GPL-3.0)** 开源协议，基于并致敬 [shixiaoheia/Nekobox-Next](https://github.com/shixiaoheia/Nekobox-Next) 与 [MatsuriDayo/NekoBoxForAndroid](https://github.com/MatsuriDayo/NekoBoxForAndroid)。

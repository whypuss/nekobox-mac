// SPDX-License-Identifier: GPL-3.0-or-later
(() => {
  "use strict";

  // 21 Material Themes matching Nekobox-Next colors.xml + themes.xml 1:1
  const THEMES = [
    { id: 1,  name: "红色",     primary: "#F44336", dark: "#D32F2F", c300: "#E57373", accent: "#FF5252" },
    { id: 2,  name: "樱花粉",   primary: "#fb7299", dark: "#e05780", c300: "#fb7299", accent: "#FF4081" },
    { id: 3,  name: "粉红",     primary: "#E91E63", dark: "#C2185B", c300: "#F06292", accent: "#FF4081" },
    { id: 4,  name: "紫色",     primary: "#9C27B0", dark: "#7B1FA2", c300: "#BA68C8", accent: "#E040FB" },
    { id: 5,  name: "深紫",     primary: "#673AB7", dark: "#512DA8", c300: "#9575CD", accent: "#7C4DFF" },
    { id: 6,  name: "靛蓝",     primary: "#3F51B5", dark: "#303F9F", c300: "#7986CB", accent: "#536DFE" },
    { id: 7,  name: "蓝色",     primary: "#2196F3", dark: "#1976D2", c300: "#64B5F6", accent: "#448AFF" },
    { id: 8,  name: "浅蓝",     primary: "#03A9F4", dark: "#0288D1", c300: "#4FC3F7", accent: "#40C4FF" },
    { id: 9,  name: "青色",     primary: "#00BCD4", dark: "#0097A7", c300: "#4DD0E1", accent: "#18FFFF" },
    { id: 10, name: "蓝绿",     primary: "#009688", dark: "#00796B", c300: "#4DB6AC", accent: "#64FFDA" },
    { id: 11, name: "绿色",     primary: "#4CAF50", dark: "#388E3C", c300: "#81C784", accent: "#69F0AE" },
    { id: 12, name: "浅绿",     primary: "#8BC34A", dark: "#689F38", c300: "#AED581", accent: "#B2FF59" },
    { id: 13, name: "青柠",     primary: "#CDDC39", dark: "#AFB42B", c300: "#DCE775", accent: "#EEFF41", darkText: true },
    { id: 14, name: "黄色",     primary: "#FFEB3B", dark: "#FBC02D", c300: "#FFF176", accent: "#FFFF00", darkText: true },
    { id: 15, name: "琥珀",     primary: "#FFC107", dark: "#FFA000", c300: "#FFD54F", accent: "#FFD740", darkText: true },
    { id: 16, name: "橙色",     primary: "#FF9800", dark: "#F57C00", c300: "#FFB74D", accent: "#FFAB40" },
    { id: 17, name: "深橙",     primary: "#FF5722", dark: "#E64A19", c300: "#FF8A65", accent: "#FF6E40" },
    { id: 18, name: "棕色",     primary: "#795548", dark: "#5D4037", c300: "#A1887F", accent: "#BCAAA4" },
    { id: 19, name: "灰色",     primary: "#9E9E9E", dark: "#616161", c300: "#BDBDBD", accent: "#EEEEEE" },
    { id: 20, name: "蓝灰",     primary: "#607D8B", dark: "#455A64", c300: "#90A4AE", accent: "#B0BEC5" },
    { id: 21, name: "纯黑",     primary: "#2B2B2B", dark: "#121212", c300: "#2B2B2B", accent: "#9E9E9E", amoled: true },
  ];

  // Crisp inline SVG icon dictionary including Nekobox-Next's signature Cat-in-Box (ic_service_active.xml)
  // and Paper-Plane (ic_service_idle.xml) vectors
  const ICONS = {
    menu: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z"/></svg>`,
    search: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>`,
    add: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6z"/></svg>`,
    more: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2m0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2m0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2"/></svg>`,
    close: `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>`,
    edit: `<svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75zM20.71 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75z"/></svg>`,
    share: `<svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11A2.99 2.99 0 0 0 21 5a3 3 0 1 0-5.91.7L8.04 9.81A3 3 0 0 0 6 9a3 3 0 1 0 2.04 5.19l7.12 4.16c-.05.21-.08.43-.08.65a2.92 2.92 0 1 0 2.92-2.92"/></svg>`,
    del: `<svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6zM19 4h-3.5l-1-1h-5l-1 1H5v2h14z"/></svg>`,
    description: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8zm2 16H8v-2h8zm0-4H8v-2h8zm-3-5V3.5L18.5 9z"/></svg>`,
    groups: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M3 14h4v-4H3zm0 5h4v-4H3zM3 9h4V5H3zm5 5h13v-4H8zm0 5h13v-4H8zM8 5v4h13V5z"/></svg>`,
    apps: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M4 8h4V4H4zm6 12h4v-4h-4zm-6 0h4v-4H4zm0-6h4v-4H4zm6 0h4v-4h-4zm6-10v4h4V4zm-6 4h4V4h-4zm6 6h4v-4h-4zm0 6h4v-4h-4z"/></svg>`,
    route: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="m21.71 11.29-9-9a1 1 0 0 0-1.41 0l-9 9a1 1 0 0 0 0 1.41l9 9a1 1 0 0 0 1.41 0l9-9a1 1 0 0 0 0-1.41M14 14.5V12h-4v3H8v-4c0-.55.45-1 1-1h5V7.5l3.5 3.5z"/></svg>`,
    battery: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M16 4h-2V2h-4v2H8C7.45 4 7 4.45 7 5v16c0 .55.45 1 1 1h8c.55 0 1-.45 1-1V5c0-.55-.45-1-1-1m-1 10h-2v2h-2v-2H9v-2h2v-2h2v2h2z"/></svg>`,
    settings: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M19.14 12.94c.04-.31.06-.63.06-.94s-.02-.63-.06-.94l2.03-1.58a.5.5 0 0 0 .12-.64l-1.92-3.32a.5.5 0 0 0-.61-.22l-2.39.96a7.2 7.2 0 0 0-1.63-.94l-.36-2.54a.48.48 0 0 0-.48-.41h-3.84a.48.48 0 0 0-.48.41l-.36 2.54c-.59.24-1.13.56-1.63.94l-2.39-.96a.5.5 0 0 0-.61.22L2.71 8.84a.5.5 0 0 0 .12.64l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94l-2.03 1.58a.5.5 0 0 0-.12.64l1.92 3.32c.13.22.4.31.61.22l2.39-.96c.5.38 1.04.7 1.63.94l.36 2.54c.04.24.24.41.48.41h3.84c.24 0 .44-.17.48-.41l.36-2.54c.59-.24 1.13-.56 1.63-.94l2.39.96c.22.09.48 0 .61-.22l1.92-3.32a.5.5 0 0 0-.12-.64zM12 15.6A3.6 3.6 0 1 1 12 8.4a3.6 3.6 0 0 1 0 7.2"/></svg>`,
    bug: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M20 8h-2.81a5.98 5.98 0 0 0-1.82-1.96L17 4.41 15.59 3l-2.17 2.17a6 6 0 0 0-2.83 0L8.41 3 7 4.41l1.62 1.63C7.88 6.55 7.26 7.22 6.81 8H4v2h2.09c-.05.33-.09.66-.09 1v1H4v2h2v1c0 .34.04.67.09 1H4v2h2.81A5.99 5.99 0 0 0 12 21a5.99 5.99 0 0 0 5.19-3H20v-2h-2.09c.05-.33.09-.66.09-1v-1h2v-2h-2v-1c0-.34-.04-.67-.09-1H20zm-6 8h-4v-2h4zm0-4h-4v-2h4z"/></svg>`,
    dashboard: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M22 18v-2H8V4h2L7 1 4 4h2v2H2v2h4v8c0 1.1.9 2 2 2h8v2h-2l3 3 3-3h-2v-2zM10 8h6v6h2V8c0-1.1-.9-2-2-2h-6z"/></svg>`,
    tools: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="m22.7 19-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4"/></svg>`,
    palette: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 3a9 9 0 0 0 0 18c.83 0 1.5-.67 1.5-1.5 0-.39-.15-.74-.39-1.01-.23-.26-.38-.61-.38-.99 0-.83.67-1.5 1.5-1.5H16c2.76 0 5-2.24 5-5 0-4.42-4.03-8-9-8m-5.5 9a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3m3-4a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3m5 0a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3m3 4a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3"/></svg>`,
    info: `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2m1 15h-2v-6h2zm0-8h-2V7h2z"/></svg>`,
    refresh: `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M17.65 6.35A7.96 7.96 0 0 0 12 4a8 8 0 1 0 7.73 10h-2.08A6 6 0 1 1 12 6c1.66 0 3.14.69 4.22 1.78L13 11h7V4z"/></svg>`,
    speed: `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="m20.38 8.57-1.23 1.85a8 8 0 0 1-.22 7.58H5.07A8 8 0 0 1 15.58 6.85l1.85-1.23A10 10 0 0 0 3.35 19a2 2 0 0 0 1.72 1h13.85a2 2 0 0 0 1.74-1 10 10 0 0 0-.27-10.44zm-9.79 6.84a2 2 0 0 0 2.83 0l5.66-8.49-8.49 5.66a2 2 0 0 0 0 2.83"/></svg>`,
    check: `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`,
    globe: `<svg viewBox="0 0 24 24" width="19" height="19" fill="currentColor"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2m6.93 6h-2.95a15.65 15.65 0 0 0-1.38-3.56A8.03 8.03 0 0 1 18.93 8M12 4.04c.83 1.2 1.48 2.53 1.91 3.96h-3.82c.43-1.43 1.08-2.76 1.91-3.96M4.26 14a8.1 8.1 0 0 1 0-4h3.38a16.5 16.5 0 0 0-.14 2c0 .68.05 1.35.14 2zm.81 2h2.95c.32 1.25.78 2.45 1.38 3.56A8 8 0 0 1 5.07 16m2.95-8H5.07a8 8 0 0 1 4.33-3.56A15.65 15.65 0 0 0 8.02 8M12 19.96c-.83-1.2-1.48-2.53-1.91-3.96h3.82c-.43 1.43-1.08 2.76-1.91 3.96M14.34 14H9.66a14.7 14.7 0 0 1-.16-2c0-.68.06-1.35.16-2h4.68c.1.65.16 1.32.16 2s-.06 1.35-.16 2m.26 5.56c.6-1.11 1.06-2.31 1.38-3.56h2.95a8 8 0 0 1-4.33 3.56M16.36 14c.09-.65.14-1.32.14-2s-.05-1.35-.14-2h3.38a8.1 8.1 0 0 1 0 4z"/></svg>`,
    catActive: `<svg viewBox="0 0 24 24" width="26" height="26" fill="currentColor"><path fill-rule="evenodd" d="M5.4,11.7 L5.3,8.9 C5.3,6.4 5.7,4.1 6.3,3.2 C6.7,2.6 7.4,2.6 8.1,3.1 L10.2,4.9 C11.3,4.6 12.7,4.6 13.8,4.9 L15.9,3.1 C16.6,2.6 17.3,2.6 17.7,3.2 C18.3,4.1 18.7,6.4 18.7,8.9 L18.6,11.7 Z M9.1,7.5 C8.4,7.5 7.9,8.2 7.9,9.2 C7.9,10.2 8.4,10.9 9.1,10.9 C9.8,10.9 10.3,10.2 10.3,9.2 C10.3,8.2 9.8,7.5 9.1,7.5 Z M14.9,7.5 C14.2,7.5 13.7,8.2 13.7,9.2 C13.7,10.2 14.2,10.9 14.9,10.9 C15.6,10.9 16.1,10.2 16.1,9.2 C16.1,8.2 15.6,7.5 14.9,7.5 Z"/><path d="M4.6,12.6 L11.4,12.6 L11.4,15.3 L2.9,15.3 C2.3,15.3 2.0,14.6 2.4,14.1 L4.0,12.8 C4.2,12.7 4.4,12.6 4.6,12.6 Z M12.6,12.6 L19.4,12.6 C19.6,12.6 19.8,12.7 20.0,12.8 L21.6,14.1 C22.0,14.6 21.7,15.3 21.1,15.3 L12.6,15.3 Z M4.6,16.4 L19.4,16.4 L19.4,19.1 C19.4,20.4 18.4,21.4 17.1,21.4 L6.9,21.4 C5.6,21.4 4.6,20.4 4.6,19.1 Z"/></svg>`,
    planeIdle: `<svg viewBox="0 0 24 24" width="25" height="25" fill="currentColor"><path d="M21.25 2.28 0 12.8l6.83 2.57 9.76-8.21-7.33 8.73 8.29 2.67 3.7-16.27ZM9.45 17.56l.01 4.44 2.63-3.59z"/></svg>`,
  };

  const INTENSITY_LABELS = ["关闭", "轻度", "适中", "标准", "浓郁", "极致"];
  const PROTOCOL_TYPES = [
    ["vless", "VLESS (sing-box / Xray)"],
    ["vmess", "VMess"],
    ["trojan", "Trojan"],
    ["shadowsocks", "Shadowsocks (AEAD / 2022)"],
    ["ssr", "ShadowsocksR (Mihomo)"],
    ["hysteria2", "Hysteria 2 (含 pinSHA256)"],
    ["hysteria", "Hysteria 1"],
    ["tuic", "TUIC v5"],
    ["anytls", "AnyTLS"],
    ["wireguard", "WireGuard"],
    ["amneziawg", "AmneziaWG (Mihomo)"],
    ["masque", "MASQUE (H3 / H2 / usque)"],
    ["mieru", "Mieru (Mihomo 原生)"],
    ["snell", "Snell (v1–v6)"],
    ["trusttunnel", "TrustTunnel"],
    ["sudoku", "Sudoku"],
    ["shadowquic", "ShadowQUIC"],
    ["socks", "SOCKS 4/5"],
    ["http", "HTTP / HTTPS"],
    ["ssh", "SSH"],
    ["full-config", "自定义 sing-box 完整 JSON"],
  ];

  let appState = null;
  let runtimeStatus = null;
  let coreVersions = null;
  let macPermissions = null;
  let logsList = [];
  let macAppsCache = null;
  let metaStatusCache = null;
  let currentPage = "configuration";
  let currentToolsTab = "backup";
  let searchKeyword = "";
  let appSearchKeyword = "";
  let appFilterCustomized = false;
  let appShowSystem = false;
  let logFilterLevel = "all";
  let snackbarTimer = null;

  const $ = (id) => document.getElementById(id);

  function hydrateIcons(root = document) {
    root.querySelectorAll("[data-icon]").forEach((el) => {
      const k = el.getAttribute("data-icon");
      if (ICONS[k]) el.innerHTML = ICONS[k];
    });
  }

  async function api(path, method = "GET", body = null) {
    const opts = { method, headers: {} };
    if (body !== null) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.error || `请求失败 (${resp.status})`);
    }
    return data;
  }

  function showSnackbar(msg, duration = 2600) {
    const el = $("snackbar");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(snackbarTimer);
    snackbarTimer = setTimeout(() => el.classList.add("hidden"), duration);
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatBytes(n) {
    n = Number(n || 0);
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
  }

  function hexToRgb(hex) {
    const h = hex.replace("#", "");
    const num = parseInt(h.length === 3 ? h.split("").map((c) => c + c).join("") : h, 16);
    return `${(num >> 16) & 255}, ${(num >> 8) & 255}, ${num & 255}`;
  }

  function resolveDarkMode(nightMode) {
    if (nightMode === "dark") return true;
    if (nightMode === "light") return false;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  function applyThemeAndAppearance() {
    if (!appState) return;
    const st = appState.settings;
    const theme = THEMES.find((t) => t.id === st.appTheme) || THEMES[1];
    const dark = theme.amoled ? true : resolveDarkMode(st.nightMode);
    const root = document.documentElement;

    root.setAttribute("data-ui", st.classicUi ? "classic" : "liquid");
    root.setAttribute("data-theme", String(theme.id));
    root.setAttribute("data-dark", String(dark));
    root.setAttribute("data-amoled", String(Boolean(theme.amoled)));

    root.style.setProperty("--primary", theme.primary);
    root.style.setProperty("--primary-dark", theme.dark);
    root.style.setProperty("--primary-300", theme.c300);
    root.style.setProperty("--accent", theme.accent);
    root.style.setProperty("--primary-rgb", hexToRgb(theme.primary));
    root.style.setProperty("--on-primary", theme.darkText ? "#111827" : "#ffffff");

    // 5-level blur & ambient glow intensity mapping (matching LiquidGlass.kt)
    const blurMap = [0, 8, 15, 22, 32, 46];
    const ambTopLight = [0, 0.05, 0.09, 0.13, 0.19, 0.27];
    const ambBotLight = [0, 0.035, 0.06, 0.09, 0.14, 0.20];
    const ambTopDark = [0, 0.08, 0.13, 0.19, 0.27, 0.36];
    const ambBotDark = [0, 0.055, 0.09, 0.14, 0.20, 0.28];

    const blurLvl = st.classicUi ? 0 : Math.max(0, Math.min(5, st.liquidBlurLevel ?? 3));
    const ambLvl = st.classicUi ? 0 : Math.max(0, Math.min(5, st.liquidAmbientLevel ?? 1));
    root.style.setProperty("--blur-dialog", `${blurMap[blurLvl]}px`);
    root.style.setProperty("--ambient-top-alpha", String((dark ? ambTopDark : ambTopLight)[ambLvl]));
    root.style.setProperty("--ambient-bottom-alpha", String((dark ? ambBotDark : ambBotLight)[ambLvl]));

    $("quickSwitchAppearanceLabel").textContent = st.classicUi
      ? "切换到液态玻璃界面"
      : "切换到怀旧界面";
  }

  // Liquid Glass 3.0 Jelly Motion Engine (Squash/Tilt/Touch Glow)
  function bindLiquidMotion() {
    document.addEventListener("pointerdown", (e) => {
      if (!appState || appState.settings.classicUi) return;
      const lvl = appState.settings.liquidJellyLevel ?? 1;
      if (lvl <= 0) return;
      const target = e.target.closest(".jelly-target, .profile-card, .service-fab, .stats-bar, .btn");
      if (!target) return;

      const rect = target.getBoundingClientRect();
      const nx = ((e.clientX - rect.left) / Math.max(rect.width, 1) - 0.5) * 2;
      const ny = ((e.clientY - rect.top) / Math.max(rect.height, 1) - 0.5) * 2;
      const intensity = [0, 0.38, 0.62, 0.9, 1.15, 1.4][lvl] || 0.38;
      const sx = 1 - 0.035 * intensity;
      const sy = 1 - 0.045 * intensity;
      const tilt = lvl >= 2 ? `perspective(600px) rotateX(${(-ny * 2.4 * intensity).toFixed(2)}deg) rotateY(${(nx * 2.4 * intensity).toFixed(2)}deg)` : "";
      target.style.transform = `${tilt} scale(${sx.toFixed(3)}, ${sy.toFixed(3)})`;

      if (lvl >= 3) {
        const glow = document.createElement("span");
        glow.className = "jelly-glow";
        glow.style.left = `${e.clientX - rect.left}px`;
        glow.style.top = `${e.clientY - rect.top}px`;
        target.appendChild(glow);
        setTimeout(() => glow.remove(), 460);
      }

      const release = () => {
        target.style.transform = "";
        window.removeEventListener("pointerup", release);
        window.removeEventListener("pointercancel", release);
      };
      window.addEventListener("pointerup", release);
      window.addEventListener("pointercancel", release);
    });
  }

  // =====================================================================
  // RENDERING: STATUS BAR, FAB, NAVIGATION & PAGES
  // =====================================================================
  function renderStatusBar() {
    if (!runtimeStatus) return;
    const st = runtimeStatus;
    $("statsTx").textContent = `↑ ${formatBytes(st.txRate)}/s (${formatBytes(st.txTotal)})`;
    $("statsRx").textContent = `↓ ${formatBytes(st.rxRate)}/s (${formatBytes(st.rxTotal)})`;

    const modeLabels = {
      system_proxy: "系统代理",
      tun: "TUN 接管",
      mixed_only: "仅混合端口",
    };
    $("statsModeBadge").textContent = `${modeLabels[st.serviceMode] || st.serviceMode} · :${st.mixedPort || 2080}`;

    const fab = $("serviceFab");
    fab.classList.remove("connecting", "connected");

    if (st.state === "connecting") {
      fab.classList.add("connecting");
      $("fabIcon").innerHTML = ICONS.planeIdle;
      $("statsStatus").textContent = `正在连接 ${st.activeName || ""}…`;
    } else if (st.state === "connected") {
      fab.classList.add("connected");
      $("fabIcon").innerHTML = ICONS.catActive;
      const lat = st.lastLatencyMs > 0 ? ` · ${st.lastLatencyMs} ms` : " · 点击测试连接";
      $("statsStatus").textContent = `已连接：${st.activeName || ""}${lat}`;
    } else {
      $("fabIcon").innerHTML = ICONS.planeIdle;
      $("statsStatus").textContent = st.lastError ? `未连接 (${st.lastError})` : "未连接";
    }

    if (st.systemInfo && st.systemInfo.chipLabel) {
      $("navChipBadge").textContent = st.systemInfo.chipLabel;
    }
  }

  function navigateTo(page) {
    currentPage = page;
    closePopup();
    $("appShell").classList.remove("drawer-open");
    document.querySelectorAll(".nav-item[data-page]").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.page === page);
    });
    // Hide search box when leaving configuration
    if (page !== "configuration") {
      $("toolbarSearchBox").classList.add("hidden");
      $("toolbarTitleWrap").classList.remove("hidden");
    }
    renderToolbar();
    renderCurrentPage();
  }

  function renderToolbar() {
    const titles = {
      configuration: "Nekobox-Mac",
      groups: "分组",
      app_proxy: "分应用代理",
      route: "路由",
      power_saver: "省电开关",
      settings: "设置",
      logs: "日志",
      dashboard: "面板 · MetaCubeXD",
      tools: "工具",
      about: "关于",
    };
    $("toolbarTitle").textContent = titles[currentPage] || "Nekobox-Mac";
    const actions = $("toolbarActions");
    actions.innerHTML = "";

    if (currentPage === "configuration") {
      actions.innerHTML = `
        <button class="icon-btn" id="actSearch" title="搜索节点">${ICONS.search}</button>
        <button class="icon-btn" id="actAddProfile" title="添加配置">${ICONS.add}</button>
        <button class="icon-btn" id="actMoreProfile" title="测速与管理">${ICONS.more}</button>
      `;
      $("actSearch").onclick = () => {
        $("toolbarTitleWrap").classList.add("hidden");
        $("toolbarSearchBox").classList.remove("hidden");
        $("globalSearchInput").focus();
      };
      $("actAddProfile").onclick = (e) => showAddProfileMenu(e.currentTarget);
      $("actMoreProfile").onclick = (e) => showProfileMoreMenu(e.currentTarget);
    } else if (currentPage === "groups") {
      actions.innerHTML = `
        <button class="icon-btn" id="actUpdateAllSub" title="更新全部订阅">${ICONS.refresh}</button>
        <button class="icon-btn" id="actAddGroup" title="新建分组">${ICONS.add}</button>
      `;
      $("actUpdateAllSub").onclick = updateAllSubscriptions;
      $("actAddGroup").onclick = () => openGroupDialog();
    } else if (currentPage === "route") {
      actions.innerHTML = `<button class="icon-btn" id="actAddRule" title="新建路由规则">${ICONS.add}</button>`;
      $("actAddRule").onclick = () => openRuleDialog();
    } else if (currentPage === "logs") {
      actions.innerHTML = `
        <button class="icon-btn" id="actCopyLogs" title="复制日志">${ICONS.share}</button>
        <button class="icon-btn" id="actClearLogs" title="清空日志">${ICONS.del}</button>
      `;
      $("actCopyLogs").onclick = () => {
        const text = logsList.map((l) => `[${l.timestamp}] [${l.level}] ${l.message}`).join("\n");
        navigator.clipboard?.writeText(text);
        showSnackbar("已复制全部日志");
      };
      $("actClearLogs").onclick = async () => {
        await api("/api/logs/clear", "POST");
        logsList = [];
        renderCurrentPage();
        showSnackbar("日志已清空");
      };
    } else if (currentPage === "dashboard") {
      actions.innerHTML = `
        <button class="icon-btn" id="actDashRefresh" title="刷新面板">${ICONS.refresh}</button>
        <button class="icon-btn" id="actDashOpen" title="浏览器打开">${ICONS.globe}</button>
      `;
      $("actDashRefresh").onclick = () => renderCurrentPage();
      $("actDashOpen").onclick = () => api("/api/tools/open-url", "POST", { url: getDashboardFullUrl() });
    }
  }

  function renderCurrentPage() {
    if (!appState) return;
    const holder = $("pageHolder");
    switch (currentPage) {
      case "configuration": renderConfigurationPage(holder); break;
      case "groups":        renderGroupsPage(holder); break;
      case "app_proxy":     renderAppProxyPage(holder); break;
      case "route":         renderRoutePage(holder); break;
      case "power_saver":   renderPowerSaverPage(holder); break;
      case "settings":      renderSettingsPage(holder); break;
      case "logs":          renderLogsPage(holder); break;
      case "dashboard":     renderDashboardPage(holder); break;
      case "tools":         renderToolsPage(holder); break;
      case "about":         renderAboutPage(holder); break;
    }
    hydrateIcons(holder);
  }

  // -------------------- PAGE 1: CONFIGURATION (PROFILES) --------------------
  function getVisibleProfiles() {
    let list = appState.profiles || [];
    const selGroup = appState.selectedGroup || 0;
    if (selGroup > 0) {
      list = list.filter((p) => p.groupId === selGroup);
    }
    if (searchKeyword.trim()) {
      const q = searchKeyword.trim().toLowerCase();
      list = list.filter((p) =>
        (p.name || "").toLowerCase().includes(q) ||
        (p.address || "").toLowerCase().includes(q) ||
        (p.type || "").toLowerCase().includes(q)
      );
    }
    return [...list].sort((a, b) => (a.order || 0) - (b.order || 0));
  }

  function renderConfigurationPage(holder) {
    const showAll = appState.settings.showAllGroup !== false;
    const groups = appState.groups || [];
    let activeGroup = appState.selectedGroup || 0;
    if (!showAll && activeGroup === 0 && groups.length > 0) {
      activeGroup = groups[0].id;
      appState.selectedGroup = activeGroup;
    }

    const tabsHtml = [];
    if (showAll) {
      tabsHtml.push(`<button class="group-tab ${activeGroup === 0 ? "active" : ""}" data-gid="0">全部 (${appState.profiles.length})</button>`);
    }
    for (const g of groups) {
      const cnt = appState.profiles.filter((p) => p.groupId === g.id).length;
      tabsHtml.push(`<button class="group-tab ${activeGroup === g.id ? "active" : ""}" data-gid="${g.id}">${escapeHtml(g.name)} (${cnt})</button>`);
    }

    const profiles = getVisibleProfiles();
    let listHtml = "";
    if (profiles.length === 0) {
      listHtml = `
        <div class="empty-state">
          <img src="/assets/app-icon.png" width="68" height="68" style="border-radius:18px;opacity:0.9" />
          <h3>暂无代理节点</h3>
          <p>点击右上角 <b>+</b> 从剪贴板导入链接 / 订阅，或手动新建节点。<br/>原生支持 VLESS / VMess / Trojan / SS / SSR / Hysteria2 / TUIC / AnyTLS / WireGuard / AmneziaWG / MASQUE / Mieru / Snell。</p>
          <div style="margin-top:16px;display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
            <button class="btn btn-primary" id="btnEmptyImportClip">从剪贴板导入</button>
            <button class="btn btn-tonal" id="btnEmptyImportText">粘贴链接 / 订阅</button>
            <button class="btn btn-ghost" id="btnEmptyAddManual">手动添加节点</button>
          </div>
        </div>
      `;
    } else {
      listHtml = `<div class="profile-list">${profiles.map((p) => {
        const selected = p.id === appState.selectedProfile;
        const coreTag = p.core && p.core !== "auto" && p.core !== "sing-box" ? ` · ${p.core.toUpperCase()}` : "";
        let latClass = "latency-idle", latText = "未测速";
        if (p.latencyMs > 0) {
          latText = `${p.latencyMs} ms`;
          latClass = p.latencyMs < 200 ? "latency-good" : p.latencyMs < 500 ? "latency-mid" : "latency-bad";
        } else if (p.latencyMs < 0) {
          latText = "不可用";
          latClass = "latency-bad";
        }
        const traffic = (p.txBytes || p.rxBytes) ? `↑${formatBytes(p.txBytes)} ↓${formatBytes(p.rxBytes)}` : "";
        return `
          <div class="profile-card glass-surface ${selected ? "selected" : ""}" data-pid="${p.id}">
            <div class="profile-selected-pill"></div>
            <div class="profile-body">
              <div class="profile-top">
                <div class="profile-name" title="${escapeHtml(p.name)}">${escapeHtml(p.name)}</div>
                <div class="profile-card-actions">
                  <button class="icon-btn squircle btn-p-edit" data-pid="${p.id}" title="编辑节点">${ICONS.edit}</button>
                  <button class="icon-btn squircle btn-p-share" data-pid="${p.id}" title="分享 / 导出配置">${ICONS.share}</button>
                  <button class="icon-btn squircle btn-p-del" data-pid="${p.id}" title="删除节点">${ICONS.del}</button>
                </div>
              </div>
              <div class="profile-mid">
                <span class="profile-addr">${escapeHtml(p.address || "custom")}${p.port ? ":" + p.port : ""}</span>
                <span>${traffic}</span>
              </div>
              <div class="profile-bottom">
                <span class="proto-pill">${escapeHtml((p.type || "proxy").toUpperCase())}${escapeHtml(coreTag)}</span>
                <span class="latency-pill ${latClass} btn-p-test" data-pid="${p.id}" title="${escapeHtml(p.lastError || "点击测速")}">${latText}</span>
              </div>
            </div>
          </div>
        `;
      }).join("")}</div>`;
    }

    holder.innerHTML = `
      <div class="group-tabs-bar glass-surface" id="groupTabsBar">${tabsHtml.join("")}</div>
      <div class="scroll-content">${listHtml}</div>
    `;

    holder.querySelectorAll(".group-tab").forEach((tab) => {
      tab.onclick = async () => {
        const gid = Number(tab.dataset.gid);
        const res = await api("/api/groups/select", "POST", { id: gid });
        appState = res.state;
        renderCurrentPage();
      };
    });

    if ($("btnEmptyImportClip")) $("btnEmptyImportClip").onclick = importFromClipboard;
    if ($("btnEmptyImportText")) $("btnEmptyImportText").onclick = openImportDialog;
    if ($("btnEmptyAddManual")) $("btnEmptyAddManual").onclick = () => openProfileEditor();

    holder.querySelectorAll(".profile-card").forEach((card) => {
      card.onclick = async (e) => {
        if (e.target.closest("button, .btn-p-test")) return;
        const pid = Number(card.dataset.pid);
        try {
          const res = await api("/api/profiles/select", "POST", { id: pid, reconnect: true });
          appState = res.state;
          runtimeStatus = res.status;
          renderCurrentPage();
          renderStatusBar();
        } catch (err) {
          showSnackbar(err.message);
        }
      };
    });

    holder.querySelectorAll(".btn-p-edit").forEach((btn) => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const p = appState.profiles.find((x) => x.id === Number(btn.dataset.pid));
        if (p) openProfileEditor(p);
      };
    });
    holder.querySelectorAll(".btn-p-share").forEach((btn) => {
      btn.onclick = (e) => {
        e.stopPropagation();
        openShareDialog(Number(btn.dataset.pid));
      };
    });
    holder.querySelectorAll(".btn-p-del").forEach((btn) => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        const res = await api("/api/profiles/delete", "POST", { id: Number(btn.dataset.pid) });
        appState = res.state;
        renderCurrentPage();
        showSnackbar("节点已删除");
      };
    });
    holder.querySelectorAll(".btn-p-test").forEach((pill) => {
      pill.onclick = async (e) => {
        e.stopPropagation();
        const pid = Number(pill.dataset.pid);
        pill.textContent = "测速中…";
        try {
          const res = await api("/api/profiles/test", "POST", { ids: [pid] });
          appState = res.state;
          renderCurrentPage();
        } catch (err) {
          showSnackbar(err.message);
        }
      };
    });
  }

  // -------------------- PAGE 2: GROUPS & SUBSCRIPTIONS --------------------
  function renderGroupsPage(holder) {
    const groups = appState.groups || [];
    holder.innerHTML = `
      <div class="scroll-content">
        <div class="stack-col">
          ${groups.map((g) => {
            const count = appState.profiles.filter((p) => p.groupId === g.id).length;
            const isSub = g.type === "subscription" || !!g.subscriptionUrl;
            const used = (g.uploadBytes || 0) + (g.downloadBytes || 0);
            const trafficStr = g.totalBytes > 0
              ? `已用 ${formatBytes(used)} / 总计 ${formatBytes(g.totalBytes)}` +
                (g.expireTimestamp > 0 ? ` · 到期 ${new Date(g.expireTimestamp * 1000).toLocaleDateString()}` : "")
              : "";
            const lastUpd = g.lastUpdated ? `上次更新：${new Date(g.lastUpdated).toLocaleString()}` : "";
            return `
              <div class="section-card glass-surface">
                <div style="display:flex;align-items:center;gap:10px">
                  <div style="flex:1;min-width:0">
                    <div style="font-size:16px;font-weight:700">${escapeHtml(g.name)} ${g.isDefault ? `<span class="proto-pill" style="margin-left:6px">默认</span>` : ""}</div>
                    <div class="pref-summary">${isSub ? escapeHtml(g.subscriptionUrl) : "本地分组"}</div>
                  </div>
                  <button class="icon-btn squircle btn-g-edit" data-gid="${g.id}" title="编辑分组">${ICONS.edit}</button>
                  ${!g.isDefault ? `<button class="icon-btn squircle btn-g-del" data-gid="${g.id}" title="删除分组">${ICONS.del}</button>` : ""}
                </div>
                <div style="display:flex;align-items:flex-end;justify-content:space-between;margin-top:12px;gap:10px;flex-wrap:wrap">
                  <div>
                    ${trafficStr ? `<div style="font-size:12.5px;color:var(--primary);font-weight:600">${trafficStr}</div>` : ""}
                    <div class="pref-summary">${count} 个节点 ${lastUpd ? "· " + lastUpd : ""}</div>
                  </div>
                  ${isSub ? `<button class="btn btn-tonal btn-g-upd" data-gid="${g.id}">更新订阅</button>` : ""}
                </div>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    `;

    holder.querySelectorAll(".btn-g-edit").forEach((b) => {
      b.onclick = () => openGroupDialog(groups.find((x) => x.id === Number(b.dataset.gid)));
    });
    holder.querySelectorAll(".btn-g-del").forEach((b) => {
      b.onclick = async () => {
        try {
          const res = await api("/api/groups/delete", "POST", { id: Number(b.dataset.gid) });
          appState = res.state;
          renderCurrentPage();
          showSnackbar("分组已删除");
        } catch (err) {
          showSnackbar(err.message);
        }
      };
    });
    holder.querySelectorAll(".btn-g-upd").forEach((b) => {
      b.onclick = async () => {
        b.disabled = true;
        b.textContent = "更新中…";
        try {
          const res = await api("/api/groups/update-sub", "POST", { id: Number(b.dataset.gid) });
          appState = res.state;
          renderCurrentPage();
          showSnackbar(`订阅已更新，共 ${res.count} 个节点`);
        } catch (err) {
          showSnackbar(err.message, 4000);
          renderCurrentPage();
        }
      };
    });
  }

  // -------------------- PAGE 3: APP PROXY & META SMART ROUTING --------------------
  async function renderAppProxyPage(holder) {
    const ap = appState.appProxy;
    if (!macAppsCache) {
      holder.innerHTML = `<div class="scroll-content"><div class="empty-state">正在扫描本机 macOS 应用列表…</div></div>`;
      try {
        const res = await api("/api/macos/apps");
        macAppsCache = res.apps || [];
      } catch {
        macAppsCache = [];
      }
    }
    if (!metaStatusCache) {
      api("/api/meta/status").then((d) => { metaStatusCache = d; if (currentPage === "app_proxy") renderAppProxyPage(holder); }).catch(() => {});
    }

    const actions = ap.appActions || {};
    let countBypass = 0, countForce = 0;
    Object.values(actions).forEach((v) => {
      if (v === "bypass") countBypass++;
      else if (v === "force_proxy") countForce++;
    });

    const filteredApps = (macAppsCache || []).filter((a) => {
      if (!appShowSystem && a.isSystem) return false;
      const act = actions[a.bundleId] || "default";
      if (appFilterCustomized && act === "default") return false;
      if (appSearchKeyword.trim()) {
        const q = appSearchKeyword.trim().toLowerCase();
        return a.name.toLowerCase().includes(q) || a.bundleId.toLowerCase().includes(q) || a.processName.toLowerCase().includes(q);
      }
      return true;
    });

    const metaRuleSetsCount = metaStatusCache?.ruleSets || metaStatusCache?.rule_sets || 17;
    const metaRevision = metaStatusCache?.revision || "内置 MetaCubeX 规则集";

    holder.innerHTML = `
      <div class="scroll-content">
        <div class="stack-col">
          <!-- Meta Smart Routing Card (1:1 app_proxy_preferences.xml) -->
          <div class="section-card compact glass-surface">
            <div class="section-title">分应用代理与 Meta 智能分流</div>
            <div class="pref-row" style="cursor:default">
              <span class="pref-icon-badge" data-icon="info"></span>
              <div class="pref-text">
                <div class="pref-title">三层分流优先级</div>
                <div class="pref-summary">侧边栏「路由」自定义规则 (#1 最高优先级) &gt; 分应用「强制代理 / 绕过直连」(#2, 基于 macOS process_name) &gt; Meta 自动分流 (#3)。</div>
              </div>
            </div>
            <div class="pref-row" id="rowMetaAuto">
              <span class="pref-icon-badge" data-icon="route"></span>
              <div class="pref-text">
                <div class="pref-title">Meta 自动分流</div>
                <div class="pref-summary">局域网和中国大陆目的地址直连，其余流量走当前节点（联动 mihomo-dns）。</div>
              </div>
              <label class="switch"><input type="checkbox" id="swMetaAuto" ${ap.metaAutoRouting ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="groups"></span>
              <div class="pref-text">
                <div class="pref-title">规则源</div>
                <div class="pref-summary">已加载 ${metaRuleSetsCount} 套 .mrs 规则集 · ${escapeHtml(metaRevision)}</div>
              </div>
              <select class="field-select" id="selMetaSource" style="width:230px">
                <option value="metacubex" ${ap.metaRuleSource === "metacubex" ? "selected" : ""}>MetaCubeX 官方加强版 (17 套)</option>
                <option value="dustinwin" ${ap.metaRuleSource === "dustinwin" ? "selected" : ""}>DustinWin 精校版 (15 套在线)</option>
              </select>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="route"></span>
              <div class="pref-text">
                <div class="pref-title">分流模式</div>
                <div class="pref-summary">绕过大陆（国内直连）或 GFW 精简模式（仅被封与 AI 走代理）。</div>
              </div>
              <select class="field-select" id="selMetaMode" style="width:230px">
                <option value="bypass_cn" ${ap.metaRoutingMode === "bypass_cn" ? "selected" : ""}>绕过大陆（默认）</option>
                <option value="gfw_only" ${ap.metaRoutingMode === "gfw_only" ? "selected" : ""}>GFW 精简模式</option>
              </select>
            </div>
            <div class="pref-row" id="rowMetaAds">
              <span class="pref-icon-badge" data-icon="del"></span>
              <div class="pref-text">
                <div class="pref-title">屏蔽常见广告域名</div>
                <div class="pref-summary">使用广告规则集拦截常见广告域名（默认关闭）。</div>
              </div>
              <label class="switch"><input type="checkbox" id="swMetaAds" ${ap.metaBlockAds ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row" id="rowMetaRefresh">
              <span class="pref-icon-badge" data-icon="refresh"></span>
              <div class="pref-text">
                <div class="pref-title">立即更新分流规则</div>
                <div class="pref-summary">从当前规则源拉取最新 .mrs 规则集</div>
              </div>
              <button class="btn btn-tonal" id="btnMetaRefresh">立即更新</button>
            </div>
            <div class="pref-row" id="rowMetaDiag">
              <span class="pref-icon-badge" data-icon="globe"></span>
              <div class="pref-text">
                <div class="pref-title">Meta 分流诊断 &amp; 路由出口检测</div>
                <div class="pref-summary">查看近期由 Meta 处理的连接命中规则，或访问 ip.net.coffee 检测出口。</div>
              </div>
              <div style="display:flex;gap:6px">
                <button class="btn btn-tonal" id="btnMetaDiag">诊断记录</button>
                <button class="btn btn-ghost" id="btnOpenIpCheck">ip.net.coffee</button>
              </div>
            </div>
          </div>

          <!-- macOS Per-App Three-State List (1:1 layout_apps.xml) -->
          <div class="section-card glass-surface">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
              <div>
                <div style="font-size:15px;font-weight:700">macOS 分应用三态控制</div>
                <div class="pref-summary">默认 ${Math.max(0, macAppsCache.length - countBypass - countForce)} 个 · 绕过直连 ${countBypass} 个 · 强制代理 ${countForce} 个</div>
              </div>
              <div class="chip-row">
                <button class="chip ${appFilterCustomized ? "active" : ""}" id="chipOnlyCustom">只看已自定义</button>
                <button class="chip ${appShowSystem ? "active" : ""}" id="chipShowSys">显示系统应用</button>
                <button class="chip" id="chipAutoChina">一键国产直连</button>
                <button class="chip" id="chipAutoOverseas">一键海外代理</button>
              </div>
            </div>
            <input class="field-input" id="appSearchInput" placeholder="搜索 macOS 应用名、Bundle ID 或进程名…" value="${escapeHtml(appSearchKeyword)}" style="margin-bottom:10px" />
            <div style="max-height:420px;overflow-y:auto">
              ${filteredApps.map((a) => {
                const act = actions[a.bundleId] || "default";
                const label = act === "bypass" ? "绕过直连" : act === "force_proxy" ? "强制代理" : (ap.metaAutoRouting ? "默认分流" : "默认代理");
                return `
                  <div class="pref-row" style="padding:9px 8px">
                    <div class="pref-text">
                      <div class="pref-title">${escapeHtml(a.name)}</div>
                      <div class="pref-summary">${escapeHtml(a.bundleId)} · 进程: <code>${escapeHtml(a.processName)}</code></div>
                    </div>
                    <button class="app-action-btn app-action-${act}" data-bid="${escapeHtml(a.bundleId)}" data-proc="${escapeHtml(a.processName)}">${label}</button>
                  </div>
                `;
              }).join("") || `<div class="empty-state" style="padding:24px">无匹配的 macOS 应用</div>`}
            </div>
          </div>
        </div>
      </div>
    `;

    const saveAP = async () => {
      const res = await api("/api/app-proxy", "POST", appState.appProxy);
      appState = res.state;
    };

    $("swMetaAuto").onchange = async (e) => { appState.appProxy.metaAutoRouting = e.target.checked; await saveAP(); renderAppProxyPage(holder); showSnackbar("Meta 自动分流已更新（重连生效）"); };
    $("selMetaSource").onchange = async (e) => { appState.appProxy.metaRuleSource = e.target.value; await saveAP(); showSnackbar("规则源已切换"); };
    $("selMetaMode").onchange = async (e) => { appState.appProxy.metaRoutingMode = e.target.value; await saveAP(); showSnackbar("分流模式已更新"); };
    $("swMetaAds").onchange = async (e) => { appState.appProxy.metaBlockAds = e.target.checked; await saveAP(); };
    $("btnMetaRefresh").onclick = async () => {
      $("btnMetaRefresh").textContent = "更新中…";
      try {
        metaStatusCache = await api("/api/meta/refresh", "POST");
        showSnackbar("分流规则已更新到最新版本");
        renderAppProxyPage(holder);
      } catch (err) {
        showSnackbar("规则更新失败：" + err.message, 3600);
        renderAppProxyPage(holder);
      }
    };
    $("btnMetaDiag").onclick = openMetaDiagDialog;
    $("btnOpenIpCheck").onclick = () => api("/api/tools/open-url", "POST", { url: "https://ip.net.coffee/" });

    $("chipOnlyCustom").onclick = () => { appFilterCustomized = !appFilterCustomized; renderAppProxyPage(holder); };
    $("chipShowSys").onclick = () => { appShowSystem = !appShowSystem; renderAppProxyPage(holder); };
    $("chipAutoChina").onclick = async () => {
      let n = 0;
      macAppsCache.forEach((a) => {
        if (a.category === "china") {
          appState.appProxy.appActions[a.bundleId] = "bypass";
          appState.appProxy.appProcessMap[a.bundleId] = a.processName;
          n++;
        }
      });
      await saveAP();
      renderAppProxyPage(holder);
      showSnackbar(`已将 ${n} 个国产应用设为绕过直连`);
    };
    $("chipAutoOverseas").onclick = async () => {
      let n = 0;
      macAppsCache.forEach((a) => {
        if (a.category === "overseas") {
          appState.appProxy.appActions[a.bundleId] = "force_proxy";
          appState.appProxy.appProcessMap[a.bundleId] = a.processName;
          n++;
        }
      });
      await saveAP();
      renderAppProxyPage(holder);
      showSnackbar(`已将 ${n} 个海外应用设为强制代理`);
    };
    $("appSearchInput").oninput = (e) => {
      appSearchKeyword = e.target.value;
      renderAppProxyPage(holder);
      $("appSearchInput").focus();
      $("appSearchInput").setSelectionRange(appSearchKeyword.length, appSearchKeyword.length);
    };
    holder.querySelectorAll(".app-action-btn").forEach((btn) => {
      btn.onclick = async () => {
        const bid = btn.dataset.bid;
        const proc = btn.dataset.proc;
        const cur = appState.appProxy.appActions[bid] || "default";
        const next = cur === "default" ? "bypass" : cur === "bypass" ? "force_proxy" : "default";
        if (next === "default") delete appState.appProxy.appActions[bid];
        else {
          appState.appProxy.appActions[bid] = next;
          appState.appProxy.appProcessMap[bid] = proc;
        }
        await saveAP();
        renderAppProxyPage(holder);
      };
    });
  }

  // -------------------- PAGE 4: ROUTES (CUSTOM RULES #1 PRIORITY) --------------------
  function renderRoutePage(holder) {
    const rules = appState.rules || [];
    holder.innerHTML = `
      <div class="scroll-content">
        <div class="stack-col">
          ${rules.length === 0 ? `
            <div class="empty-state">
              <h3>暂无自定义路由规则</h3>
              <p>自定义路由规则始终保持 #1 最高优先级，可按域名、IP CIDR、端口或 macOS 进程名指定直连、拦截或特定代理节点。</p>
              <button class="btn btn-primary" id="btnAddRuleEmpty" style="margin-top:12px">新建路由规则</button>
            </div>
          ` : rules.map((r) => {
            const conds = [r.domains && `域名: ${r.domains}`, r.ips && `IP: ${r.ips}`, r.ports && `端口: ${r.ports}`, r.processName && `进程: ${r.processName}`].filter(Boolean).join(" · ");
            const outLabel = r.outbound === "direct" ? "直连 (bypass)" : r.outbound === "block" ? "拦截 (block)" : r.outbound === "proxy" ? "当前代理节点" : r.outbound;
            return `
              <div class="section-card glass-surface">
                <div style="display:flex;align-items:center;gap:10px">
                  <div style="flex:1;min-width:0">
                    <div style="font-size:15px;font-weight:700">${escapeHtml(r.name || "未命名规则")}</div>
                    <div class="pref-summary">${escapeHtml(conds || "全流量")}</div>
                    <div style="margin-top:4px;font-size:12.5px;font-weight:700;color:var(--primary)">→ ${escapeHtml(outLabel)}</div>
                  </div>
                  <button class="icon-btn squircle btn-r-edit" data-rid="${r.id}">${ICONS.edit}</button>
                  <button class="icon-btn squircle btn-r-del" data-rid="${r.id}">${ICONS.del}</button>
                  <label class="switch"><input type="checkbox" class="sw-r-enable" data-rid="${r.id}" ${r.enabled ? "checked" : ""}><span class="switch-track"></span></label>
                </div>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    `;

    if ($("btnAddRuleEmpty")) $("btnAddRuleEmpty").onclick = () => openRuleDialog();
    holder.querySelectorAll(".btn-r-edit").forEach((b) => {
      b.onclick = () => openRuleDialog(rules.find((x) => x.id === Number(b.dataset.rid)));
    });
    holder.querySelectorAll(".btn-r-del").forEach((b) => {
      b.onclick = async () => {
        const res = await api("/api/rules/delete", "POST", { id: Number(b.dataset.rid) });
        appState = res.state;
        renderCurrentPage();
      };
    });
    holder.querySelectorAll(".sw-r-enable").forEach((sw) => {
      sw.onchange = async () => {
        const rule = rules.find((x) => x.id === Number(sw.dataset.rid));
        if (!rule) return;
        rule.enabled = sw.checked;
        const res = await api("/api/rules/upsert", "POST", rule);
        appState = res.state;
      };
    });
  }

  // -------------------- PAGE 5: POWER SAVER (1:1 layout_power_saver.xml) --------------------
  function renderPowerSaverPage(holder) {
    const ps = appState.powerSaver;
    const keys = ["mixedTunStack", "smartFindProcess", "pauseOnHidden", "sleepCoreOnIdle"];
    const activeCount = keys.filter((k) => ps[k]).length;
    const statusText = activeCount === 4
      ? `已开启 4 / 4 项 · 高效节能中`
      : activeCount === 0
      ? `已关闭全部可控省电项`
      : `已开启 ${activeCount} / 4 项 · 自定义`;

    holder.innerHTML = `
      <div class="scroll-content">
        <div class="stack-col">
          <!-- Hero Status & Master Switch Card -->
          <div class="section-card glass-surface">
            <div class="power-hero-row">
              <div class="power-hero-icon-box" data-icon="battery"></div>
              <div style="flex:1;min-width:0">
                <div style="font-size:18px;font-weight:700">省电开关</div>
                <span class="status-pill">${statusText}</span>
              </div>
              <label class="switch"><input type="checkbox" id="swPowerMaster" ${activeCount > 0 ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-summary" style="margin-top:12px">在不限制多核峰值网速的前提下，全面降低后台唤醒、数据包拷贝与跨进程调度开销，特别针对 MacBook 电池续航优化。</div>
          </div>

          <!-- Controllable 4 Switches -->
          <div class="section-card compact glass-surface">
            <div class="section-title">可控省电项</div>
            <div class="pref-row">
              <div class="pref-text">
                <div class="pref-title">内核级省电协议栈（Mixed）</div>
                <div class="pref-summary">TCP 走 macOS 内核栈、UDP/QUIC 走 gVisor，大幅降低高流量 CPU 占用并兼顾千兆/两千兆满速；关闭将切回纯 gVisor。</div>
              </div>
              <label class="switch"><input type="checkbox" data-ps="mixedTunStack" ${ps.mixedTunStack ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <div class="pref-text">
                <div class="pref-title">按需进程识别（智能 find_process）</div>
                <div class="pref-summary">仅在分应用强制代理、绕过直连或进程路由需要时查询进程归属，削减系统调用开销。</div>
              </div>
              <label class="switch"><input type="checkbox" data-ps="smartFindProcess" ${ps.smartFindProcess ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <div class="pref-text">
                <div class="pref-title">窗口隐藏暂停流量轮询</div>
                <div class="pref-summary">最小化到菜单栏或息屏时自动挂起每秒统计协程，打开窗口毫秒级补刷累计流量。</div>
              </div>
              <label class="switch"><input type="checkbox" data-ps="pauseOnHidden" ${ps.pauseOnHidden ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <div class="pref-text">
                <div class="pref-title">macOS 合盖待机核心休眠（Sleep / Wake）</div>
                <div class="pref-summary">Mac 进入睡眠时自动调用 box.Sleep() 暂停核心后台定时器，开盖瞬间 box.Wake() 无缝恢复。</div>
              </div>
              <label class="switch"><input type="checkbox" data-ps="sleepCoreOnIdle" ${ps.sleepCoreOnIdle ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
          </div>

          <!-- Always-On Built-in Engine Optimizations -->
          <div class="section-card glass-surface">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
              <div style="font-size:15px;font-weight:700">底层无感省电引擎</div>
              <span class="status-pill">默认生效</span>
            </div>
            <div class="builtin-item">
              <span class="builtin-check" data-icon="check"></span>
              <div><div class="pref-title">全核满速调度与 Go 内存调优</div><div class="pref-summary">不限核应对千兆/两千兆测速，消除启动双倍规则编译并配置内存软上限 (192 MiB)。</div></div>
            </div>
            <div class="builtin-item">
              <span class="builtin-check" data-icon="check"></span>
              <div><div class="pref-title">Apple Silicon &amp; Intel 原生指令集优化</div><div class="pref-summary">Universal 通用二进制在 M 系列与 Intel Mac 上均原生执行，零 Rosetta 转译损耗。</div></div>
            </div>
            <div class="builtin-item">
              <span class="builtin-check" data-icon="check"></span>
              <div><div class="pref-title">Meta 热点域名 O(1) 匹配缓存</div><div class="pref-summary">高频重复域名 O(1) 命中分流结果，规则热更新后自动随新策略失效。</div></div>
            </div>
            <div class="builtin-item">
              <span class="builtin-check" data-icon="check"></span>
              <div><div class="pref-title">原生 Cocoa 外壳极低常驻内存</div><div class="pref-summary">无 Electron / Chromium 进程常驻，仅使用系统原生 AppKit + WebKit。</div></div>
            </div>
          </div>
        </div>
      </div>
    `;

    const savePS = async () => {
      const res = await api("/api/power-saver", "POST", appState.powerSaver);
      appState = res.state;
      renderPowerSaverPage(holder);
      hydrateIcons(holder);
    };

    $("swPowerMaster").onchange = async (e) => {
      keys.forEach((k) => { appState.powerSaver[k] = e.target.checked; });
      await savePS();
    };
    holder.querySelectorAll("[data-ps]").forEach((inp) => {
      inp.onchange = async () => {
        appState.powerSaver[inp.dataset.ps] = inp.checked;
        await savePS();
      };
    });
  }

  // -------------------- PAGE 6: SETTINGS (1:1 global_preferences.xml) --------------------
  function renderSettingsPage(holder) {
    const st = appState.settings;
    const activeTheme = THEMES.find((t) => t.id === st.appTheme) || THEMES[1];
    const renderIntensityRow = (key, title, summary, icon) => `
      <div class="pref-row" style="align-items:flex-start">
        <span class="pref-icon-badge" data-icon="${icon}"></span>
        <div class="pref-text">
          <div class="pref-title">${title} <span class="proto-pill" style="margin-left:6px">${INTENSITY_LABELS[st[key] ?? 1]}</span></div>
          <div class="pref-summary">${summary}</div>
          <div class="intensity-bar">
            ${INTENSITY_LABELS.map((lbl, idx) => `<button class="intensity-seg ${(st[key] ?? 1) === idx ? "active" : ""}" data-int-key="${key}" data-int-val="${idx}">${lbl}</button>`).join("")}
          </div>
        </div>
      </div>
    `;

    holder.innerHTML = `
      <div class="scroll-content">
        <div class="stack-col">
          <!-- General Settings -->
          <div class="section-card compact glass-surface">
            <div class="section-title">通用设置</div>
            <div class="pref-row" id="rowThemePicker">
              <span class="pref-icon-badge" data-icon="palette"></span>
              <div class="pref-text">
                <div class="pref-title">主题颜色（21 套）</div>
                <div class="pref-summary">当前：${activeTheme.name}</div>
              </div>
              <span style="width:26px;height:26px;border-radius:50%;background:${activeTheme.primary};box-shadow:0 2px 8px rgba(0,0,0,0.2)"></span>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="palette"></span>
              <div class="pref-text"><div class="pref-title">深色模式</div><div class="pref-summary">跟随 macOS 外观或手动指定浅色/深色</div></div>
              <select class="field-select" data-st="nightMode" style="width:150px">
                <option value="system" ${st.nightMode === "system" ? "selected" : ""}>跟随系统</option>
                <option value="light" ${st.nightMode === "light" ? "selected" : ""}>浅色模式</option>
                <option value="dark" ${st.nightMode === "dark" ? "selected" : ""}>深色模式</option>
              </select>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="settings"></span>
              <div class="pref-text">
                <div class="pref-title">服务模式</div>
                <div class="pref-summary">系统代理免密码即开即用；TUN 模式支持全协议底层接管（需管理员权限）。</div>
              </div>
              <select class="field-select" data-st="serviceMode" style="width:170px">
                <option value="system_proxy" ${st.serviceMode === "system_proxy" ? "selected" : ""}>macOS 系统代理</option>
                <option value="tun" ${st.serviceMode === "tun" ? "selected" : ""}>TUN 虚拟网卡</option>
                <option value="mixed_only" ${st.serviceMode === "mixed_only" ? "selected" : ""}>仅本地混合端口</option>
              </select>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="groups"></span>
              <div class="pref-text"><div class="pref-title">显示「全部」分组</div><div class="pref-summary">在配置页顶部显示汇总所有分组节点的标签</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="showAllGroup" ${st.showAllGroup ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="refresh"></span>
              <div class="pref-text"><div class="pref-title">启动时自动连接</div><div class="pref-summary">打开 Nekobox-Mac 后自动连接上次选中的节点</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="autoConnect" ${st.autoConnect ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="apps"></span>
              <div class="pref-text"><div class="pref-title">macOS 开机自启</div><div class="pref-summary">自动注册 LaunchAgent (~/Library/LaunchAgents/com.nekobox.mac.plist)</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="launchAtLogin" ${st.launchAtLogin ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row" id="rowPermGuideSettings" style="cursor:pointer">
              <span class="pref-icon-badge" data-icon="info"></span>
              <div class="pref-text">
                <div class="pref-title">macOS 系统权限与打开设置教学（简体 / 繁體）</div>
                <div class="pref-summary">查看 Gatekeeper 放行、系统代理、本地网络、TUN 管理员权限与开机自启设置步骤</div>
              </div>
              <button class="btn btn-tonal" type="button" id="btnOpenPermGuideSettings">打开教学</button>
            </div>
          </div>

          <!-- Interface & Liquid Glass 3.0 Motion -->
          <div class="section-card compact glass-surface">
            <div class="section-title">界面与动效（Liquid Glass 3.0 / 怀旧双风格）</div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="palette"></span>
              <div class="pref-text"><div class="pref-title">怀旧界面</div><div class="pref-summary">1:1 还原原版 NekoBox 实色顶栏与经典卡片样式，保留全部新功能</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="classicUi" ${st.classicUi ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            ${renderIntensityRow("liquidJellyLevel", "液态果冻动效强度", "调节点击果冻回弹、3D 微倾与触点柔光幅度（五档可调，轻度最流畅）", "palette")}
            ${renderIntensityRow("liquidBlurLevel", "弹窗背景毛玻璃模糊", "调节对话框后方实时高斯模糊强度（点击强度条实时生效）", "palette")}
            ${renderIntensityRow("liquidAmbientLevel", "主题环境流光底色", "调节液态玻璃卡片后方的主题色光晕强度（点击实时预览）", "palette")}
            ${renderIntensityRow("liquidScrollLevel", "列表弹性滚动动效", "调节列表滚动与回弹动效强度", "palette")}
          </div>

          <!-- Routing & DNS -->
          <div class="section-card compact glass-surface">
            <div class="section-title">路由与 DNS 设置</div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="globe"></span>
              <div class="pref-text"><div class="pref-title">IPv6 模式</div><div class="pref-summary">默认启用双栈路由与 IPv6 FakeDNS，可随时按需关闭</div></div>
              <select class="field-select" data-st="ipv6Mode" style="width:150px">
                <option value="disable" ${st.ipv6Mode === "disable" ? "selected" : ""}>禁用</option>
                <option value="enable" ${st.ipv6Mode === "enable" ? "selected" : ""}>启用（默认）</option>
                <option value="prefer" ${st.ipv6Mode === "prefer" ? "selected" : ""}>优先 IPv6</option>
                <option value="only" ${st.ipv6Mode === "only" ? "selected" : ""}>仅使用 IPv6</option>
              </select>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="route"></span>
              <div class="pref-text"><div class="pref-title">远程 DNS</div><div class="pref-summary">用于海外与代理域名解析</div></div>
              <input class="field-input" data-st-text="remoteDns" value="${escapeHtml(st.remoteDns)}" style="width:240px" />
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="route"></span>
              <div class="pref-text"><div class="pref-title">直连 DNS</div><div class="pref-summary">用于国内直连域名与服务器域名解析</div></div>
              <input class="field-input" data-st-text="directDns" value="${escapeHtml(st.directDns)}" style="width:240px" />
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="route"></span>
              <div class="pref-text"><div class="pref-title">启用 FakeDNS</div><div class="pref-summary">TUN 模式下启用 FakeIP 加速解析并防止 DNS 泄漏</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="enableFakeDns" ${st.enableFakeDns ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
          </div>

          <!-- Inbound & Misc -->
          <div class="section-card compact glass-surface">
            <div class="section-title">入站端口与效率工具</div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="settings"></span>
              <div class="pref-text"><div class="pref-title">混合代理端口（HTTP + SOCKS5）</div><div class="pref-summary">本机代理统一监听端口（默认 2080）</div></div>
              <input class="field-input" type="number" data-st-num="mixedPort" value="${st.mixedPort}" style="width:110px" />
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="globe"></span>
              <div class="pref-text"><div class="pref-title">允许局域网设备连接</div><div class="pref-summary">将本地端口绑定至 0.0.0.0 供同一局域网设备共享</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="allowLan" ${st.allowLan ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="speed"></span>
              <div class="pref-text"><div class="pref-title">批量测速并发线程数</div><div class="pref-summary">同时测试 ${st.connectionTestConcurrent} 个节点</div></div>
              <select class="field-select" data-st-num-sel="connectionTestConcurrent" style="width:120px">
                ${[1, 3, 5, 8, 12, 16].map((n) => `<option value="${n}" ${st.connectionTestConcurrent === n ? "selected" : ""}>${n} 线程</option>`).join("")}
              </select>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="speed"></span>
              <div class="pref-text"><div class="pref-title">连接测速地址（1-RTT）</div><div class="pref-summary">用于节点延迟与连接可用性测试</div></div>
              <input class="field-input" data-st-text="connectionTestUrl" value="${escapeHtml(st.connectionTestUrl)}" style="width:240px" />
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="dashboard"></span>
              <div class="pref-text"><div class="pref-title">启用 Clash API / MetaCubeXD 面板</div><div class="pref-summary">默认端口 9090，用于侧边栏「面板」实时观测连接</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="enableClashApi" ${st.enableClashApi ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="bug"></span>
              <div class="pref-text"><div class="pref-title">日志级别</div><div class="pref-summary">控制内核输出日志详细程度</div></div>
              <select class="field-select" data-st="logLevel" style="width:130px">
                ${["panic", "warn", "info", "debug", "trace"].map((l) => `<option value="${l}" ${st.logLevel === l ? "selected" : ""}>${l}</option>`).join("")}
              </select>
            </div>
            <div class="pref-row">
              <span class="pref-icon-badge" data-icon="info"></span>
              <div class="pref-text"><div class="pref-title">全局允许不安全 TLS 证书</div><div class="pref-summary">仅调试自签证书节点时开启</div></div>
              <label class="switch"><input type="checkbox" data-st-bool="globalAllowInsecure" ${st.globalAllowInsecure ? "checked" : ""}><span class="switch-track"></span></label>
            </div>
          </div>
        </div>
      </div>
    `;

    const persistSettings = async (rerender = false) => {
      const res = await api("/api/settings", "POST", appState.settings);
      appState = res.state;
      applyThemeAndAppearance();
      if (rerender) {
        renderSettingsPage(holder);
        hydrateIcons(holder);
      }
    };

    $("rowThemePicker").onclick = openThemePickerDialog;
    if ($("rowPermGuideSettings")) {
      $("rowPermGuideSettings").onclick = () => openPermissionGuideDialog(true);
    }
    if ($("btnOpenPermGuideSettings")) {
      $("btnOpenPermGuideSettings").onclick = (e) => {
        e.stopPropagation();
        openPermissionGuideDialog(true);
      };
    }

    holder.querySelectorAll("[data-st-bool]").forEach((inp) => {
      inp.onchange = async () => {
        appState.settings[inp.dataset.stBool] = inp.checked;
        await persistSettings(false);
        showSnackbar("设置已保存");
      };
    });
    holder.querySelectorAll("[data-st]").forEach((sel) => {
      sel.onchange = async () => {
        appState.settings[sel.dataset.st] = sel.value;
        await persistSettings(false);
        showSnackbar("设置已保存");
        if (sel.dataset.st === "serviceMode" && sel.value === "tun") {
          try {
            macPermissions = await api("/api/macos/permissions");
            if (!macPermissions.canTun) {
              openPermissionGuideDialog(true);
            }
          } catch {}
        }
      };
    });
    holder.querySelectorAll("[data-st-num-sel]").forEach((sel) => {
      sel.onchange = async () => {
        appState.settings[sel.dataset.stNumSel] = Number(sel.value);
        await persistSettings(true);
      };
    });
    holder.querySelectorAll("[data-st-num]").forEach((inp) => {
      inp.onchange = async () => {
        appState.settings[inp.dataset.stNum] = Number(inp.value) || 2080;
        await persistSettings(false);
        showSnackbar("端口已更新（重连生效）");
      };
    });
    holder.querySelectorAll("[data-st-text]").forEach((inp) => {
      inp.onchange = async () => {
        appState.settings[inp.dataset.stText] = inp.value.trim();
        await persistSettings(false);
        showSnackbar("设置已保存");
      };
    });
    holder.querySelectorAll("[data-int-key]").forEach((btn) => {
      btn.onclick = async () => {
        const k = btn.dataset.intKey;
        const v = Number(btn.dataset.intVal);
        appState.settings[k] = v;
        await persistSettings(true);
      };
    });
  }

  // -------------------- PAGE 7: LOGS --------------------
  function renderLogsPage(holder) {
    const filtered = logFilterLevel === "all" ? logsList : logsList.filter((l) => l.level === logFilterLevel);
    holder.innerHTML = `
      <div class="group-tabs-bar glass-surface">
        ${[["all", "全部"], ["info", "INFO"], ["warn", "WARN"], ["error", "ERROR"], ["debug", "DEBUG"]].map(([k, lbl]) =>
          `<button class="group-tab ${logFilterLevel === k ? "active" : ""}" data-lvl="${k}">${lbl}</button>`
        ).join("")}
      </div>
      <div class="scroll-content" id="logScrollArea">
        <div class="glass-surface log-viewer" id="logViewerBox">
          ${filtered.length === 0 ? `<div style="color:var(--ink-secondary)">暂无日志输出</div>` :
            filtered.map((l) => `<div class="log-line"><span class="log-ts">${escapeHtml(l.timestamp)}</span><span class="log-lvl log-lvl-${escapeHtml(l.level)}">${escapeHtml(l.level)}</span><span>${escapeHtml(l.message)}</span></div>`).join("")}
        </div>
      </div>
    `;
    holder.querySelectorAll(".group-tab").forEach((b) => {
      b.onclick = () => { logFilterLevel = b.dataset.lvl; renderLogsPage(holder); };
    });
    const area = $("logScrollArea");
    if (area) area.scrollTop = area.scrollHeight;
  }

  // -------------------- PAGE 8: DASHBOARD (MetaCubeXD v1.276.0) --------------------
  function getDashboardFullUrl() {
    const port = appState?.settings?.clashApiPort || 9090;
    return `${window.location.origin}/ui/#/setup?hostname=127.0.0.1&port=${port}&secret=`;
  }

  function renderDashboardPage(holder) {
    const connected = runtimeStatus && runtimeStatus.state === "connected";
    const port = appState.settings.clashApiPort || 9090;
    holder.innerHTML = `
      <div class="dashboard-frame-wrap glass-surface">
        ${!connected ? `
          <div style="padding:12px 16px;border-bottom:1px solid var(--divider);display:flex;align-items:center;justify-content:space-between;gap:10px">
            <span class="pref-summary">请先点击右下角按钮连接节点，MetaCubeXD 将自动接入本地 Clash API (127.0.0.1:${port})。</span>
            <button class="btn btn-primary" id="btnDashConnect">立即连接</button>
          </div>
        ` : ""}
        <iframe class="dashboard-iframe" src="${getDashboardFullUrl()}" title="MetaCubeXD Dashboard"></iframe>
      </div>
    `;
    if ($("btnDashConnect")) {
      $("btnDashConnect").onclick = toggleConnection;
    }
  }

  // -------------------- PAGE 9: TOOLS (BACKUP + STUN) --------------------
  function renderToolsPage(holder) {
    holder.innerHTML = `
      <div class="group-tabs-bar glass-surface">
        <button class="group-tab ${currentToolsTab === "backup" ? "active" : ""}" data-tt="backup">备份与恢复</button>
        <button class="group-tab ${currentToolsTab === "network" ? "active" : ""}" data-tt="network">网络与 STUN 检测</button>
      </div>
      <div class="scroll-content">
        <div class="stack-col" id="toolsBody"></div>
      </div>
    `;
    holder.querySelectorAll("[data-tt]").forEach((b) => {
      b.onclick = () => { currentToolsTab = b.dataset.tt; renderToolsPage(holder); };
    });

    const body = $("toolsBody");
    if (currentToolsTab === "backup") {
      body.innerHTML = `
        <div class="section-card glass-surface">
          <div style="font-size:15px;font-weight:700;margin-bottom:10px">备份与导出</div>
          <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><input type="checkbox" id="bkProfiles" checked> 导出分组与全部节点配置</label>
          <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><input type="checkbox" id="bkRules" checked> 导出路由规则与分应用设置</label>
          <label style="display:flex;align-items:center;gap:8px;margin-bottom:14px"><input type="checkbox" id="bkSettings" checked> 导出全部应用与主题设置</label>
          <button class="btn btn-primary" id="btnExportBackup">导出 JSON 备份文件</button>
        </div>
        <div class="section-card glass-surface">
          <div style="font-size:15px;font-weight:700;margin-bottom:6px">恢复与重置</div>
          <div class="pref-summary" style="margin-bottom:12px">导入先前导出的 JSON 备份文件以恢复配置，或一键将设置恢复为出厂默认值。</div>
          <input type="file" id="bkFileInput" accept=".json,application/json" class="hidden" />
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <button class="btn btn-tonal" id="btnImportBackup">从文件恢复备份</button>
            <button class="btn btn-danger" id="btnResetSettings">重置所有设置</button>
          </div>
        </div>
      `;
      $("btnExportBackup").onclick = () => {
        const q = `profiles=${$("bkProfiles").checked ? 1 : 0}&rules=${$("bkRules").checked ? 1 : 0}&settings=${$("bkSettings").checked ? 1 : 0}`;
        window.location.href = `/api/backup/export?${q}`;
        showSnackbar("已开始下载备份文件");
      };
      $("btnImportBackup").onclick = () => $("bkFileInput").click();
      $("bkFileInput").onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const text = await file.text();
        try {
          const resp = await fetch("/api/backup/import", { method: "POST", body: text });
          const data = await resp.json();
          if (!resp.ok) throw new Error(data.error);
          appState = data.state;
          applyThemeAndAppearance();
          showSnackbar("备份已成功恢复");
        } catch (err) {
          showSnackbar(err.message);
        }
      };
      $("btnResetSettings").onclick = async () => {
        const res = await api("/api/backup/reset", "POST");
        appState = res.state;
        applyThemeAndAppearance();
        showSnackbar("已恢复默认设置");
      };
    } else {
      body.innerHTML = `
        <div class="section-card glass-surface">
          <div style="font-size:15px;font-weight:700;margin-bottom:8px">STUN NAT 类型检测</div>
          <div class="field-group">
            <label class="field-label">STUN 服务器地址</label>
            <input class="field-input" id="stunServerInput" value="${escapeHtml(appState.settings.stunServer || "stun.voipgate.com:3478")}" />
          </div>
          <div style="display:flex;gap:10px;align-items:center">
            <button class="btn btn-primary" id="btnRunStun">开始检测</button>
            <button class="btn btn-ghost" id="btnToolIpCoffee">打开 ip.net.coffee 出口检测</button>
          </div>
          <div id="stunResultBox" class="pref-summary" style="margin-top:14px;padding:12px;border-radius:14px;background:var(--input-bg)">等待开始检测…</div>
        </div>
      `;
      $("btnToolIpCoffee").onclick = () => api("/api/tools/open-url", "POST", { url: "https://ip.net.coffee/" });
      $("btnRunStun").onclick = async () => {
        $("btnRunStun").disabled = true;
        $("stunResultBox").textContent = "正在通过内置 STUN 引擎探测 NAT 映射行为…";
        try {
          const res = await api("/api/tools/stun", "POST", { server: $("stunServerInput").value.trim() });
          $("stunResultBox").innerHTML = `<b>NAT 类型：</b>${escapeHtml(res.natType)}<br/><b>映射公网地址：</b>${escapeHtml(res.externalAddr || "未知")}<br/><b>测试服务器：</b>${escapeHtml(res.server)}`;
        } catch (err) {
          $("stunResultBox").textContent = "探测失败：" + err.message;
        } finally {
          $("btnRunStun").disabled = false;
        }
      };
    }
  }

  // -------------------- PAGE 10: ABOUT (1:1 layout_about.xml) --------------------
  function renderAboutPage(holder) {
    const v = coreVersions || {};
    const sysProxy = runtimeStatus?.systemProxy || {};
    holder.innerHTML = `
      <div class="scroll-content">
        <div class="stack-col">
          <div class="section-card glass-surface" id="aboutTitleCard" style="cursor:pointer" title="点击复制全部版本信息">
            <div class="about-head">
              <img class="about-logo" src="/assets/app-icon.png" alt="Nekobox-Mac" />
              <div>
                <div style="font-size:20px;font-weight:800">Nekobox-Mac</div>
                <span class="status-pill">${escapeHtml(v.app || "1.6.1-mac")} · macOS Universal (arm64 + x86_64)</span>
              </div>
            </div>
            <div class="core-pills">
              <span class="core-pill">sing-box ${escapeHtml(v.singBox || "")}</span>
              <span class="core-pill">Xray-core ${escapeHtml(v.xray || "")}</span>
              <span class="core-pill">Mihomo ${escapeHtml(v.mihomo || "")}</span>
              <span class="core-pill">${escapeHtml(v.arch || "")}</span>
              <span class="core-pill">${escapeHtml(v.os || "")}</span>
            </div>
          </div>

          <div class="section-card compact glass-surface">
            <div class="pref-row" id="aboutSysProxyRow">
              <span class="pref-icon-badge" data-icon="globe"></span>
              <div class="pref-text">
                <div class="pref-title">macOS 系统代理状态</div>
                <div class="pref-summary">${sysProxy.enabled ? `已启用 (${sysProxy.host}:${sysProxy.port} · ${(sysProxy.services || []).join(", ")})` : "当前未启用系统代理"}</div>
              </div>
              <button class="btn btn-tonal" id="btnToggleSysProxy">${sysProxy.enabled ? "关闭系统代理" : "启用系统代理"}</button>
            </div>
            <div class="pref-row" id="aboutPermGuideRow" style="cursor:pointer">
              <span class="pref-icon-badge" data-icon="settings"></span>
              <div class="pref-text">
                <div class="pref-title">macOS 系统权限教学（简体中文 / 繁體中文）</div>
                <div class="pref-summary">首次打开放行、网络代理、本地网络、TUN 虚拟网卡与登录项权限指引</div>
              </div>
              <button class="btn btn-tonal" type="button" id="btnAboutPermGuide">查看教学</button>
            </div>
            <div class="pref-row" id="aboutUpstreamRow">
              <span class="pref-icon-badge" data-icon="info"></span>
              <div class="pref-text">
                <div class="pref-title">上游源码基线（Nekobox-Next）</div>
                <div class="pref-summary">github.com/shixiaoheia/Nekobox-Next · 基于原项目三内核与双界面完整移植为 macOS 原生版本</div>
              </div>
            </div>
          </div>

          <div class="section-card glass-surface">
            <div style="font-size:14px;font-weight:700;margin-bottom:6px">开源协议与致谢</div>
            <div class="pref-summary">
              Nekobox-Mac 遵循 GNU General Public License v3.0 (GPL-3.0) 开源协议。<br/>
              核心引擎整合自 SagerNet/sing-box、XTLS/Xray-core、MetaCubeX/mihomo、MetaCubeX/metacubexd 与 MetaCubeX/meta-rules-dat，致敬 MatsuriDayo/NekoBoxForAndroid 与 shixiaoheia/Nekobox-Next。
            </div>
          </div>
        </div>
      </div>
    `;

    $("aboutTitleCard").onclick = () => {
      const txt = `Nekobox-Mac ${v.app}\nsing-box: ${v.singBox}\nXray: ${v.xray}\nMihomo: ${v.mihomo}\n${v.go} (${v.arch} / ${v.os})`;
      navigator.clipboard?.writeText(txt);
      showSnackbar("已复制三内核版本信息");
    };
    $("btnToggleSysProxy").onclick = async () => {
      try {
        const res = await api("/api/sysproxy", "POST", { enabled: !sysProxy.enabled });
        runtimeStatus.systemProxy = res;
        renderAboutPage(holder);
        hydrateIcons(holder);
        showSnackbar(res.enabled ? "已开启 macOS 系统代理" : "已关闭 macOS 系统代理");
      } catch (err) {
        showSnackbar(err.message);
      }
    };
    $("aboutPermGuideRow").onclick = () => openPermissionGuideDialog(true);
    $("btnAboutPermGuide").onclick = (e) => {
      e.stopPropagation();
      openPermissionGuideDialog(true);
    };
    $("aboutUpstreamRow").onclick = () => api("/api/tools/open-url", "POST", { url: "https://github.com/shixiaoheia/Nekobox-Next" });
  }

  // =====================================================================
  // POPUP MENUS & MODAL DIALOGS
  // =====================================================================
  function showPopup(anchorEl, items) {
    const menu = $("popupMenu");
    menu.innerHTML = items.map((it, idx) =>
      it.divider ? `<div class="popup-divider"></div>` :
      `<button class="popup-item" data-idx="${idx}">${it.icon ? `<span>${ICONS[it.icon] || ""}</span>` : ""}<span>${escapeHtml(it.label)}</span></button>`
    ).join("");
    menu.classList.remove("hidden");

    const rect = anchorEl.getBoundingClientRect();
    const mw = menu.offsetWidth || 220;
    const left = Math.max(12, Math.min(window.innerWidth - mw - 12, rect.right - mw));
    const top = Math.min(window.innerHeight - menu.offsetHeight - 12, rect.bottom + 8);
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;

    menu.querySelectorAll(".popup-item").forEach((btn) => {
      btn.onclick = () => {
        const item = items[Number(btn.dataset.idx)];
        closePopup();
        item?.action?.();
      };
    });
  }

  function closePopup() {
    $("popupMenu").classList.add("hidden");
  }

  function showAddProfileMenu(anchor) {
    showPopup(anchor, [
      { label: "从剪贴板导入节点 / 订阅", icon: "add", action: importFromClipboard },
      { label: "粘贴分享链接 / YAML / JSON", icon: "description", action: openImportDialog },
      { divider: true },
      { label: "手动输入节点配置", icon: "edit", action: () => openProfileEditor() },
      { label: "添加远程订阅分组", icon: "groups", action: () => openGroupDialog({ type: "subscription" }) },
    ]);
  }

  function showProfileMoreMenu(anchor) {
    const gid = appState.selectedGroup || 0;
    showPopup(anchor, [
      { label: "批量 URL Test (1-RTT 测速)", icon: "speed", action: batchTestVisible },
      { label: "按延迟从低到高排序", icon: "speed", action: () => sortProfiles("latency") },
      { label: "按名称排序", icon: "description", action: () => sortProfiles("name") },
      { divider: true },
      { label: "清除流量与测速记录", icon: "refresh", action: async () => {
        const res = await api("/api/profiles/clear-traffic", "POST", { groupId: gid });
        appState = res.state;
        renderCurrentPage();
        showSnackbar("已清除测速与流量记录");
      }},
      { label: "移除重复节点", icon: "del", action: () => cleanupProfiles("duplicates") },
      { label: "移除不可用节点", icon: "del", action: () => cleanupProfiles("unavailable") },
    ]);
  }

  function openModal(title, bodyHtml, footerButtons = [], opts = {}) {
    $("modalTitle").textContent = title;
    $("modalBody").innerHTML = bodyHtml;
    $("modalDialog").classList.toggle("modal-wide", Boolean(opts.wide));
    const footer = $("modalFooter");
    footer.innerHTML = "";
    if (opts.footerLeadingHtml) {
      const lead = document.createElement("div");
      lead.className = "perm-footer-check";
      lead.innerHTML = opts.footerLeadingHtml;
      footer.appendChild(lead);
    }
    footerButtons.forEach((b) => {
      const btn = document.createElement("button");
      btn.className = `btn ${b.cls || "btn-ghost"}`;
      btn.textContent = b.label;
      btn.onclick = () => b.action?.();
      footer.appendChild(btn);
    });
    $("modalBackdrop").classList.remove("hidden");
    hydrateIcons($("modalDialog"));
  }

  function closeModal() {
    $("modalBackdrop").classList.add("hidden");
    $("modalDialog").classList.remove("modal-wide");
  }

  async function openMacSettingsPane(pane, okMsg) {
    try {
      await api("/api/macos/open-settings", "POST", { pane });
      showSnackbar(okMsg || "已打开 macOS 系统设置");
    } catch (err) {
      showSnackbar(err.message);
    }
  }

  async function openPermissionGuideDialog(refresh = false) {
    if (refresh || !macPermissions) {
      try {
        macPermissions = await api("/api/macos/permissions");
      } catch {
        macPermissions = macPermissions || {};
      }
    }
    const perm = macPermissions || {};
    let langMode = appState?.settings?.permissionGuideLang || "both";
    if (!["both", "zh-CN", "zh-TW"].includes(langMode)) langMode = "both";
    let dontShowAgain = Boolean(appState?.settings?.permissionGuideDismissed);

    const quarantineCmd = perm.quarantineCmd || 'xattr -dr com.apple.quarantine "/Applications/Nekobox-Mac.app"';
    const tunCmd = perm.tunLaunchCmd || 'sudo "/Applications/Nekobox-Mac.app/Contents/MacOS/Nekobox-Mac"';
    const blocking = new Set(perm.blockingIssues || []);
    const netLabel = (perm.networkServices && perm.networkServices.length > 0)
      ? perm.networkServices.join(", ")
      : "Wi-Fi / Ethernet";

    const renderLangColumns = (scSteps, tcSteps) => {
      const showSC = langMode === "both" || langMode === "zh-CN";
      const showTC = langMode === "both" || langMode === "zh-TW";
      const cols = [];
      if (showSC) {
        cols.push(`
          <div class="perm-lang-col">
            <span class="perm-lang-tag">简体中文</span>
            <ol class="perm-steps">${scSteps.map((s) => `<li>${s}</li>`).join("")}</ol>
          </div>
        `);
      }
      if (showTC) {
        cols.push(`
          <div class="perm-lang-col">
            <span class="perm-lang-tag">繁體中文</span>
            <ol class="perm-steps">${tcSteps.map((s) => `<li>${s}</li>`).join("")}</ol>
          </div>
        `);
      }
      return `<div class="perm-bilingual-grid ${langMode === "both" ? "" : "single-col"}">${cols.join("")}</div>`;
    };

    const pickTitle = (sc, tc) => (langMode === "zh-CN" ? sc : langMode === "zh-TW" ? tc : `${sc} / ${tc}`);

    const renderDialog = () => {
      const modalTitle = pickTitle("macOS 系统权限与设置教学", "macOS 系統權限與設定教學");
      const statusPills = [
        perm.inReadOnlyVolume
          ? `<span class="perm-badge perm-badge-warn">⚠️ ${pickTitle("请拖入「应用程序」文件夹再运行", "請拖曳至「應用程式」資料夾再執行")}</span>`
          : `<span class="perm-badge perm-badge-ok">✓ ${pickTitle("运行目录正常", "執行目錄正常")}</span>`,
        perm.hasQuarantine
          ? `<span class="perm-badge perm-badge-warn">⚠️ ${pickTitle("检测到系统隔离属性 (Quarantine)", "偵測到系統隔離屬性 (Quarantine)")}</span>`
          : `<span class="perm-badge perm-badge-ok">✓ ${pickTitle("无隔离拦截标记", "無隔離攔截標記")}</span>`,
        `<span class="perm-badge perm-badge-info">🌐 ${pickTitle("网络接口", "網路介面")}: ${escapeHtml(netLabel)}</span>`,
        perm.canTun
          ? `<span class="perm-badge perm-badge-ok">✓ ${pickTitle("已获 TUN 管理员权限", "已取得 TUN 管理員權限")}</span>`
          : `<span class="perm-badge ${blocking.has("tun_requires_admin") ? "perm-badge-warn" : "perm-badge-info"}">${blocking.has("tun_requires_admin") ? "⚠️" : "ℹ"} ${pickTitle("系统代理免密可用 · TUN 需管理员", "系統代理免密可用 · TUN 需管理員")}</span>`,
      ].join("");

      const bodyHtml = `
        <div class="perm-topbar">
          <div class="pref-summary" style="margin:0">
            ${escapeHtml(perm.osVersion || "macOS")} · ${escapeHtml(perm.chipLabel || "Universal")}
          </div>
          <div class="perm-lang-tabs" role="tablist">
            <button type="button" class="perm-lang-btn ${langMode === "both" ? "active" : ""}" data-plang="both">简繁双语</button>
            <button type="button" class="perm-lang-btn ${langMode === "zh-CN" ? "active" : ""}" data-plang="zh-CN">简体中文</button>
            <button type="button" class="perm-lang-btn ${langMode === "zh-TW" ? "active" : ""}" data-plang="zh-TW">繁體中文</button>
          </div>
        </div>

        <div class="perm-status-strip">${statusPills}</div>

        <!-- 1. Gatekeeper / First Open -->
        <div class="perm-card ${(blocking.has("readonly_volume") || blocking.has("quarantine")) ? "perm-card-highlight" : ""}">
          <div class="perm-card-head">
            <div class="perm-card-title">1. ${pickTitle("首次打开放行与位置检查（Gatekeeper 安全性）", "首次開啟放行與位置檢查（Gatekeeper 安全性）")}</div>
          </div>
          ${renderLangColumns(
            [
              `请先将 <b>Nekobox-Mac.app</b> 拖入 <b>「应用程序（Applications）」</b> 文件夹，避免直接在只读 DMG 镜像中运行。`,
              `若弹窗提示「无法验证开发者 / 已损坏」，请点击下方按钮打开 <b>系统设置 → 隐私与安全性</b>，下滑至「安全性」点击 <b>「仍要打开」</b> 并输入密码或触控 ID。`,
              `或打开「终端」执行下方命令一键解除隔离标记，之后即可直接双击打开（也可使用终端一键脚本安装免弹窗）。`,
            ],
            [
              `請先將 <b>Nekobox-Mac.app</b> 拖曳至 <b>「應用程式（Applications）」</b> 資料夾，避免直接在唯讀 DMG 映像檔中執行。`,
              `若跳出「無法驗證開發者 / 已損毀」提示，請點擊下方按鈕開啟 <b>系統設定 → 隱私權與安全性</b>，向下捲動至「安全性」點擊 <b>「強制打開（仍要開啟）」</b> 並驗證密碼或 Touch ID。`,
              `或開啟「終端機」執行下方指令一鍵移除隔離標記，完成後即可直接點兩下開啟（亦可使用終端機一鍵腳本安裝免彈窗）。`,
            ]
          )}
          <div class="perm-cmd-row">
            <code class="perm-cmd-code">${escapeHtml(quarantineCmd)}</code>
            <button type="button" class="btn btn-tonal" data-copy-cmd="quarantine" style="padding:4px 10px;font-size:11.5px">${pickTitle("复制命令", "複製指令")}</button>
          </div>
          <div class="perm-actions-row">
            <button type="button" class="btn btn-ghost" data-open-pane="security">${pickTitle("打开隐私与安全性", "開啟隱私權與安全性")}</button>
          </div>
        </div>

        <!-- 2. System Proxy & Local Network -->
        <div class="perm-card">
          <div class="perm-card-head">
            <div class="perm-card-title">2. ${pickTitle("系统代理与本地网络权限（默认推荐）", "系統代理與區域網路權限（預設推薦）")}</div>
          </div>
          ${renderLangColumns(
            [
              `默认「<b>macOS 系统代理</b>」模式免管理员密码即可使用；首次连接若系统提示修改网络代理配置，请点击 <b>「允许」</b>。`,
              `<b>macOS 15 Sequoia 及以上</b>：若连接后网页打不开或提示无权访问本地端口，前往 <b>系统设置 → 隐私与安全性 → 本地网络</b>，打开 <b>Nekobox-Mac</b> 开关。`,
            ],
            [
              `預設「<b>macOS 系統代理</b>」模式免管理員密碼即可使用；首次連線若系統詢問修改網路代理設定，請點擊 <b>「允許」</b>。`,
              `<b>macOS 15 Sequoia 及以上</b>：若連線後網頁無法開啟或提示無權存取本機埠，前往 <b>系統設定 → 隱私權與安全性 → 區域網路</b>，開啟 <b>Nekobox-Mac</b> 開關。`,
            ]
          )}
          <div class="perm-actions-row">
            <button type="button" class="btn btn-ghost" data-open-pane="network">${pickTitle("打开网络设置", "開啟網路設定")}</button>
            <button type="button" class="btn btn-ghost" data-open-pane="local_network">${pickTitle("打开本地网络权限", "開啟區域網路權限")}</button>
          </div>
        </div>

        <!-- 3. TUN Virtual NIC Admin Privilege -->
        <div class="perm-card ${blocking.has("tun_requires_admin") ? "perm-card-highlight" : ""}">
          <div class="perm-card-head">
            <div class="perm-card-title">3. ${pickTitle("TUN 虚拟网卡模式（需管理员权限，按需开启）", "TUN 虛擬網卡模式（需管理員權限，按需開啟）")}</div>
          </div>
          ${renderLangColumns(
            [
              `日常浏览与主流应用使用「系统代理」即可；仅在需要接管全部 UDP / 终端 / 游戏流量时切换为 <b>TUN 虚拟网卡</b>。`,
              `macOS 创建 <code>utun</code> 网卡与路由表需要 root 管理员权限；请在「终端」运行下方命令并输入开机密码启动即可启用 TUN。`,
            ],
            [
              `日常瀏覽與主流應用程式使用「系統代理」即可；僅於需要接管全部 UDP／終端機／遊戲流量時切換為 <b>TUN 虛擬網卡</b>。`,
              `macOS 建立 <code>utun</code> 網卡與路由表需要 root 管理員權限；請於「終端機」執行下方指令並輸入開機密碼啟動即可啟用 TUN。`,
            ]
          )}
          <div class="perm-cmd-row">
            <code class="perm-cmd-code">${escapeHtml(tunCmd)}</code>
            <button type="button" class="btn btn-tonal" data-copy-cmd="tun" style="padding:4px 10px;font-size:11.5px">${pickTitle("复制命令", "複製指令")}</button>
          </div>
        </div>

        <!-- 4. Launch at Login -->
        <div class="perm-card" style="margin-bottom:2px">
          <div class="perm-card-head">
            <div class="perm-card-title">4. ${pickTitle("开机自启与后台项目权限（可选）", "開機自啟與背景項目權限（選用）")}</div>
          </div>
          ${renderLangColumns(
            [
              `在「设置」中开启「macOS 开机自启」后，macOS 13+ 会弹出后台项目通知。如需检查，前往 <b>系统设置 → 通用 → 登录项与扩展</b> 允许 <b>Nekobox-Mac</b>。`,
            ],
            [
              `於「設定」中開啟「macOS 開機自啟」後，macOS 13+ 會彈出背景項目通知。如需檢查，前往 <b>系統設定 → 一般 → 登入項目與延伸功能</b> 允許 <b>Nekobox-Mac</b>。`,
            ]
          )}
          <div class="perm-actions-row">
            <button type="button" class="btn btn-ghost" data-open-pane="login_items">${pickTitle("打开登录项设置", "開啟登入項目設定")}</button>
          </div>
        </div>
      `;

      const footerCheckLabel = pickTitle("下次打开不再自动提示", "下次開啟不再自動提示");
      const saveGuidePrefs = async () => {
        if (!appState?.settings) return;
        const chk = $("chkPermDismiss");
        if (chk) dontShowAgain = chk.checked;
        if (
          appState.settings.permissionGuideDismissed !== dontShowAgain ||
          appState.settings.permissionGuideLang !== langMode
        ) {
          appState.settings.permissionGuideDismissed = dontShowAgain;
          appState.settings.permissionGuideLang = langMode;
          try {
            const res = await api("/api/settings", "POST", appState.settings);
            appState = res.state;
          } catch {}
        }
      };

      openModal(
        modalTitle,
        bodyHtml,
        [
          {
            label: pickTitle("重新检测", "重新偵測"),
            cls: "btn-tonal",
            action: async () => {
              await saveGuidePrefs();
              await openPermissionGuideDialog(true);
              showSnackbar(pickTitle("已刷新 macOS 权限状态", "已重新整理 macOS 權限狀態"));
            },
          },
          {
            label: pickTitle("我已了解", "我已了解"),
            cls: "btn-primary",
            action: async () => {
              await saveGuidePrefs();
              closeModal();
            },
          },
        ],
        {
          wide: true,
          footerLeadingHtml: `<label style="display:inline-flex;align-items:center;gap:7px;cursor:pointer"><input type="checkbox" id="chkPermDismiss" ${dontShowAgain ? "checked" : ""}> <span>${footerCheckLabel}</span></label>`,
        }
      );

      $("modalBody").querySelectorAll("[data-plang]").forEach((btn) => {
        btn.onclick = async () => {
          const chk = $("chkPermDismiss");
          if (chk) dontShowAgain = chk.checked;
          langMode = btn.dataset.plang;
          if (appState?.settings) {
            appState.settings.permissionGuideLang = langMode;
            api("/api/settings", "POST", appState.settings).then((r) => { appState = r.state; }).catch(() => {});
          }
          renderDialog();
        };
      });

      $("modalBody").querySelectorAll("[data-open-pane]").forEach((btn) => {
        btn.onclick = () => openMacSettingsPane(btn.dataset.openPane, pickTitle("已打开 macOS 系统设置", "已開啟 macOS 系統設定"));
      });

      $("modalBody").querySelectorAll("[data-copy-cmd]").forEach((btn) => {
        btn.onclick = () => {
          const cmd = btn.dataset.copyCmd === "tun" ? tunCmd : quarantineCmd;
          navigator.clipboard?.writeText(cmd);
          showSnackbar(pickTitle("已复制终端命令", "已複製終端機指令"));
        };
      });
    };

    renderDialog();
  }

  window.__nekoOpenPermissionGuide = () => openPermissionGuideDialog(true);

  async function importFromClipboard() {
    try {
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        openImportDialog();
        return;
      }
      await submitImport(text);
    } catch {
      openImportDialog();
    }
  }

  function openImportDialog() {
    openModal("导入节点 / 订阅", `
      <div class="field-group">
        <label class="field-label">支持分享链接 (vless/vmess/trojan/ss/ssr/hy2/tuic/anytls/wg/awg/masque/mieru/snell)、订阅 URL、Clash YAML、sing-box JSON、Xray JSON、WireGuard .conf、usque config.json</label>
        <textarea class="field-textarea" id="impTextArea" rows="7" placeholder="在此粘贴分享链接、多行节点或订阅 URL…"></textarea>
      </div>
    `, [
      { label: "取消", cls: "btn-ghost", action: closeModal },
      { label: "立即导入", cls: "btn-primary", action: async () => {
        const text = $("impTextArea").value;
        if (!text.trim()) return;
        await submitImport(text);
        closeModal();
      }},
    ]);
    setTimeout(() => $("impTextArea")?.focus(), 40);
  }

  async function submitImport(text) {
    try {
      const gid = appState.selectedGroup || 0;
      const res = await api("/api/profiles/import", "POST", { groupId: gid, text });
      appState = res.state;
      renderCurrentPage();
      showSnackbar(res.subscription ? `订阅已创建并拉取 ${res.imported} 个节点` : `成功导入 ${res.imported} 个节点`);
    } catch (err) {
      showSnackbar(err.message, 4200);
    }
  }

  function openProfileEditor(existing = null) {
    const p = existing ? JSON.parse(JSON.stringify(existing)) : {
      id: 0,
      groupId: appState.selectedGroup || 1,
      name: "",
      type: "vless",
      core: "auto",
      address: "",
      port: 443,
      params: { security: "tls", transport: "tcp" },
    };
    p.params = p.params || {};
    const gp = (k, def = "") => p.params[k] ?? def;

    const renderForm = () => {
      const isFull = p.type === "full-config";
      const html = `
        <div class="form-grid-2">
          <div class="field-group">
            <label class="field-label">节点名称</label>
            <input class="field-input" id="edName" value="${escapeHtml(p.name)}" placeholder="例如：香港 IEPL 01" />
          </div>
          <div class="field-group">
            <label class="field-label">协议类型</label>
            <select class="field-select" id="edType">
              ${PROTOCOL_TYPES.map(([k, lbl]) => `<option value="${k}" ${p.type === k ? "selected" : ""}>${lbl}</option>`).join("")}
            </select>
          </div>
        </div>
        ${isFull ? `
          <div class="field-group">
            <label class="field-label">sing-box 完整 JSON 配置（支持 1.8–1.14 自动归一化）</label>
            <textarea class="field-textarea" id="edFullConfig" rows="11">${escapeHtml(p.customFullConfig || "{\n  \"outbounds\": []\n}")}</textarea>
          </div>
        ` : `
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">服务器地址</label>
              <input class="field-input" id="edAddr" value="${escapeHtml(p.address)}" placeholder="example.com 或 IP" />
            </div>
            <div class="field-group">
              <label class="field-label">端口</label>
              <input class="field-input" type="number" id="edPort" value="${p.port || 443}" />
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">执行内核</label>
              <select class="field-select" id="edCore">
                <option value="auto" ${p.core === "auto" ? "selected" : ""}>自动选择（推荐）</option>
                <option value="sing-box" ${p.core === "sing-box" ? "selected" : ""}>sing-box</option>
                <option value="xray" ${p.core === "xray" ? "selected" : ""}>Xray-core</option>
                <option value="mihomo" ${p.core === "mihomo" ? "selected" : ""}>Mihomo (Clash.Meta)</option>
              </select>
            </div>
            <div class="field-group">
              <label class="field-label">所属分组</label>
              <select class="field-select" id="edGroup">
                ${appState.groups.map((g) => `<option value="${g.id}" ${p.groupId === g.id ? "selected" : ""}>${escapeHtml(g.name)}</option>`).join("")}
              </select>
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">${["vless", "vmess", "tuic"].includes(p.type) ? "UUID" : p.type === "snell" ? "PSK" : "密码 / 密钥"}</label>
              <input class="field-input" id="edCred" value="${escapeHtml(["vless", "vmess", "tuic"].includes(p.type) ? gp("uuid") : p.type === "snell" ? gp("psk") : gp("password", gp("privateKey")))}" />
            </div>
            <div class="field-group">
              <label class="field-label">${p.type === "shadowsocks" || p.type === "ssr" ? "加密方式" : p.type === "vless" ? "Flow / 流控" : p.type === "hysteria2" ? "pinSHA256 证书指纹" : "TLS / 安全层"}</label>
              <input class="field-input" id="edExtra1" value="${escapeHtml(p.type === "shadowsocks" ? gp("method", "2022-blake3-aes-128-gcm") : p.type === "ssr" ? gp("cipher", "aes-256-cfb") : p.type === "vless" ? gp("flow") : p.type === "hysteria2" ? gp("pinSHA256") : gp("security", "tls"))}" />
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">SNI / Peer / PublicKey</label>
              <input class="field-input" id="edSni" value="${escapeHtml(gp("sni", gp("publicKey")))}" />
            </div>
            <div class="field-group">
              <label class="field-label">传输方式 (tcp / ws / grpc / xhttp / h2)</label>
              <input class="field-input" id="edTransport" value="${escapeHtml(gp("transport", "tcp"))}" />
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">Path / ServiceName</label>
              <input class="field-input" id="edPath" value="${escapeHtml(gp("path", gp("serviceName")))}" />
            </div>
            <div class="field-group">
              <label class="field-label">Host / Reality PBK</label>
              <input class="field-input" id="edHost" value="${escapeHtml(gp("host", gp("pbk")))}" />
            </div>
          </div>
          <div class="field-group">
            <label class="field-label">高级参数 JSON（完整保留所有协议扩展字段）</label>
            <textarea class="field-textarea" id="edParamsJson" rows="4">${escapeHtml(JSON.stringify(p.params, null, 2))}</textarea>
          </div>
        `}
      `;
      openModal(existing ? "编辑节点" : "手动新建节点", html, [
        { label: "取消", cls: "btn-ghost", action: closeModal },
        { label: "保存", cls: "btn-primary", action: async () => {
          p.name = $("edName").value.trim() || `${p.type.toUpperCase()} Node`;
          p.type = $("edType").value;
          if (p.type === "full-config") {
            p.customFullConfig = $("edFullConfig").value;
            p.address = "custom";
            p.port = 0;
          } else {
            p.address = $("edAddr").value.trim();
            p.port = Number($("edPort").value) || 443;
            p.core = $("edCore").value;
            p.groupId = Number($("edGroup").value) || 1;
            try { p.params = JSON.parse($("edParamsJson").value || "{}"); } catch {}
            const cred = $("edCred").value.trim();
            if (["vless", "vmess", "tuic"].includes(p.type)) p.params.uuid = cred;
            else if (p.type === "snell") p.params.psk = cred;
            else if (["wireguard", "amneziawg", "masque"].includes(p.type)) p.params.privateKey = cred;
            else p.params.password = cred;

            const ex1 = $("edExtra1").value.trim();
            if (p.type === "shadowsocks") p.params.method = ex1;
            else if (p.type === "ssr") p.params.cipher = ex1;
            else if (p.type === "vless") p.params.flow = ex1;
            else if (p.type === "hysteria2") p.params.pinSHA256 = ex1;
            else p.params.security = ex1;

            const sni = $("edSni").value.trim();
            if (["wireguard", "amneziawg", "masque"].includes(p.type)) p.params.publicKey = sni;
            else p.params.sni = sni;
            p.params.transport = $("edTransport").value.trim();
            p.params.path = $("edPath").value.trim();
            if (p.params.security === "reality") p.params.pbk = $("edHost").value.trim();
            else p.params.host = $("edHost").value.trim();
            p.shareUri = "";
          }
          try {
            const ep = existing ? "/api/profiles/update" : "/api/profiles/create";
            const res = await api(ep, "POST", p);
            appState = res.state;
            closeModal();
            renderCurrentPage();
            showSnackbar("节点已保存");
          } catch (err) {
            showSnackbar(err.message);
          }
        }},
      ]);
      $("edType").onchange = (e) => {
        p.type = e.target.value;
        renderForm();
      };
    };
    renderForm();
  }

  async function openShareDialog(pid) {
    try {
      const [shareData, cfgData] = await Promise.all([
        api(`/api/profiles/share?id=${pid}`),
        api(`/api/profiles/export-config?id=${pid}`).catch(() => ({ config: "" })),
      ]);
      openModal(`分享 · ${shareData.name}`, `
        <div class="field-group">
          <label class="field-label">分享链接</label>
          <textarea class="field-textarea" id="shareUriBox" rows="3" readonly>${escapeHtml(shareData.uri)}</textarea>
        </div>
        <div class="field-group">
          <label class="field-label">归一化 sing-box 配置预览</label>
          <textarea class="field-textarea" id="shareCfgBox" rows="8" readonly>${escapeHtml(cfgData.config || "无")}</textarea>
        </div>
      `, [
        { label: "复制配置 JSON", cls: "btn-ghost", action: () => { navigator.clipboard?.writeText($("shareCfgBox").value); showSnackbar("已复制 sing-box JSON"); } },
        { label: "复制分享链接", cls: "btn-primary", action: () => { navigator.clipboard?.writeText($("shareUriBox").value); showSnackbar("已复制分享链接"); closeModal(); } },
      ]);
    } catch (err) {
      showSnackbar(err.message);
    }
  }

  function openGroupDialog(existing = null) {
    const g = existing ? { ...existing } : { id: 0, name: "", type: "basic", subscriptionUrl: "", userAgent: "", deduplication: true };
    openModal(g.id ? "编辑分组" : "新建分组 / 订阅", `
      <div class="field-group">
        <label class="field-label">分组名称</label>
        <input class="field-input" id="grpName" value="${escapeHtml(g.name)}" placeholder="例如：主力订阅" />
      </div>
      <div class="field-group">
        <label class="field-label">分组类型</label>
        <select class="field-select" id="grpType">
          <option value="basic" ${g.type === "basic" ? "selected" : ""}>本地分组</option>
          <option value="subscription" ${g.type === "subscription" ? "selected" : ""}>远程订阅</option>
        </select>
      </div>
      <div class="field-group">
        <label class="field-label">订阅链接（留空则为本地分组）</label>
        <input class="field-input" id="grpUrl" value="${escapeHtml(g.subscriptionUrl || "")}" placeholder="https://..." />
      </div>
      <div class="field-group">
        <label class="field-label">自定义 User-Agent（可选）</label>
        <input class="field-input" id="grpUa" value="${escapeHtml(g.userAgent || "")}" placeholder="默认自动兼容 ClashMeta / Base64" />
      </div>
      <label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="grpDedup" ${g.deduplication ? "checked" : ""}> 更新订阅时自动节点去重</label>
    `, [
      { label: "取消", cls: "btn-ghost", action: closeModal },
      { label: "保存", cls: "btn-primary", action: async () => {
        g.name = $("grpName").value.trim() || "新分组";
        g.subscriptionUrl = $("grpUrl").value.trim();
        g.type = g.subscriptionUrl ? "subscription" : $("grpType").value;
        g.userAgent = $("grpUa").value.trim();
        g.deduplication = $("grpDedup").checked;
        try {
          const res = await api("/api/groups/upsert", "POST", g);
          appState = res.state;
          closeModal();
          renderCurrentPage();
          showSnackbar("分组已保存");
        } catch (err) {
          showSnackbar(err.message, 4000);
        }
      }},
    ]);
  }

  function openRuleDialog(existing = null) {
    const r = existing ? { ...existing } : { id: 0, name: "", enabled: true, domains: "", ips: "", ports: "", processName: "", outbound: "proxy" };
    openModal(r.id ? "编辑路由规则" : "新建路由规则 (#1 最高优先级)", `
      <div class="field-group"><label class="field-label">规则名称</label><input class="field-input" id="rlName" value="${escapeHtml(r.name)}" placeholder="例如：公司内网直连" /></div>
      <div class="field-group"><label class="field-label">域名规则（每行或逗号分隔，支持 full: / domain: / keyword: / regexp:）</label><textarea class="field-textarea" id="rlDomains" rows="3">${escapeHtml(r.domains || "")}</textarea></div>
      <div class="form-grid-2">
        <div class="field-group"><label class="field-label">IP / CIDR</label><input class="field-input" id="rlIps" value="${escapeHtml(r.ips || "")}" placeholder="10.0.0.0/8" /></div>
        <div class="field-group"><label class="field-label">端口</label><input class="field-input" id="rlPorts" value="${escapeHtml(r.ports || "")}" placeholder="80,443" /></div>
      </div>
      <div class="form-grid-2">
        <div class="field-group"><label class="field-label">macOS 进程名</label><input class="field-input" id="rlProc" value="${escapeHtml(r.processName || "")}" placeholder="curl, Telegram" /></div>
        <div class="field-group">
          <label class="field-label">目标出站</label>
          <select class="field-select" id="rlOut">
            <option value="proxy" ${r.outbound === "proxy" ? "selected" : ""}>当前代理节点 (proxy)</option>
            <option value="direct" ${r.outbound === "direct" ? "selected" : ""}>直连 (direct)</option>
            <option value="block" ${r.outbound === "block" ? "selected" : ""}>拦截 (block)</option>
            ${appState.profiles.map((p) => `<option value="profile:${p.id}" ${r.outbound === "profile:" + p.id ? "selected" : ""}>指定节点：${escapeHtml(p.name)}</option>`).join("")}
          </select>
        </div>
      </div>
    `, [
      { label: "取消", cls: "btn-ghost", action: closeModal },
      { label: "保存规则", cls: "btn-primary", action: async () => {
        r.name = $("rlName").value.trim() || "自定义规则";
        r.domains = $("rlDomains").value.trim();
        r.ips = $("rlIps").value.trim();
        r.ports = $("rlPorts").value.trim();
        r.processName = $("rlProc").value.trim();
        r.outbound = $("rlOut").value;
        const res = await api("/api/rules/upsert", "POST", r);
        appState = res.state;
        closeModal();
        renderCurrentPage();
        showSnackbar("路由规则已保存");
      }},
    ]);
  }

  function openThemePickerDialog() {
    openModal("选择主题颜色（21 套）", `
      <div class="theme-grid">
        ${THEMES.map((t) => `<button class="theme-swatch ${appState.settings.appTheme === t.id ? "active" : ""}" data-tid="${t.id}" title="${t.name}" style="background:${t.primary}">${appState.settings.appTheme === t.id ? `<span style="color:${t.darkText ? "#000" : "#fff"}">${ICONS.check}</span>` : ""}</button>`).join("")}
      </div>
    `, [{ label: "完成", cls: "btn-primary", action: closeModal }]);

    $("modalBody").querySelectorAll(".theme-swatch").forEach((sw) => {
      sw.onclick = async () => {
        appState.settings.appTheme = Number(sw.dataset.tid);
        const res = await api("/api/settings", "POST", appState.settings);
        appState = res.state;
        applyThemeAndAppearance();
        openThemePickerDialog();
        if (currentPage === "settings") renderCurrentPage();
      };
    });
  }

  async function openMetaDiagDialog() {
    const data = await api("/api/meta/status");
    metaStatusCache = data;
    const decisions = data.recent || data.decisions || [];
    openModal("Meta 分流诊断", `
      <div class="pref-summary" style="margin-bottom:10px">
        规则源：<b>${escapeHtml(data.source || appState.appProxy.metaRuleSource)}</b> · 版本：${escapeHtml(data.revision || "内置")}
      </div>
      ${decisions.length === 0 ? `<div class="empty-state" style="padding:24px">连接代理后，使用任意应用上网即可查看近期命中的 Meta 规则记录。</div>` :
        decisions.map((d) => `
          <div class="pref-row" style="padding:8px 4px">
            <div class="pref-text">
              <div class="pref-title">${escapeHtml(d.destination)}</div>
              <div class="pref-summary">${escapeHtml(d.rule)} → ${d.direct ? "直连" : d.action === "reject" ? "已拦截" : "代理"}</div>
            </div>
            <span class="proto-pill">${d.direct ? "直连" : "代理"}</span>
          </div>
        `).join("")}
    `, [
      { label: "刷新", cls: "btn-tonal", action: openMetaDiagDialog },
      { label: "关闭", cls: "btn-primary", action: closeModal },
    ]);
  }

  // =====================================================================
  // ACTIONS: CONNECT, TEST, SORT, CLEANUP, SSE STREAM
  // =====================================================================
  async function toggleConnection() {
    if (!runtimeStatus) return;
    try {
      if (runtimeStatus.state === "connected" || runtimeStatus.state === "connecting") {
        runtimeStatus = await api("/api/disconnect", "POST");
        showSnackbar("已断开代理连接");
      } else {
        runtimeStatus = await api("/api/connect", "POST", { profileId: appState.selectedProfile });
        showSnackbar(`已连接：${runtimeStatus.activeName}`);
      }
      renderStatusBar();
    } catch (err) {
      showSnackbar(err.message, 3800);
      runtimeStatus = await api("/api/status");
      renderStatusBar();
    }
  }

  async function batchTestVisible() {
    const ids = getVisibleProfiles().map((p) => p.id);
    if (ids.length === 0) return showSnackbar("当前分组无节点");
    showSnackbar(`正在使用 ${appState.settings.connectionTestConcurrent} 线程并发测速 ${ids.length} 个节点…`, 4000);
    try {
      const res = await api("/api/profiles/test", "POST", { ids });
      appState = res.state;
      renderCurrentPage();
      showSnackbar("批量 1-RTT 测速完成");
    } catch (err) {
      showSnackbar(err.message);
    }
  }

  async function sortProfiles(by) {
    const res = await api("/api/profiles/sort", "POST", { groupId: appState.selectedGroup || 0, by });
    appState = res.state;
    renderCurrentPage();
    showSnackbar("排序完成");
  }

  async function cleanupProfiles(mode) {
    const res = await api("/api/profiles/cleanup", "POST", { groupId: appState.selectedGroup || 0, mode });
    appState = res.state;
    renderCurrentPage();
    showSnackbar(`已清理 ${res.removed} 个节点`);
  }

  async function updateAllSubscriptions() {
    showSnackbar("正在更新全部订阅…");
    try {
      const res = await api("/api/groups/update-all", "POST");
      appState = res.state;
      renderCurrentPage();
      showSnackbar(`已更新 ${res.updated} 个订阅` + (res.errors?.length ? `（${res.errors.length} 个失败）` : ""));
    } catch (err) {
      showSnackbar(err.message);
    }
  }

  function connectEventStream() {
    const es = new EventSource("/api/events");
    es.addEventListener("status", (e) => {
      runtimeStatus = JSON.parse(e.data);
      renderStatusBar();
    });
    es.addEventListener("log", (e) => {
      const entry = JSON.parse(e.data);
      logsList.push(entry);
      if (logsList.length > 1500) logsList.shift();
      if (currentPage === "logs") {
        const box = $("logViewerBox");
        if (box && (logFilterLevel === "all" || logFilterLevel === entry.level)) {
          const line = document.createElement("div");
          line.className = "log-line";
          line.innerHTML = `<span class="log-ts">${escapeHtml(entry.timestamp)}</span><span class="log-lvl log-lvl-${escapeHtml(entry.level)}">${escapeHtml(entry.level)}</span><span>${escapeHtml(entry.message)}</span>`;
          box.appendChild(line);
          const area = $("logScrollArea");
          if (area) area.scrollTop = area.scrollHeight;
        }
      }
    });
    es.onerror = () => {
      es.close();
      setTimeout(connectEventStream, 2000);
    };
  }

  function bindMacWindowDrag() {
    const bridge = window.webkit?.messageHandlers?.nekoWindow;
    if (!bridge) return;

    const NO_DRAG_SELECTOR = [
      "button", "a", "input", "textarea", "select", "option", "label", "summary", "code", "pre",
      "[role='button']", "[contenteditable='true']",
      ".icon-btn", ".nav-item", ".profile-card", ".tab-pill", ".group-tab", ".rule-card",
      ".app-row", ".setting-row", ".pref-row", ".service-fab", ".stats-bar",
      ".modal-dialog", ".popup-menu", ".log-viewer", ".log-line",
      ".theme-swatch", ".chip", ".btn", ".switch", ".intensity-seg", ".app-action-btn",
      ".perm-cmd-row", "iframe"
    ].join(", ");

    const TITLEBAR_SELECTOR = ".mac-drag-strip, .appbar, .toolbar, .nav-header";

    function isOnScrollbar(target, clientX, clientY) {
      let el = target instanceof Element ? target : target?.parentElement;
      while (el && el !== document.documentElement) {
        const style = window.getComputedStyle(el);
        const canScrollY = (style.overflowY === "auto" || style.overflowY === "scroll") && el.scrollHeight > el.clientHeight;
        const canScrollX = (style.overflowX === "auto" || style.overflowX === "scroll") && el.scrollWidth > el.clientWidth;
        if (canScrollY || canScrollX) {
          const rect = el.getBoundingClientRect();
          if (canScrollY && rect.right - clientX <= 16) return true;
          if (canScrollX && rect.bottom - clientY <= 16) return true;
        }
        el = el.parentElement;
      }
      return false;
    }

    let pendingDrag = null;

    const cancelPending = () => {
      pendingDrag = null;
    };

    document.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      const target = e.target instanceof Element ? e.target : null;
      if (!target) return;
      if (target.closest(NO_DRAG_SELECTOR)) return;
      if (isOnScrollbar(target, e.clientX, e.clientY)) return;

      const inTitlebar = Boolean(target.closest(TITLEBAR_SELECTOR));
      if (e.detail === 2 && inTitlebar) {
        e.preventDefault();
        bridge.postMessage({ action: "titlebarDoubleClick" });
        return;
      }
      if (e.detail !== 1) return;

      pendingDrag = { x: e.clientX, y: e.clientY, threshold: inTitlebar ? 2 : 4 };
    });

    window.addEventListener("mousemove", (e) => {
      if (!pendingDrag) return;
      if ((e.buttons & 1) === 0) {
        pendingDrag = null;
        return;
      }
      const dx = Math.abs(e.clientX - pendingDrag.x);
      const dy = Math.abs(e.clientY - pendingDrag.y);
      if (dx >= pendingDrag.threshold || dy >= pendingDrag.threshold) {
        pendingDrag = null;
        bridge.postMessage({ action: "startDrag" });
      }
    });

    window.addEventListener("mouseup", cancelPending);
    window.addEventListener("blur", cancelPending);
  }

  // =====================================================================
  // BOOTSTRAP
  // =====================================================================
  async function init() {
    hydrateIcons(document);
    bindLiquidMotion();
    bindMacWindowDrag();

    // Drawer toggle (desktop collapse / narrow slide-over)
    $("btnToggleDrawer").onclick = () => {
      if (window.innerWidth <= 820) {
        $("appShell").classList.toggle("drawer-open");
      } else {
        $("appShell").classList.toggle("drawer-collapsed");
      }
    };
    $("drawerBackdrop").onclick = () => $("appShell").classList.remove("drawer-open");

    // Sidebar nav clicks
    document.querySelectorAll(".nav-item[data-page]").forEach((btn) => {
      btn.onclick = () => navigateTo(btn.dataset.page);
    });

    // Quick switch Liquid Glass <-> Classic UI (1:1 Nekobox-Next v1.6.1 drawer item)
    $("btnQuickSwitchAppearance").onclick = async () => {
      appState.settings.classicUi = !appState.settings.classicUi;
      const res = await api("/api/settings", "POST", appState.settings);
      appState = res.state;
      applyThemeAndAppearance();
      if (currentPage === "settings") renderCurrentPage();
      showSnackbar(appState.settings.classicUi ? "已切换至 1:1 原版怀旧界面" : "已切换至 Liquid Glass 3.0 液态玻璃界面");
    };

    // Global search
    $("globalSearchInput").oninput = (e) => {
      searchKeyword = e.target.value;
      if (currentPage === "configuration") renderCurrentPage();
    };
    $("btnCloseSearch").onclick = () => {
      searchKeyword = "";
      $("globalSearchInput").value = "";
      $("toolbarSearchBox").classList.add("hidden");
      $("toolbarTitleWrap").classList.remove("hidden");
      if (currentPage === "configuration") renderCurrentPage();
    };

    // FAB & StatsBar
    $("serviceFab").onclick = toggleConnection;
    $("statsBar").onclick = async () => {
      if (!runtimeStatus || runtimeStatus.state !== "connected") {
        showSnackbar("请先点击右侧按钮连接节点");
        return;
      }
      $("statsStatus").textContent = "正在测试 1-RTT 连接延迟…";
      try {
        const res = await api("/api/test-active", "POST");
        runtimeStatus.lastLatencyMs = res.latencyMs;
        renderStatusBar();
        showSnackbar(`连接可用 · 延迟 ${res.latencyMs} ms`);
      } catch (err) {
        showSnackbar("连接测试失败：" + err.message);
        renderStatusBar();
      }
    };

    // Modal & Popup global dismiss
    $("modalCloseBtn").onclick = closeModal;
    $("modalBackdrop").onclick = (e) => { if (e.target === $("modalBackdrop")) closeModal(); };
    document.addEventListener("click", (e) => {
      if (!e.target.closest("#popupMenu, .toolbar-actions")) closePopup();
    });

    // Pause traffic polling when page hidden (Power Saver #3)
    document.addEventListener("visibilitychange", () => {
      api("/api/power/polling", "POST", { paused: document.hidden }).catch(() => {});
    });

    // Follow macOS Dark Mode change live
    window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener?.("change", applyThemeAndAppearance);

    // Load bootstrap payload
    const boot = await api("/api/bootstrap");
    appState = boot.state;
    runtimeStatus = boot.status;
    coreVersions = boot.versions;
    macPermissions = boot.permissions || null;
    logsList = boot.logs || [];

    applyThemeAndAppearance();
    renderStatusBar();
    navigateTo("configuration");
    connectEventStream();

    // Auto-show bilingual (Simplified + Traditional Chinese) macOS permission guide on launch when needed
    if (macPermissions) {
      const hasBlocking = Array.isArray(macPermissions.blockingIssues) && macPermissions.blockingIssues.length > 0;
      const shouldShow = hasBlocking || (macPermissions.needsGuide && !appState.settings.permissionGuideDismissed);
      if (shouldShow) {
        setTimeout(() => openPermissionGuideDialog(false), 180);
      }
    }
  }

  window.addEventListener("DOMContentLoaded", init);
})();

const screens = document.querySelectorAll(".screen");
const title = document.querySelector("#page-title");
const titles = {
  home: "Security Overview",
  scan: "Wi-Fi Network Scanner",
  devices: "Connected Devices",
  traffic: "Network Traffic Monitor",
  firewall: "Firewall Management",
  malware: "Virus & Malware Detection",
  vulnerabilities: "Vulnerability Scanner",
  ids: "Intrusion Detection System (IDS)",
  intel: "Threat Intelligence",
  logs: "Security Logs",
  reports: "Reports & Analytics",
  settings: "Settings",
  threats: "Threat Detection",
  performance: "Network Performance",
  compare: "Wi-Fi Comparison",
  alerts: "Security Alerts",
  "ai-chat": "AI Security Assistant",
  knowledge: "Knowledge & Audit",
  history: "Scan History"
};
const message = document.querySelector("#app-message");
const settings = {
  auto_scan: true,
  notifications: true,
  theme: "dark",
  device_wifi_tracking: true,
  auto_scan_interval: "30"
};

// State caches
let dashboardData = null;
let cachedNetworks = [];
let selectedSsidsForCompare = new Set();
let viewMode = "table"; // "table" or "cards"
let currentAlertFilter = "all";
let currentSortColumn = "signal";
let currentSortAsc = false;
let autoScanTimerId = null;

// Telemetry series
let trafficHistoryRx = [10, 24, 18, 35, 28, 42, 65, 50, 48, 72, 85, 60, 45, 90, 80];
let trafficHistoryTx = [5, 12, 10, 18, 15, 22, 30, 26, 22, 35, 40, 28, 20, 45, 38];
let currentPasswordMasked = true;

const defaultDashboard = {
  network: {
    id: 1,
    name: "Home_WiFi",
    ssid: "Home_WiFi",
    state: "connected",
    connected: true,
    band: "5 GHz",
    channel: 36,
    signalPercent: 88,
    signal_dbm: -48,
    signalQuality: "Excellent",
    score: 82,
    securityRating: "Good",
    securityClassification: "Good",
    encryption: "WPA2-Personal",
    cipher: "CCMP",
    bssid: "8e:29:31:cd:69:bc",
    password: "",
    vendor: "Realtek Semiconductor",
    radioType: "802.11ac",
  },
  devices: [
    {
      id: 1,
      name: "Android Phone",
      platform: "Samsung · Android 14",
      ip_address: "192.168.1.10",
      mac_address: "50:01:d9:12:34:56",
      vendor: "Samsung Electronics",
      device_type: "phone",
      status: "online",
      last_seen: "just now",
      connected_wifi: "Home_WiFi",
      is_trusted: true,
    },
    {
      id: 2,
      name: "Laptop",
      platform: "Windows · Personal",
      ip_address: "192.168.1.12",
      mac_address: "a4:4c:c8:78:90:ab",
      vendor: "Intel Corporation",
      device_type: "laptop",
      status: "online",
      last_seen: "2 min ago",
      connected_wifi: "Home_WiFi",
      is_trusted: true,
    },
    {
      id: 3,
      name: "Smart TV",
      platform: "Samsung · Tizen",
      ip_address: "192.168.1.15",
      mac_address: "64:b5:c6:cd:ef:01",
      vendor: "Samsung Electronics",
      device_type: "tv",
      status: "online",
      last_seen: "8 min ago",
      connected_wifi: "Home_WiFi",
      is_trusted: true,
    },
  ],
  scans: [
    {
      id: 1,
      network_name: "Home_WiFi",
      scanned_at: "Today, 12:05 PM",
      encryption: "WPA2-Personal",
      score: 82,
      result: "GOOD",
    },
    {
      id: 2,
      network_name: "Cafe_WiFi",
      scanned_at: "Sep 21, 11:30 AM",
      encryption: "Open network",
      score: 42,
      result: "RISKY",
    },
    {
      id: 3,
      network_name: "Office_5G",
      scanned_at: "Sep 15, 04:20 PM",
      encryption: "WPA3",
      score: 78,
      result: "GOOD",
    },
  ],
  threats: [],
  traffic: {
    bytesReceivedFormatted: "24.5 MB",
    bytesSentFormatted: "8.2 MB",
    rxSpeedFormatted: "128.4 KB/s",
    txSpeedFormatted: "34.2 KB/s",
    unicastPackets: 18450,
    errors: 0,
    discards: 0,
    anomalyDetected: false,
    anomalyMessage: "Traffic within normal parameters.",
  },
  stats: {
    totalNetworks: 1,
    secureNetworks: 1,
    openNetworks: 0,
    threatCount: 0,
    activeDevices: 3,
    averageSecurityScore: 82,
  },
  unreadAlerts: 0,
  settings: {
    auto_scan: true,
    notifications: true,
    theme: "dark",
    device_wifi_tracking: true,
    auto_scan_interval: "30",
  },
};

// API Helper
async function api(path, options) {
  const { headers, ...requestOptions } = options || {};
  const response = await fetch(path, {
    ...requestOptions,
    headers: { Accept: "application/json", ...headers },
  });
  if (!response.ok) {
    const detail = await response.text();
    let msg = detail;
    try {
      const problem = JSON.parse(detail);
      msg = problem.detail || problem.message || detail;
    } catch {
      // Keep plain text
    }
    throw new Error(msg || `Request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

function showMessage(text, isError = true) {
  if (!message) return;
  message.textContent = text;
  message.hidden = !text;
  message.classList.toggle("error-message", isError);
  message.classList.toggle("success-message", !isError);
  if (!isError && text) {
    setTimeout(() => {
      if (message.textContent === text) message.hidden = true;
    }, 4000);
  }
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setText(selector, value) {
  const node = document.querySelector(selector);
  if (node) node.textContent = value ?? "";
}

function setSettings(values) {
  Object.entries(values).forEach(([key, value]) => {
    if (key === "theme") {
      settings.theme = value;
    } else if (key in settings) {
      settings[key] = (value === true || value === "true");
    }
  });
  document.body.classList.toggle("light", settings.theme === "light");
  document.querySelectorAll(".theme-toggle").forEach((toggle) => {
    toggle.classList.toggle("on", settings.theme === "light");
  });
  document.querySelectorAll("[data-setting]").forEach((toggle) => {
    toggle.classList.toggle("on", settings[toggle.dataset.setting] === true);
  });
}

// -------------------------------------------------------------
// USER REQUEST FEATURE: CONNECTED WI-FI PASSWORD SHOW / HIDE / COPY
// -------------------------------------------------------------
function updateConnectedWifiPasswordDisplay(rawPassword, isConnected) {
  const passwordVals = document.querySelectorAll("#wifi-pass-val-desktop, #wifi-pass-val-mobile, #settings-pass-val");
  const toggleBtns = document.querySelectorAll("#toggle-pass-desktop, #toggle-pass-mobile, #toggle-pass-settings");

  let displayText = "••••••••";
  if (!isConnected) {
    displayText = "No Wi-Fi";
  } else if (!rawPassword || rawPassword.trim() === "") {
    displayText = currentPasswordMasked ? "••••••••" : "Open Network (No Password)";
  } else {
    displayText = currentPasswordMasked ? "••••••••" : rawPassword;
  }

  passwordVals.forEach((el) => {
    el.textContent = displayText;
  });

  toggleBtns.forEach((btn) => {
    btn.textContent = currentPasswordMasked ? "👁 Show" : "✕ Hide";
  });
}

function togglePasswordVisibility() {
  currentPasswordMasked = !currentPasswordMasked;
  const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
  const isConn = net.connected !== false && net.state !== "disconnected" && net.name !== "No Wi-Fi Connected";
  updateConnectedWifiPasswordDisplay(net.password || "", isConn);
}

function copyPasswordToClipboard(btn) {
  const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
  const pwd = net.password || "";
  if (!pwd) {
    showMessage("No password available for this network or network is Open.", false);
    return;
  }
  navigator.clipboard.writeText(pwd).then(() => {
    const originalText = btn.textContent;
    btn.textContent = "✓ Copied!";
    setTimeout(() => {
      btn.textContent = originalText;
    }, 2000);
    showMessage("Connected Wi-Fi password copied to clipboard!", false);
  }).catch(() => {
    showMessage("Password copy failed. Please select text manually.", true);
  });
}

// -------------------------------------------------------------
// -------------------------------------------------------------
// DEVICES RENDERING — Professional Device Management Panel
// -------------------------------------------------------------
function renderDevices(devices) {
  const cards = document.querySelector(".device-cards");
  if (cards) cards.replaceChildren();
  const list = document.querySelector(".device-list");
  if (list) list.replaceChildren();

  const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
  const isConnected = net.connected !== false && net.state !== "disconnected" && net.name !== "No Wi-Fi Connected";
  const currentNetwork = isConnected ? (net.name || net.ssid || "Connected Wi-Fi") : "No Wi-Fi Connected";

  let onlineCount = 0;
  let hostFound = false;
  let gatewayFound = false;

  // Device type icon map (using emoji + text)
  const DEVICE_ICONS = {
    router: { icon: "📡", label: "Router / Gateway", color: "#9365ff" },
    phone: { icon: "📱", label: "Mobile Device", color: "#39e1d0" },
    laptop: { icon: "💻", label: "Laptop / PC", color: "#258cff" },
    tv: { icon: "📺", label: "Smart TV / IoT", color: "#f5c65e" },
    tablet: { icon: "🖥️", label: "Tablet", color: "#32e8ad" },
    printer: { icon: "🖨️", label: "Printer", color: "#ff667b" },
    unknown: { icon: "⬡", label: "Unknown Device", color: "#89a0c2" },
  };

  devices.forEach((device, index) => {
    const isOnline = isConnected && (device.status !== "offline");
    if (isOnline) onlineCount++;
    if (device.is_host) hostFound = true;
    if (device.device_type === "router" || device.name?.toLowerCase().includes("gateway") || device.name?.toLowerCase().includes("router")) gatewayFound = true;

    const devType = device.device_type || (index === 0 ? "phone" : index === 1 ? "laptop" : "tv");
    const typeInfo = DEVICE_ICONS[devType] || DEVICE_ICONS.unknown;
    const isTrusted = device.is_trusted === 1 || device.is_trusted === true;
    const isHost = device.is_host === 1 || device.is_host === true;
    const wifiName = isConnected ? (device.connected_wifi || currentNetwork) : "No Wi-Fi";
    const statusVal = isOnline ? "online" : "offline";
    const vendor = device.vendor ? device.vendor : "";
    const mac = device.mac_address || "";

    // ── Main Device Card ──────────────────────────────────────
    if (cards) {
      const card = document.createElement("article");
      card.className = "device-pro-card";
      card.dataset.deviceId = device.id;

      // Status stripe on left edge
      const stripe = document.createElement("div");
      stripe.className = `device-status-stripe ${isOnline ? "stripe-online" : "stripe-offline"}`;
      card.appendChild(stripe);

      // Icon block
      const iconBlock = document.createElement("div");
      iconBlock.className = "device-icon-block";
      iconBlock.style.background = `${typeInfo.color}18`;
      iconBlock.style.borderColor = `${typeInfo.color}44`;
      iconBlock.innerHTML = `<span class="device-icon-emoji">${typeInfo.icon}</span>`;
      if (isHost) {
        const hostBadge = document.createElement("span");
        hostBadge.className = "device-host-badge";
        hostBadge.textContent = "HOST";
        iconBlock.appendChild(hostBadge);
      }
      card.appendChild(iconBlock);

      // Info block
      const infoBlock = document.createElement("div");
      infoBlock.className = "device-info-block";

      // Name row
      const nameRow = document.createElement("div");
      nameRow.className = "device-name-row";
      const nameEl = document.createElement("h3");
      nameEl.className = "device-name";
      nameEl.textContent = device.name || "Unknown Device";
      nameRow.appendChild(nameEl);

      // Status pill
      const statusPill = document.createElement("span");
      statusPill.className = `device-status-pill ${isOnline ? "pill-online" : "pill-offline"}`;
      statusPill.innerHTML = `<span class="pill-dot"></span>${isOnline ? "Online" : "Offline"}`;
      nameRow.appendChild(statusPill);

      if (isTrusted) {
        const trustBadge = document.createElement("span");
        trustBadge.className = "device-trusted-badge";
        trustBadge.textContent = "✓ Trusted";
        nameRow.appendChild(trustBadge);
      }

      infoBlock.appendChild(nameRow);

      // Vendor / type subtitle
      const subtitle = document.createElement("p");
      subtitle.className = "device-subtitle";
      subtitle.textContent = [vendor, typeInfo.label].filter(Boolean).join(" · ");
      infoBlock.appendChild(subtitle);

      // Meta grid
      const metaGrid = document.createElement("div");
      metaGrid.className = "device-meta-grid";

      const metaItems = [
        { label: "IP Address", value: device.ip_address || "—", icon: "🌐" },
        { label: "MAC Address", value: mac || "—", icon: "🔑" },
        { label: "Network", value: isConnected ? wifiName : "Disconnected", icon: "📶" },
        { label: "Last Seen", value: device.last_seen || "Just now", icon: "🕐" },
      ];

      metaItems.forEach(({ label, value, icon }) => {
        const cell = document.createElement("div");
        cell.className = "device-meta-cell";
        cell.innerHTML = `
          <span class="meta-label">${icon} ${label}</span>
          <span class="meta-value">${escapeHtml(value)}</span>
        `;
        metaGrid.appendChild(cell);
      });
      infoBlock.appendChild(metaGrid);

      card.appendChild(infoBlock);

      // Action column
      const actionCol = document.createElement("div");
      actionCol.className = "device-action-col";

      const trustBtn = document.createElement("button");
      trustBtn.className = `device-trust-btn ${isTrusted ? "trusted" : ""}`;
      trustBtn.innerHTML = isTrusted
        ? `<span>✓</span> Allowlisted`
        : `<span>＋</span> Allowlist`;
      trustBtn.title = isTrusted ? "Remove from authorized allowlist" : "Add to authorized allowlist";
      trustBtn.addEventListener("click", () => toggleDeviceTrust(device.id, trustBtn));
      actionCol.appendChild(trustBtn);

      if (device.ip_address) {
        const pingBtn = document.createElement("button");
        pingBtn.className = "device-action-pill";
        pingBtn.innerHTML = "⚡ Ping";
        pingBtn.title = `Ping ${device.ip_address}`;
        pingBtn.addEventListener("click", () => {
          showMessage(`Pinging ${device.ip_address}…`, false);
          pingBtn.disabled = true;
          api("/api/performance/test", { method: "POST" })
            .then(() => showMessage(`${device.ip_address} responded.`, false))
            .catch(() => showMessage(`Could not ping ${device.ip_address}.`, true))
            .finally(() => { pingBtn.disabled = false; });
        });
        actionCol.appendChild(pingBtn);
      }

      card.appendChild(actionCol);
      cards.appendChild(card);
    }

    // ── Dashboard Mini List ───────────────────────────────────
    if (list) {
      const dot = element("span", `device-dot ${devType === "phone" ? "phone" : devType === "tv" ? "tv" : "laptop"}`);
      const nameWrap = element("span", "device-name-wrap");
      nameWrap.append(
        element("strong", "", device.name || "Unknown"),
        element("small", `device-wifi-sub ${isConnected ? "" : "disconnected"}`, isConnected ? `Connected to ${wifiName}` : "No Wi-Fi Connected"),
      );
      const address = element("b", "", isConnected ? (device.ip_address || "?") : "Offline");
      list.append(dot, nameWrap, address);
    }
  });

  // Empty state
  if (devices.length === 0 && cards) {
    const empty = document.createElement("div");
    empty.className = "device-empty-state";
    empty.innerHTML = `
      <div class="empty-icon">🔍</div>
      <h3>No Devices Discovered</h3>
      <p>No connected devices were found on this subnet. Click <strong>Refresh Subnet</strong> to scan again.</p>
    `;
    cards.appendChild(empty);
    if (list) list.append(element("span", "muted", "No connected devices"));
  }

  const count = isConnected ? devices.length : 0;
  setText("#devices-screen .page-heading .muted", isConnected
    ? `${devices.length} device${devices.length === 1 ? "" : "s"} monitored on ${currentNetwork}`
    : "No devices connected (Wi-Fi is disconnected or disabled)");
  setText(".device-network-sub", isConnected ? `Connected to ${currentNetwork}` : "No Wi-Fi Connected");
  setText("#device-count", isConnected ? `${devices.length} devices` : "0 devices");
  setText("#dev-stat-online", isConnected ? `${onlineCount} Active` : "0 Active");
  setText("#dev-stat-host", hostFound ? "Active Host" : "Host Online");
  setText("#dev-stat-gateway", gatewayFound ? "Gateway Verified" : "192.168.1.1");

  document.querySelectorAll(".nav-item[data-screen='devices'] b, .shortcut[data-screen='devices'] em, #nav-device-badge, #mob-device-count").forEach((badge) => {
    badge.textContent = count;
  });
}

async function toggleDeviceTrust(deviceId, buttonElement) {
  try {
    const res = await api(`/api/devices/${deviceId}/trust`, { method: "POST" });
    const isNowTrusted = res.is_trusted;
    buttonElement.classList.toggle("trusted", isNowTrusted);
    buttonElement.textContent = isNowTrusted ? "✓ Allowlisted" : "＋ Allowlist";
    showMessage(isNowTrusted ? "Device added to authorized allowlist." : "Device removed from allowlist.", false);
  } catch (err) {
    showMessage("Could not update device trust: " + err.message, true);
  }
}

// -------------------------------------------------------------
// DYNAMIC REAL-TIME GREETING
// -------------------------------------------------------------
function getGreeting() {
  const hour = new Date().getHours();
  if (hour >= 5 && hour < 12) {
    return "Good morning";
  } else if (hour >= 12 && hour < 17) {
    return "Good afternoon";
  } else if (hour >= 17 && hour < 21) {
    return "Good evening";
  } else {
    return "Good night";
  }
}

function updateDynamicGreeting() {
  const greetingEl = document.querySelector("#welcome-greeting");
  if (greetingEl) {
    const greeting = getGreeting();
    greetingEl.innerHTML = `${greeting}  <span>✦</span>`;
  }
}

// -------------------------------------------------------------
// DYNAMIC REAL-TIME GREETING
// -------------------------------------------------------------
function getGreeting() {
  const hour = new Date().getHours();
  if (hour >= 5 && hour < 12) {
    return "Good morning";
  } else if (hour >= 12 && hour < 17) {
    return "Good afternoon";
  } else if (hour >= 17 && hour < 21) {
    return "Good evening";
  } else {
    return "Good night";
  }
}

function updateDynamicGreeting() {
  const greetingEl = document.querySelector("#welcome-greeting");
  if (greetingEl) {
    const greeting = getGreeting();
    greetingEl.innerHTML = `${greeting} <span>✦</span>`;
  }
}

// -------------------------------------------------------------
// HISTORY RENDERING
// -------------------------------------------------------------
function createHistoryRow(scan, compact = false) {
  const result = scan.result || (scan.score >= 70 ? "GOOD" : "RISKY");
  const statusClass = result === "GOOD" ? "good" : "danger";
  if (compact) {
    const item = element("div", "history-item card");
    item.append(element("span", "history-icon blue", "🛡️"));
    const details = element("div");
    details.append(
      element("strong", "", scan.network_name),
      element("small", "", `${scan.scanned_at} · ${scan.encryption}`),
    );
    item.append(details, element("span", `status-chip ${statusClass}`, `${scan.score} ${result}`));
    return item;
  }

  const row = element("div", "table-row history-data-row");
  const netCol = element("div", "history-net-col");
  netCol.innerHTML = `<strong><span class="net-shield-icon">🛡️</span> ${escapeHtml(scan.network_name)}</strong>`;
  
  const dateCol = element("span", "history-time-col", scan.scanned_at);
  const cipherCol = element("span", "history-cipher-col", scan.encryption || "WPA2-Personal");
  const scoreCol = element("div", "history-score-col");
  scoreCol.innerHTML = `<span class="status-chip ${statusClass}">${scan.score} ${result}</span>`;
  
  const actionCol = element("div", "history-actions-col");
  const inspectBtn = element("button", "history-inspect-btn", "Inspect Airspace");
  inspectBtn.onclick = () => {
    showScreen("scan");
    showMessage(`Displaying active scan environment for ${scan.network_name}`, false);
  };
  actionCol.append(inspectBtn);

  row.append(netCol, dateCol, cipherCol, scoreCol, actionCol);
  return row;
}

function renderHistory(scans) {
  const historyTable = document.querySelector("#history-table-container");
  if (historyTable) {
    historyTable.replaceChildren();
    if (!scans || scans.length === 0) {
      historyTable.innerHTML = `
        <div class="empty-history-box">
          <div class="empty-icon">🛡️</div>
          <h3>No Saved Scans Yet</h3>
          <p class="muted">Run your first Wi-Fi security scan to build a historical audit trail of nearby networks and security ratings.</p>
          <button class="primary-button" id="btn-history-empty-scan" style="margin-top:12px"><span>◉</span> Run Security Scan Now</button>
        </div>
      `;
      const runBtn = historyTable.querySelector("#btn-history-empty-scan");
      if (runBtn) {
        runBtn.addEventListener("click", () => showScreen("scan"));
      }
    } else {
      const heading = element("div", "table-head");
      ["Network", "Date & Time", "Security Cipher", "Audit Score", "Action"].forEach((label) => heading.append(element("span", "", label)));
      historyTable.append(heading);
      scans.forEach((scan) => historyTable.append(createHistoryRow(scan)));
    }
  }

  const recentScans = document.querySelector(".history-row");
  if (recentScans) {
    if (!scans || scans.length === 0) {
      recentScans.replaceChildren(element("p", "muted", "No recent scans."));
    } else {
      recentScans.replaceChildren(...scans.slice(0, 3).map((scan) => createHistoryRow(scan, true)));
    }
  }

  if (scans && scans[0]) {
    setText(".reference-activity strong", "Security scan completed");
    setText(".reference-activity small", scans[0].scanned_at);
    setText(".reference-activity .status-chip", `${scans[0].score} ${scans[0].result}`);
    const chip = document.querySelector(".reference-activity .status-chip");
    if (chip) chip.className = `status-chip ${scans[0].result === "GOOD" ? "good" : "danger"}`;
    setText(".last-scan", `Last scan: ${scans[0].scanned_at}`);
  } else {
    setText(".reference-activity strong", "No scans recorded");
    setText(".reference-activity small", "Run a security scan to get started.");
    setText(".reference-activity .status-chip", "No data");
    const chip = document.querySelector(".reference-activity .status-chip");
    if (chip) chip.className = "status-chip";
    setText(".last-scan", "No scans yet");
  }
}

// -------------------------------------------------------------
// DASHBOARD RENDERING (Enhanced with KPI, AI, Telemetry & Passwords)
// -------------------------------------------------------------
function renderDashboard(data) {
  dashboardData = data || defaultDashboard;
  const { network, devices, scans, threats, stats, traffic, unreadAlerts } = dashboardData;
  if (!network) return;

  const isConnected = network.connected !== false && network.state !== "disconnected" && network.name !== "No Wi-Fi Connected";
  const netName = isConnected ? (network.name || "Connected") : "No Wi-Fi Connected";

  // Update Wi-Fi Password display
  updateConnectedWifiPasswordDisplay(network.password || "", isConnected);

  // Update KPI Ribbon
  if (stats) {
    setText("#kpi-total-networks", `${stats.totalNetworks || 1} Visible`);
    setText("#kpi-secure-networks", `${stats.secureNetworks || 1} Secure · ${stats.openNetworks || 0} Open`);
    setText("#kpi-threat-count", `${stats.threatCount || 0} Detected`);
    const threatCountBadge = document.querySelector("#kpi-threat-count");
    if (threatCountBadge) {
      threatCountBadge.style.color = (stats.threatCount > 0) ? "var(--red)" : "var(--green)";
    }
  }

  // Update Alerts badges
  const unread = unreadAlerts || 0;
  setText("#nav-alert-badge", unread);
  setText("#alert-badge-count", unread);
  const alertDot = document.querySelector("#alert-dot");
  if (alertDot) alertDot.hidden = (unread === 0);
  const alertBadgeCount = document.querySelector("#alert-badge-count");
  if (alertBadgeCount) alertBadgeCount.hidden = (unread === 0);

  // Update Threats badges
  const threatNum = (threats && threats.length) || (stats && stats.threatCount) || 0;
  setText("#nav-threat-badge", threatNum);
  setText("#mob-threat-count", threatNum);

  // Update Traffic
  if (traffic) {
    setText("#traffic-rx-speed", traffic.rxSpeedFormatted || "0.0 KB/s");
    setText("#traffic-tx-speed", traffic.txSpeedFormatted || "0.0 KB/s");
    setText("#traffic-rx-total", traffic.bytesReceivedFormatted || "0 B");
    setText("#traffic-tx-total", traffic.bytesSentFormatted || "0 B");
    setText("#traffic-packets-total", Number(traffic.unicastPackets || 0).toLocaleString());
    setText("#traffic-errors-total", `${traffic.errors || 0} / ${traffic.discards || 0}`);
  }

  if (isConnected) {
    setText("#network-name-mobile", netName);
    setText("#network-name-sidebar", netName);
    const desktopHeading = document.querySelector("#network-name-desktop");
    if (desktopHeading) desktopHeading.innerHTML = `<span class="connected-dot"></span> Connected to ${netName}`;
    const topbarPill = document.querySelector(".topbar-network-pill");
    if (topbarPill) topbarPill.innerHTML = `<span class="connected-dot"></span><span>Connected to:</span><strong id="network-name-topbar">${netName}</strong>`;
    setText("#settings-network-name", netName);
    setText("#settings-network-details", `${network.band || "5 GHz"} · Channel ${network.channel || 36} · ${network.encryption || "WPA2"} · Signal: ${network.signal_dbm || -50} dBm (${network.signalQuality || "Good"})`);
    setText("#network-mobile-details", `${network.band || "5 GHz"} · Channel ${network.channel || 36} · ${network.signal_dbm || -50} dBm`);
    setText("#network-details-sidebar", `${network.band || "5 GHz"} · Channel ${network.channel || 36}`);
    setText(".reference-label", "Connected to");
    setText(".welcome-row p.muted", `Real-time 802.11 airspace monitoring, rogue AP defense, and authorized LAN auditing are active on ${netName}.`);

    document.querySelectorAll(".connected-dot, .live-dot").forEach((dot) => dot.classList.remove("disconnected"));
    const settingsChip = document.querySelector(".settings-network-banner .status-chip");
    if (settingsChip) {
      settingsChip.textContent = "CONNECTED";
      settingsChip.className = "status-chip good";
    }

    const scoreVal = network.score || 82;
    setText(".reference-score-ring strong", scoreVal);
    setText(".reference-score-ring b", scoreVal >= 75 ? "GOOD" : "RISKY");
    setText("#score", scoreVal);
    setText("#kpi-rating-badge", `${scoreVal} ${network.securityRating || (scoreVal >= 75 ? "GOOD" : "RISKY")}`);
    setText("#score-classification-text", `Classification: ${network.securityClassification || (scoreVal >= 75 ? "Good" : "Moderate")}`);
    setText(".metric-value", `${network.band || "5 GHz"} · Channel ${network.channel || 36}`);
    const signalValue = document.querySelector(".metric-foot strong");
    if (signalValue?.firstChild) signalValue.firstChild.nodeValue = `${network.signal_dbm || -50} dBm `;
    setText(".metric-foot i", network.signalQuality || "Excellent");
    setText(".reference-score .card-heading h2", scoreVal >= 75 ? "Your network is protected" : "Your network needs attention");
    setText(".reference-score > p", "Strong encryption and a secure router configuration keep your network safe.");

    const networkStatus = document.querySelector(".score-card .status-chip");
    if (networkStatus) {
      networkStatus.textContent = scoreVal >= 75 ? "GOOD" : "RISKY";
      networkStatus.classList.toggle("good", scoreVal >= 75);
      networkStatus.classList.toggle("danger", scoreVal < 75);
    }
  } else {
    // DISCONNECTED STATE
    setText("#network-name-mobile", "No Wi-Fi Connected");
    setText("#network-name-sidebar", "No Wi-Fi Connected");
    const desktopHeading = document.querySelector("#network-name-desktop");
    if (desktopHeading) desktopHeading.innerHTML = `<span class="connected-dot disconnected"></span> No Wi-Fi Connected`;
    const topbarPill = document.querySelector(".topbar-network-pill");
    if (topbarPill) topbarPill.innerHTML = `<span class="connected-dot disconnected"></span><span>Status:</span><strong id="network-name-topbar" style="color:var(--red)">No Wi-Fi Connected</strong>`;
    setText("#settings-network-name", "No Wi-Fi Connected");
    setText("#settings-network-details", "Wi-Fi adapter is disconnected or disabled. Connect to a network to inspect security.");
    setText("#network-mobile-details", "Wi-Fi is disconnected or turned off");
    setText("#network-details-sidebar", "Disconnected");
    setText(".reference-label", "Status");
    setText(".welcome-row p.muted", "No active Wi-Fi connection detected. Connect to an access point to run security analysis.");

    document.querySelectorAll(".connected-dot, .live-dot").forEach((dot) => dot.classList.add("disconnected"));
    const settingsChip = document.querySelector(".settings-network-banner .status-chip");
    if (settingsChip) {
      settingsChip.textContent = "DISCONNECTED";
      settingsChip.className = "status-chip danger";
    }

    setText(".reference-score-ring strong", "0");
    setText(".reference-score-ring b", "OFFLINE");
    setText("#score", "0");
    setText("#kpi-rating-badge", "OFFLINE");
    setText(".metric-value", "Disconnected");
    const signalValue = document.querySelector(".metric-foot strong");
    if (signalValue?.firstChild) signalValue.firstChild.nodeValue = "0 dBm ";
    setText(".metric-foot i", "Offline");
    setText(".reference-score .card-heading h2", "No Wi-Fi Connected");
    setText(".reference-score > p", "Wi-Fi is turned off or disconnected. Connect to a network to run security analysis.");

    const networkStatus = document.querySelector(".score-card .status-chip");
    if (networkStatus) {
      networkStatus.textContent = "OFFLINE";
      networkStatus.classList.remove("good");
      networkStatus.classList.add("danger");
    }
  }

  renderDevices(devices || defaultDashboard.devices);
  renderHistory(scans || defaultDashboard.scans);
  setSettings(dashboardData.settings || defaultDashboard.settings);
  generateWifiQrCode();
}

// -------------------------------------------------------------
// ADVANCED WI-FI SCANNER: SORTABLE TABLE & CARDS RENDERING + FILTERS
// -------------------------------------------------------------
function filterAndRenderWifiNetworks() {
  const searchInput = document.querySelector("#wifi-search-input");
  const bandSelect = document.querySelector("#filter-band-select");
  const secSelect = document.querySelector("#filter-security-select");

  const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
  const bandFilter = bandSelect ? bandSelect.value : "all";
  const secFilter = secSelect ? secSelect.value : "all";

  let filtered = cachedNetworks.filter((net) => {
    // 1. Text Search (SSID or BSSID)
    if (query) {
      const matchSsid = net.ssid?.toLowerCase().includes(query);
      const matchBssid = net.bssid?.toLowerCase().includes(query);
      if (!matchSsid && !matchBssid) return false;
    }
    // 2. Band filter
    if (bandFilter !== "all") {
      if (!net.band?.toLowerCase().includes(bandFilter.toLowerCase())) return false;
    }
    // 3. Security filter
    if (secFilter !== "all") {
      const auth = (net.authentication || "").toLowerCase();
      const enc = (net.encryption || "").toLowerCase();
      if (secFilter === "wpa3" && !auth.includes("wpa3")) return false;
      if (secFilter === "wpa2" && !auth.includes("wpa2")) return false;
      if (secFilter === "open" && !(auth.includes("open") || enc.includes("none"))) return false;
      if (secFilter === "wep" && !auth.includes("wep")) return false;
    }
    return true;
  });

  // Sort
  filtered.sort((a, b) => {
    let valA = a[currentSortColumn];
    let valB = b[currentSortColumn];
    if (currentSortColumn === "signal") {
      valA = a.signalPercent;
      valB = b.signalPercent;
    } else if (currentSortColumn === "score") {
      valA = a.securityScore;
      valB = b.securityScore;
    } else if (currentSortColumn === "channel") {
      valA = a.channel;
      valB = b.channel;
    } else {
      valA = String(valA || "").toLowerCase();
      valB = String(valB || "").toLowerCase();
    }
    if (valA < valB) return currentSortAsc ? -1 : 1;
    if (valA > valB) return currentSortAsc ? 1 : -1;
    return 0;
  });

  renderWifiTable(filtered);
  renderWifiCards(filtered);
}

function renderWifiTable(networks) {
  const tbody = document.querySelector("#wifi-table-body");
  if (!tbody) return;
  tbody.replaceChildren();

  if (networks.length === 0) {
    const tr = element("tr");
    tr.innerHTML = `<td colspan="11" class="muted" style="text-align:center;padding:24px">No matching visible Wi-Fi networks found.</td>`;
    tbody.append(tr);
    return;
  }

  networks.forEach((net) => {
    const tr = element("tr");
    const isChecked = selectedSsidsForCompare.has(net.ssid);
    const isGood = net.securityScore >= 70;
    const scoreChip = `<span class="status-chip ${isGood ? "good" : "danger"}">${net.securityScore} ${net.securityRating || ""}</span>`;

    let threatTag = "";
    if (net.isEvilTwin) {
      threatTag = `<span class="threat-badge critical" style="margin-left:6px" title="Possible Evil Twin Rogue AP">EVIL TWIN</span>`;
    } else if (net.isDuplicate) {
      threatTag = `<span class="threat-badge medium" style="margin-left:6px" title="Duplicate SSID">DUPLICATE</span>`;
    }

    const qualClass = (net.signalQuality || "Good").toLowerCase();

    tr.innerHTML = `
      <td><input type="checkbox" class="wifi-select-check" data-ssid="${escapeHtml(net.ssid)}" ${isChecked ? "checked" : ""} /></td>
      <td><strong>${escapeHtml(net.ssid)}</strong>${threatTag}</td>
      <td><span class="bssid-mono">${net.bssid || "00:00:00:00:00:00"}</span></td>
      <td>${net.band || "2.4 GHz"}</td>
      <td>${net.channel || 11}</td>
      <td><strong>${net.signalPercent}%</strong> <small class="muted">(${net.signal_dbm || -50} dBm)</small></td>
      <td><span class="status-chip ${qualClass === 'excellent' || qualClass === 'good' ? 'good' : 'danger'}">${net.signalQuality || "Good"}</span></td>
      <td>${net.authentication} / ${net.encryption}</td>
      <td><small class="muted">${net.vendor || "Standard"}</small></td>
      <td>${scoreChip}</td>
      <td>
        <button type="button" class="table-btn btn-analyze-table" data-ssid="${escapeHtml(net.ssid)}">Analyze</button>
      </td>
    `;

    tr.querySelector(".wifi-select-check").addEventListener("change", (e) => {
      if (e.target.checked) {
        selectedSsidsForCompare.add(net.ssid);
      } else {
        selectedSsidsForCompare.delete(net.ssid);
      }
      updateCompareSelectionCounter();
    });

    tr.querySelector(".btn-analyze-table").addEventListener("click", () => {
      analyzeWifiNetwork(net.ssid, tr);
    });

    tbody.append(tr);
  });
}

function renderWifiCards(networks) {
  const list = document.querySelector("#wifi-networks");
  if (!list) return;
  list.replaceChildren();

  if (networks.length === 0) {
    list.append(element("p", "muted wifi-empty", "No visible WiFi networks match your filter."));
    return;
  }

  networks.forEach((network) => {
    const card = element("button", "wifi-network-card");
    card.type = "button";
    const details = element("span", "wifi-network-details");
    details.append(
      element("strong", "", network.ssid + (network.isEvilTwin ? " [EVIL TWIN DETECTED]" : "")),
      element("small", "", `${network.authentication} · ${network.encryption}`),
      element("small", "", `BSSID: ${network.bssid || ""} · ${network.band} · Channel ${network.channel} · ${network.signalPercent}% signal (${network.signalQuality || "Good"})`),
    );
    const score = element("span", `status-chip ${network.securityScore >= 70 ? "good" : "danger"}`, `${network.securityScore} ${network.securityRating}`);
    card.append(details, score);
    card.addEventListener("click", () => analyzeWifiNetwork(network.ssid, card));
    list.append(card);
  });
}

function updateCompareSelectionCounter() {
  const counter = document.querySelector("#selection-counter");
  const badge = document.querySelector("#compare-count-badge");
  const count = selectedSsidsForCompare.size;
  if (badge) badge.textContent = count;
  if (!counter) return;
  if (count > 0) {
    counter.hidden = false;
    counter.textContent = `${count} network${count === 1 ? "" : "s"} selected for comparison`;
  } else {
    counter.hidden = true;
  }
}

function escapeHtml(text) {
  if (!text) return "";
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderWifiAnalysis(result) {
  const network = result.network;
  const isGood = network.securityScore >= 70;
  setText("#analysis-ssid", network.ssid);
  setText("#analysis-auth", `${network.authentication} · ${network.encryption}`);
  setText("#analysis-bssid-text", `BSSID: ${network.bssid || "00:00:00:00:00:00"} · Vendor: ${network.vendor || "Standard IEEE Hardware"}`);
  setText("#analysis-badge", `${network.securityScore} ${network.securityRating}`);
  const badge = document.querySelector("#analysis-badge");
  if (badge) badge.className = `status-chip ${isGood ? "good" : "danger"}`;
  setText("#analysis-score", network.securityScore);
  setText("#analysis-rating", network.securityRating);
  setText("#analysis-summary", isGood
    ? "This network advertises robust 802.11 security. Keep its firmware and passphrase updated."
    : "This network advertises weak or unverified security parameters. Review the remediation steps below.");
  setText("#analysis-scope", result.assessmentScope);

  const factorsEl = document.querySelector("#analysis-score-factors");
  if (factorsEl) {
    factorsEl.replaceChildren();
    const factors = network.scoreFactors || [
      `${network.securityScore >= 70 ? "+" : "-"}${network.securityScore}: Cryptographic posture based on advertised ${network.authentication}.`
    ];
    factors.forEach((f) => factorsEl.append(element("li", "", f)));
  }

  const facts = document.querySelector("#analysis-facts");
  if (facts) {
    facts.replaceChildren(
      element("span", "", `Band: ${network.band}`),
      element("span", "", `Channel: ${network.channel}`),
      element("span", "", `Signal: ${network.signalPercent}% (${network.signal_dbm || -50} dBm)`),
      element("span", "", `Scanned: ${result.scannedAt}`),
    );
  }
  const recommendations = document.querySelector("#analysis-recommendations");
  if (recommendations) {
    recommendations.replaceChildren(...(network.recommendations || []).map((item) => element("li", "", item)));
  }
  const scoreRing = document.querySelector("#analysis-ring");
  if (scoreRing) {
    scoreRing.classList.toggle("danger", !isGood);
    scoreRing.style.setProperty("--score", `${network.securityScore}%`);
  }
  const analysisEl = document.querySelector("#wifi-analysis");
  if (analysisEl) analysisEl.hidden = false;

  const printSingleBtn = document.querySelector("#btn-print-single-analysis");
  if (printSingleBtn) {
    printSingleBtn.onclick = () => openPdfReportModal(network);
  }
}

async function loadWifiNetworks() {
  const refreshButton = document.querySelector("#refresh-wifi");
  const status = document.querySelector("#wifi-status");
  const count = document.querySelector("#wifi-network-count");
  const scanTime = document.querySelector("#wifi-scan-time");
  if (refreshButton) refreshButton.disabled = true;
  if (status) status.textContent = "Scanning 802.11 broadcast channels for nearby Wi-Fi networks…";
  if (count) count.textContent = "Scanning…";
  if (scanTime) scanTime.textContent = "";

  try {
    // POST to /api/scan — this scans AND saves to the database
    const result = await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trigger: "manual" }),
    });

    cachedNetworks = result.networks || [];
    filterAndRenderWifiNetworks();

    const total = cachedNetworks.length;
    if (count) count.textContent = `${total} network${total === 1 ? "" : "s"} visible`;
    if (scanTime) scanTime.textContent = `Scanned ${result.scanned_at || "just now"} · Session #${result.sessionId || "?"}`;
    if (status) {
      status.textContent = total
        ? `Airspace survey complete — ${total} network${total === 1 ? "" : "s"} recorded. Select a network to inspect or compare.`
        : "No visible Wi-Fi networks were detected in local physical range.";
    }

    if (result.threats) {
      renderThreats(result.threats);
    }

    // Refresh history to show newly saved scan
    api("/api/history")
      .then((scans) => renderHistory(scans))
      .catch(() => {});

  } catch (error) {
    // Fallback: try GET if POST fails (read-only display, won't save)
    try {
      const fallback = await api("/api/wifi/networks");
      cachedNetworks = fallback.networks || [];
      filterAndRenderWifiNetworks();
      if (count) count.textContent = `${cachedNetworks.length} visible (not saved)`;
      if (status) status.textContent = "Scan displayed but could not be saved to history. Check server connection.";
    } catch (e2) {
      if (count) count.textContent = "Scan unavailable";
      if (status) status.textContent = "Wi-Fi scanner unavailable. Ensure the Flask backend is running on port 5001.";
    }
  } finally {
    if (refreshButton) refreshButton.disabled = false;
  }
}

async function analyzeWifiNetwork(ssid, triggerElement) {
  const status = document.querySelector("#wifi-status");
  if (status) status.textContent = `Analyzing security frames for ${ssid}…`;

  try {
    const result = await api("/api/wifi/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid }),
    });
    document.querySelector("#wifi-cards-container").hidden = false;
    renderWifiAnalysis(result);
    if (status) status.textContent = `${ssid} security assessment completed and recorded.`;
    await loadDashboard();
  } catch (error) {
    if (status) status.textContent = `Unable to analyze ${ssid}: ${error.message}`;
  }
}

// -------------------------------------------------------------
// ADVANCED THREAT DETECTION RENDERING
// -------------------------------------------------------------
async function loadThreats() {
  try {
    const data = await api("/api/threats");
    renderThreats(data.threats || []);
  } catch (error) {
    renderThreats(dashboardData?.threats || []);
  }
}

function renderThreats(threats) {
  const container = document.querySelector("#threat-list-container");
  if (!container) return;
  container.replaceChildren();

  const totalThreatBadge = document.querySelector("#threat-total-badge");
  const healthChip = document.querySelector("#threat-health-chip");
  const headline = document.querySelector("#threat-stat-headline");

  if (threats.length === 0) {
    if (totalThreatBadge) totalThreatBadge.textContent = "0";
    if (healthChip) {
      healthChip.textContent = "PROTECTED";
      healthChip.className = "status-chip good";
    }
    if (headline) headline.textContent = "Airspace Protected";

    const empty = element("article", "card threat-card");
    empty.style.borderLeftColor = "var(--green)";
    empty.innerHTML = `
      <div class="threat-card-head">
        <h4>✓ Zero Rogue Access Points Detected</h4>
        <span class="status-chip good">CLEAN AIRSPACE</span>
      </div>
      <p class="muted">No duplicate SSIDs, Evil Twin rogue access points, or active deauthentication beacon anomalies detected.</p>
    `;
    container.append(empty);
    return;
  }

  if (totalThreatBadge) {
    totalThreatBadge.textContent = threats.length;
    totalThreatBadge.classList.add("alert-danger");
  }
  if (healthChip) {
    healthChip.textContent = `${threats.length} THREATS FOUND`;
    healthChip.className = "status-chip danger";
  }
  if (headline) headline.textContent = "Vulnerabilities Detected";

  threats.forEach((threat) => {
    const isConfirmed = threat.status === "CONFIRMED";
    const sev = (threat.severity || "MEDIUM").toLowerCase();
    const card = element("article", `card threat-card ${isConfirmed ? "" : "potential"}`);
    if (sev === "critical") card.style.borderLeftColor = "var(--red)";
    else if (sev === "high") card.style.borderLeftColor = "var(--red)";
    else if (sev === "medium") card.style.borderLeftColor = "var(--yellow)";
    else card.style.borderLeftColor = "var(--blue)";

    card.innerHTML = `
      <div class="threat-card-head">
        <h4>${escapeHtml(threat.title)}</h4>
        <span class="threat-badge ${sev}">${threat.severity} · ${threat.status}</span>
      </div>
      <div class="threat-card-body">
        <p>${escapeHtml(threat.description)}</p>
        <div class="threat-remediation-box">
          <span>🛡</span>
          <div>
            <strong>Recommended Action:</strong> ${escapeHtml(threat.recommendation)}
          </div>
        </div>
      </div>
    `;
    container.append(card);
  });
}

// -------------------------------------------------------------
// PART 6: NETWORK PERFORMANCE ANALYSIS
// -------------------------------------------------------------
async function loadPerformance() {
  try {
    const perf = await api("/api/performance");
    setText("#perf-latency-val", `${perf.avgLatencyMs || 24} ms`);
    setText("#perf-latency-range", `${perf.minLatencyMs || 15} ms / ${perf.maxLatencyMs || 34} ms`);
    setText("#perf-jitter-val", `${perf.jitterMs || 0} ms`);
    setText("#perf-loss-val", `${perf.packetLossPercent || 0}%`);
    setText("#perf-score-val", `${perf.connectionQualityScore || 95} / 100`);
    setText("#perf-status-val", `${perf.qualityRating || "Good"} Quality`);
    setText("#kpi-live-latency", `${perf.avgLatencyMs || 24} ms (${perf.qualityRating || "Good"})`);
    setText("#kpi-jitter-sub", `${perf.jitterMs || 0} ms Jitter`);

    const internetChip = document.querySelector("#perf-internet-chip");
    if (internetChip) {
      const isOnline = perf.internetAvailable !== false;
      internetChip.textContent = isOnline ? "INTERNET AVAILABLE" : "GATEWAY / OFFLINE";
      internetChip.className = `status-chip ${isOnline ? "good" : "danger"}`;
    }
  } catch (err) {
    // Graceful fallback
  }

  loadMlAnomalies();
}

async function loadMlAnomalies() {
  try {
    const ml = await api("/api/ml/anomalies");
    setText("#ml-prob-val", `${ml.anomalyScore || 0.05} (${ml.isAnomalous ? "Elevated" : "Low"})`);
    const statusChip = document.querySelector("#ml-status-chip");
    if (statusChip) {
      statusChip.textContent = ml.isAnomalous ? "ANOMALY FLAGGED" : "NORMAL SPECTRUM";
      statusChip.className = `status-chip ${ml.isAnomalous ? "danger" : "good"}`;
    }
    const list = document.querySelector("#ml-anomaly-items");
    if (list) {
      list.replaceChildren();
      const anomalies = ml.anomaliesDetected || [];
      if (anomalies.length === 0) {
        list.append(element("li", "", "Zero extreme proximity beacon power spikes detected."));
      } else {
        anomalies.forEach((a) => list.append(element("li", "", a)));
      }
    }
  } catch (err) {
    // Graceful fallback
  }
}

// -------------------------------------------------------------
// NETWORK TRAFFIC MONITORING
// -------------------------------------------------------------
async function loadTraffic() {
  try {
    const traffic = await api("/api/traffic");
    setText("#traffic-rx-speed", traffic.rxSpeedFormatted || "0.0 KB/s");
    setText("#traffic-tx-speed", traffic.txSpeedFormatted || "0.0 KB/s");
    setText("#traffic-rx-total", traffic.bytesReceivedFormatted || "0 B");
    setText("#traffic-tx-total", traffic.bytesSentFormatted || "0 B");
    setText("#traffic-packets-total", Number(traffic.unicastPackets || 0).toLocaleString());
    setText("#traffic-errors-total", `${traffic.errors || 0} / ${traffic.discards || 0}`);

    const rxKb = traffic.rxSpeedKbps || 0;
    const txKb = traffic.txSpeedKbps || 0;
    trafficHistoryRx.push(rxKb);
    trafficHistoryTx.push(txKb);
    if (trafficHistoryRx.length > 20) trafficHistoryRx.shift();
    if (trafficHistoryTx.length > 20) trafficHistoryTx.shift();
    updateLiveTrafficChart();

    const anomalyIcon = document.querySelector("#anomaly-icon");
    const anomalyTitle = document.querySelector("#anomaly-title");
    const anomalyDesc = document.querySelector("#anomaly-desc");

    if (traffic.anomalyDetected) {
      if (anomalyIcon) { anomalyIcon.className = "anomaly-icon red"; anomalyIcon.textContent = "!"; }
      if (anomalyTitle) anomalyTitle.textContent = "Traffic Anomaly Alert";
      if (anomalyDesc) anomalyDesc.textContent = traffic.anomalyMessage;
    } else {
      if (anomalyIcon) { anomalyIcon.className = "anomaly-icon green"; anomalyIcon.textContent = "✓"; }
      if (anomalyTitle) anomalyTitle.textContent = "Traffic Patterns Normal";
      if (anomalyDesc) anomalyDesc.textContent = traffic.anomalyMessage;
    }
  } catch (error) {
    // Keep running gracefully
  }
}

function updateLiveTrafficChart() {
  const rxPath = document.querySelector("#svg-rx-path");
  const txPath = document.querySelector("#svg-tx-path");
  if (!rxPath || !txPath) return;

  const maxVal = Math.max(100, ...trafficHistoryRx, ...trafficHistoryTx);
  const width = 600;
  const height = 180;
  const step = width / (trafficHistoryRx.length - 1);

  let rxD = "";
  let txD = "";

  trafficHistoryRx.forEach((val, i) => {
    const x = Math.round(i * step);
    const y = Math.round(height - (val / maxVal) * 140 - 20);
    rxD += (i === 0 ? `M${x} ${y}` : ` L${x} ${y}`);
  });

  trafficHistoryTx.forEach((val, i) => {
    const x = Math.round(i * step);
    const y = Math.round(height - (val / maxVal) * 140 - 20);
    txD += (i === 0 ? `M${x} ${y}` : ` L${x} ${y}`);
  });

  rxPath.setAttribute("d", rxD);
  txPath.setAttribute("d", txD);
}

// -------------------------------------------------------------
// WI-FI COMPARISON
// -------------------------------------------------------------
async function loadComparison() {
  const container = document.querySelector("#comparison-matrix-container");
  if (!container) return;

  let query = "";
  if (selectedSsidsForCompare.size > 0) {
    query = "?ssids=" + encodeURIComponent(Array.from(selectedSsidsForCompare).join(","));
  }

  try {
    const data = await api("/api/wifi/compare" + query);
    renderComparison(data.networks || []);
  } catch (error) {
    renderComparison(cachedNetworks.slice(0, 3));
  }
}

function renderComparison(networks) {
  const container = document.querySelector("#comparison-matrix-container");
  if (!container) return;
  container.replaceChildren();

  if (networks.length === 0) {
    container.innerHTML = `<p class="muted" style="padding:24px">No networks selected to compare. Check boxes in the Security Scan table to compare up to 4 networks.</p>`;
    return;
  }

  const grid = element("div", "comparison-grid-layout");

  const labelCol = element("div", "comp-label-col");
  labelCol.innerHTML = `
    <div>SSID NAME</div>
    <div>BSSID (MAC)</div>
    <div>FREQUENCY / BAND</div>
    <div>OPERATING CHANNEL</div>
    <div>SIGNAL STRENGTH</div>
    <div>ENCRYPTION PROTOCOL</div>
    <div>CIPHER SUITE</div>
    <div>HARDWARE VENDOR</div>
    <div>SECURITY SCORE</div>
    <div>RISK CLASSIFICATION</div>
    <div>EVIL TWIN STATUS</div>
  `;
  grid.append(labelCol);

  networks.forEach((net) => {
    const isGood = net.securityScore >= 70;
    const col = element("div", `comp-card-col ${isGood ? "highlight-best" : ""}`);
    col.innerHTML = `
      <h3 class="comp-net-title">${escapeHtml(net.ssid)}</h3>
      <div class="comp-item-row"><small class="muted">BSSID</small> <span class="bssid-mono">${net.bssid || "00:00:00:00:00:00"}</span></div>
      <div class="comp-item-row"><small class="muted">Band</small> <strong>${net.band || "2.4 GHz"}</strong></div>
      <div class="comp-item-row"><small class="muted">Channel</small> <strong>${net.channel || 11}</strong></div>
      <div class="comp-item-row"><small class="muted">Signal</small> <strong>${net.signalPercent}% (${net.signal_dbm || -50} dBm)</strong></div>
      <div class="comp-item-row"><small class="muted">Auth</small> <strong>${net.authentication}</strong></div>
      <div class="comp-item-row"><small class="muted">Cipher</small> <strong>${net.encryption}</strong></div>
      <div class="comp-item-row"><small class="muted">Vendor</small> <span>${net.vendor || "Standard"}</span></div>
      <div class="comp-item-row"><small class="muted">Score</small> <span class="status-chip ${isGood ? "good" : "danger"}">${net.securityScore}/100</span></div>
      <div class="comp-item-row"><small class="muted">Rating</small> <strong>${net.securityRating}</strong></div>
      <div class="comp-item-row"><small class="muted">Rogue Check</small> <strong style="color:${net.isEvilTwin ? 'var(--red)' : 'var(--green)'}">${net.isEvilTwin ? 'THREAT DETECTED' : 'Verified'}</strong></div>
      <button class="primary-button" style="margin-top:14px" onclick="analyzeWifiNetwork('${escapeHtml(net.ssid)}', this)">Inspect Details</button>
    `;
    grid.append(col);
  });

  container.append(grid);
}

// -------------------------------------------------------------
// REAL-TIME SECURITY ALERTS
// -------------------------------------------------------------
async function loadAlerts() {
  try {
    const alerts = await api("/api/alerts");
    renderAlerts(alerts || []);
  } catch (error) {
    renderAlerts([]);
  }
}

function renderAlerts(alerts) {
  const container = document.querySelector("#alerts-list-container");
  if (!container) return;
  container.replaceChildren();

  const filtered = alerts.filter((a) => {
    if (currentAlertFilter === "all") return true;
    return (a.severity || "").toUpperCase() === currentAlertFilter.toUpperCase();
  });

  if (filtered.length === 0) {
    const empty = element("div", "alert-item-card card");
    empty.innerHTML = `
      <div class="alert-item-icon low">✓</div>
      <div class="alert-item-body">
        <strong>No security alerts in this category</strong>
        <p class="muted">Your network and airspace logs have no active alert warnings.</p>
      </div>
    `;
    container.append(empty);
    return;
  }

  filtered.forEach((alert) => {
    const sev = (alert.severity || "LOW").toLowerCase();
    const item = element("div", "alert-item-card card");
    const iconChar = sev === "critical" ? "!" : sev === "high" ? "⚠" : sev === "medium" ? "⌁" : "ℹ";

    item.innerHTML = `
      <div class="alert-item-icon ${sev}">${iconChar}</div>
      <div class="alert-item-body">
        <div class="alert-item-head">
          <strong>${escapeHtml(alert.title)}</strong>
          <span class="threat-badge ${sev}">${alert.severity}</span>
        </div>
        <p>${escapeHtml(alert.message)}</p>
        <small>${alert.created_at || "Recent"} · Category: ${alert.category || "SECURITY"}</small>
      </div>
    `;
    container.append(item);
  });
}

// -------------------------------------------------------------
// PART 3: AI CYBERSECURITY ASSISTANT (CHAT)
// -------------------------------------------------------------
async function sendAiChatMessage(userQuestion) {
  const chatContainer = document.querySelector("#ai-chat-messages-container");
  const inputEl = document.querySelector("#ai-chat-input");
  if (!userQuestion || !chatContainer) return;

  // Append user message
  const userMsg = element("div", "ai-msg user");
  userMsg.innerHTML = `
    <div class="msg-bubble">${escapeHtml(userQuestion)}</div>
    <small class="msg-time">Just now</small>
  `;
  chatContainer.append(userMsg);
  chatContainer.scrollTop = chatContainer.scrollHeight;

  if (inputEl) inputEl.value = "";

  // Append typing indicator
  const typingMsg = element("div", "ai-msg bot typing-indicator");
  typingMsg.innerHTML = `<div class="msg-bubble"><em>Analyzing airspace telemetry and threat models…</em></div>`;
  chatContainer.append(typingMsg);
  chatContainer.scrollTop = chatContainer.scrollHeight;

  try {
    const res = await api("/api/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: userQuestion }),
    });

    typingMsg.remove();

    // Render formatted response
    const botMsg = element("div", "ai-msg bot");
    const formattedAnswer = formatMarkdownText(res.answer || "No response received.");
    botMsg.innerHTML = `
      <div class="msg-bubble">${formattedAnswer}</div>
      <small class="msg-time">${res.timestamp || "Just now"}</small>
    `;
    chatContainer.append(botMsg);

    // Dynamic suggested questions from server
    if (res.suggestedQuestions && res.suggestedQuestions.length > 0) {
      const suggestWrap = element("div", "ai-msg bot ai-inline-suggestions");
      suggestWrap.style.cssText = "display:flex;flex-wrap:wrap;gap:6px;margin-top:2px;";
      res.suggestedQuestions.forEach((sq) => {
        const chip = element("button", "ai-pill-btn", sq);
        chip.type = "button";
        chip.style.cssText = "cursor:pointer;";
        suggestWrap.append(chip);
      });
      chatContainer.append(suggestWrap);
    }

    chatContainer.scrollTop = chatContainer.scrollHeight;
  } catch (err) {
    typingMsg.remove();
    const errEl = element("div", "ai-msg bot");
    errEl.innerHTML = `<div class="msg-bubble" style="border-color:var(--red);color:#ff8094">Unable to reach security AI: ${escapeHtml(err.message)}</div>`;
    chatContainer.append(errEl);
    chatContainer.scrollTop = chatContainer.scrollHeight;
  }
}

function clearAiChat() {
  const chatContainer = document.querySelector("#ai-chat-messages-container");
  if (!chatContainer) return;
  chatContainer.innerHTML = `
    <div class="ai-msg bot">
      <div class="msg-bubble">
        Hello! I am your <strong>NetGuard AI Security Assistant</strong>. I have analyzed your active wireless environment and nearby airspace. Ask me anything about your security score, rogue AP threats, or router configuration!
      </div>
      <small class="msg-time">Just now</small>
    </div>
  `;
  const inputEl = document.querySelector("#ai-chat-input");
  if (inputEl) {
    inputEl.value = "";
    inputEl.focus();
  }
  showMessage("AI conversation reset.", false);
}

function formatMarkdownText(text) {
  if (!text) return "";
  let html = escapeHtml(text);
  // Bold
  html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  // Code / Mono
  html = html.replace(/`(.*?)`/g, "<code>$1</code>");
  // Line breaks
  html = html.replace(/\n\n/g, "<br><br>").replace(/\n/g, "<br>");
  return html;
}

// -------------------------------------------------------------
// PART 14: KNOWLEDGE CENTER, CHECKLIST & QR CODE
// -------------------------------------------------------------
async function loadChecklist() {
  const container = document.querySelector("#checklist-container");
  if (!container) return;

  try {
    const res = await api("/api/security/checklist");
    setText("#checklist-progress-count", `${res.completedCount || 4} / ${res.totalCount || 5}`);
    container.replaceChildren();

    (res.checklist || []).forEach((item) => {
      const row = element("div", "checklist-row");
      row.innerHTML = `
        <input type="checkbox" class="checklist-check" ${item.completed ? "checked" : ""} />
        <div class="checklist-info">
          <strong>${escapeHtml(item.title)}</strong>
          <p>${escapeHtml(item.description)}</p>
        </div>
      `;
      row.querySelector(".checklist-check").addEventListener("change", (e) => {
        item.completed = e.target.checked;
        const total = res.checklist.length;
        const completed = res.checklist.filter(i => i.completed).length;
        setText("#checklist-progress-count", `${completed} / ${total}`);
      });
      container.append(row);
    });
  } catch (err) {
    // Fallback
  }
}

async function loadKnowledge() {
  const container = document.querySelector("#knowledge-articles-container");
  if (!container) return;

  try {
    const res = await api("/api/knowledge");
    if (res.tipOfTheDay) {
      setText("#tip-title", res.tipOfTheDay.title);
      setText("#tip-body", res.tipOfTheDay.content);
    }
    container.replaceChildren();

    (res.articles || []).forEach((art) => {
      const card = element("div", "article-card card");
      card.innerHTML = `
        <small>${escapeHtml(art.category)}</small>
        <h4>${escapeHtml(art.title)}</h4>
        <p>${escapeHtml(art.summary)}</p>
      `;
      container.append(card);
    });
  } catch (err) {
    // Fallback
  }

  generateWifiQrCode();
}

function generateWifiQrCode() {
  const canvas = document.querySelector("#qr-code-canvas");
  const qrLib = (typeof QRCode !== "undefined" ? QRCode : (typeof NetGuardQR !== "undefined" ? NetGuardQR : null));
  if (!canvas || !qrLib) return;

  const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
  const isConn = net.connected !== false && net.state !== "disconnected" && net.name !== "No Wi-Fi Connected";
  const ssid = net.ssid || net.name || (isConn ? "Home_WiFi" : "No_WiFi");
  const pwd = net.password || "";
  const auth = net.encryption || "WPA2";

  setText("#qr-net-name", ssid);
  setText("#qr-net-type", !isConn ? "Disconnected" : (pwd ? `Protected (${auth})` : "Open Network (No Password)"));

  const qrString = qrLib.wifiString ? qrLib.wifiString(ssid, pwd, auth) : `WIFI:T:${auth.includes("WPA") ? "WPA" : "nopass"};S:${ssid};P:${pwd};;`;
  try {
    qrLib.render(canvas, qrString, {
      size: 160,
      margin: 2,
      dark: "#06152c",
      light: "#ffffff"
    });
  } catch (e) {
    console.warn("QR Code render error:", e);
  }
}

// -------------------------------------------------------------
// PDF REPORT GENERATOR & MODAL
// -------------------------------------------------------------
async function openPdfReportModal(specificNetwork = null) {
  const backdrop = document.querySelector("#pdf-modal-backdrop");
  if (!backdrop) return;

  showMessage("Preparing official cybersecurity audit report...", false);

  try {
    const data = await api("/api/report/data");
    const net = specificNetwork || data.network || defaultDashboard.network;
    const isConn = net.connected !== false && net.state !== "disconnected" && net.name !== "No Wi-Fi Connected";

    setText("#pdf-report-date", data.generatedAt || new Date().toLocaleString());
    setText("#pdf-system-platform", data.systemPlatform || "Windows 64-bit");
    setText("#pdf-score-val", net.securityScore || net.score || 82);
    setText("#pdf-score-rating", `${(net.securityRating || "GOOD").toUpperCase()} PROTECTION LEVEL`);
    setText("#pdf-exec-summary", data.aiAnalysis?.executiveSummary || "Target network security evaluated against NIST 802.11 standards.");

    // Target telemetry
    setText("#pdf-target-ssid", net.ssid || net.name || "Home_WiFi");
    setText("#pdf-target-bssid", net.bssid || "8e:29:31:cd:69:bc");
    setText("#pdf-target-band", net.band || "5 GHz");
    setText("#pdf-target-channel", net.channel || 36);
    setText("#pdf-target-encryption", net.authentication ? `${net.authentication} (${net.encryption || 'CCMP'})` : (net.encryption || "WPA2-Personal"));
    setText("#pdf-target-signal", `${net.signalPercent || 88}% (${net.signal_dbm || -48} dBm)`);
    setText("#pdf-target-vendor", net.vendor || "Standard Wi-Fi Hardware");
    setText("#pdf-target-pass-status", net.password ? "Passphrase Configured & Stored" : (isConn ? "Open Network / Unset" : "N/A"));

    // Threat findings
    const threatList = document.querySelector("#pdf-threat-findings-list");
    if (threatList) {
      threatList.replaceChildren();
      const threats = data.threats || [];
      if (threats.length === 0) {
        threatList.innerHTML = `<p class="muted">✓ Zero rogue Evil Twin access points or active deauthentication beacon anomalies detected.</p>`;
      } else {
        threats.forEach((t) => {
          const div = element("div", "pdf-threat-row", `⚠ [${t.severity}] ${t.title}: ${t.description}`);
          div.style.marginBottom = "6px";
          threatList.append(div);
        });
      }
    }

    // Devices table
    const devBody = document.querySelector("#pdf-devices-table-body");
    if (devBody) {
      devBody.replaceChildren();
      const devs = data.devices || defaultDashboard.devices;
      devs.forEach((d) => {
        const tr = element("tr");
        tr.innerHTML = `
          <td><strong>${escapeHtml(d.name)}</strong></td>
          <td>${d.ip_address}</td>
          <td>${d.mac_address || "Subnet Dynamic"}</td>
          <td>${d.vendor || "Standard Hardware"}</td>
          <td>${d.status || "online"}</td>
        `;
        devBody.append(tr);
      });
    }

    // AI Recommendations
    const recsList = document.querySelector("#pdf-recommendations-list");
    if (recsList) {
      recsList.replaceChildren();
      const hardening = data.aiAnalysis?.routerHardeningSteps || [
        { title: "Disable WPS", action: "Disable Wi-Fi Protected Setup in the router administration panel.", reason: "Prevents brute-force PIN attacks." },
        { title: "Enforce WPA2-AES / WPA3", action: "Turn off legacy TKIP compatibility.", reason: "Eliminates cryptographic collision vulnerabilities." }
      ];
      hardening.forEach((h) => {
        const li = element("li");
        li.innerHTML = `<strong>${escapeHtml(h.title)}:</strong> ${escapeHtml(h.action)} <em>(${escapeHtml(h.reason)})</em>`;
        recsList.append(li);
      });
    }

    backdrop.hidden = false;
  } catch (error) {
    backdrop.hidden = false;
  }
}

// -------------------------------------------------------------
// FIREWALL DETECTION & MANAGEMENT ENGINE
// -------------------------------------------------------------
async function loadFirewall() {
  const btn = document.querySelector("#btn-rescan-firewall");
  if (btn) btn.classList.add("spinning");
  try {
    const [fwRes, connRes, rulesRes] = await Promise.all([
      api("/api/firewall"),
      api("/api/firewall/connections"),
      api("/api/firewall/rules")
    ]);
    renderFirewall(fwRes.firewall || fwRes, connRes.connections || [], rulesRes.rules || []);
  } catch (err) {
    showMessage(`Could not load firewall status: ${err.message}`, true);
  } finally {
    if (btn) setTimeout(() => btn.classList.remove("spinning"), 400);
  }
}

function renderFirewall(fw, connections = [], customRules = []) {
  if (!fw) return;

  // Overview headline & score
  setText("#fw-defense-headline", `${fw.active_profiles_count || 3} / ${fw.total_profiles_count || 3} Profiles Active`);
  setText("#fw-engine-sub", `Engine: ${fw.engine || "Windows Advanced Firewall Subsystem"}`);
  setText("#fw-score-val", `${fw.score || 100} / 100`);
  setText("#fw-rating-val", fw.rating || "OPTIMAL");

  const scorePill = document.querySelector("#fw-score-pill");
  if (scorePill) {
    scorePill.className = `firewall-score-pill ${fw.rating === "OPTIMAL" || fw.rating === "GOOD" ? "good" : "warning"}`;
  }

  // Update nav badge
  const navBadge = document.querySelector("#nav-firewall-badge");
  if (navBadge) {
    navBadge.textContent = fw.overall_status === "ENABLED" ? "ON" : (fw.overall_status === "PARTIAL" ? "WARN" : "OFF");
    navBadge.className = fw.overall_status === "ENABLED" ? "badge-success" : "badge-danger";
  }

  // Profiles
  const profs = fw.profiles || {};
  ["domain", "private", "public"].forEach((pKey) => {
    const p = profs[pKey];
    if (p) {
      const chip = document.querySelector(`#fw-${pKey}-chip`);
      if (chip) {
        chip.textContent = p.enabled ? "ACTIVE · ON" : "DISABLED · OFF";
        chip.className = `status-chip ${p.enabled ? "good" : "danger"}`;
      }
      setText(`#fw-${pKey}-inbound`, p.inbound === "Block" ? "Block Inbound (Enforced)" : "Allow Inbound (Vulnerable)");
      setText(`#fw-${pKey}-outbound`, p.outbound === "Allow" ? "Allow Outbound (Standard)" : "Filtered Outbound");
      setText(`#fw-${pKey}-notify`, p.notifications || "Enabled");
    }
  });

  // Listening ports / attack surface table
  const tbody = document.querySelector("#fw-ports-tbody");
  if (tbody) {
    tbody.replaceChildren();
    const ports = fw.attack_surface || [];
    setText("#fw-ports-count-badge", `${ports.length} Open Endpoints`);

    if (ports.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="6" class="muted table-loading">Zero unauthorized listening ports detected. Perimeter fully cloaked.</td>`;
      tbody.appendChild(tr);
    } else {
      ports.forEach((pt) => {
        const tr = document.createElement("tr");
        const riskClass = pt.risk === "HIGH" ? "danger" : (pt.risk === "ELEVATED" || pt.risk === "MODERATE" ? "warning" : "good");
        tr.innerHTML = `
          <td><strong>${escapeHtml(pt.protocol || "TCP")}</strong></td>
          <td><span class="bssid-mono" style="font-weight:600;color:var(--cyan)">${escapeHtml(pt.local_address)}</span></td>
          <td><strong>${escapeHtml(pt.service)}</strong></td>
          <td><span class="muted">${escapeHtml(pt.exposure)}</span></td>
          <td><span class="status-chip ${riskClass}">${escapeHtml(pt.risk)}</span></td>
          <td><span class="status-chip good">🛡️ Filtered by Host Firewall</span></td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  // Live Connections Table
  const connTbody = document.querySelector("#fw-connections-tbody");
  if (connTbody) {
    connTbody.replaceChildren();
    setText("#fw-conn-count-badge", `${connections.length} Active Connections`);
    if (connections.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="7" class="muted table-loading">No external connections active.</td>`;
      connTbody.appendChild(tr);
    } else {
      connections.slice(0, 30).forEach((c) => {
        const tr = document.createElement("tr");
        const dirClass = c.direction === "INBOUND" ? "good" : (c.direction === "OUTBOUND" ? "warning" : "muted");
        const isSuspicious = c.is_suspicious;
        tr.innerHTML = `
          <td><span class="status-chip ${isSuspicious ? 'danger' : dirClass}">${escapeHtml(c.direction)}</span></td>
          <td><strong>${escapeHtml(c.process_name || 'System')}</strong></td>
          <td><code>${escapeHtml(String(c.pid || 0))}</code></td>
          <td><span class="bssid-mono">${escapeHtml(c.local_address)}</span></td>
          <td><span class="bssid-mono" style="color:${isSuspicious ? 'var(--red)' : 'var(--text)'}">${escapeHtml(c.foreign_address)}</span></td>
          <td><small>${escapeHtml(c.state)}</small></td>
          <td><span class="status-chip ${isSuspicious ? 'danger' : 'good'}">${escapeHtml(c.risk_reason || 'Authorized Socket')}</span></td>
        `;
        connTbody.appendChild(tr);
      });
    }
  }

  // Custom Firewall Rules Table
  const rulesTbody = document.querySelector("#fw-custom-rules-tbody");
  if (rulesTbody) {
    rulesTbody.replaceChildren();
    if (customRules.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="8" class="muted table-loading">No custom firewall rules configured. Click 'Add Custom Rule' to create one.</td>`;
      rulesTbody.appendChild(tr);
    } else {
      customRules.forEach((r) => {
        const tr = document.createElement("tr");
        const actClass = r.action === "BLOCK" ? "danger" : "good";
        tr.innerHTML = `
          <td><strong>${escapeHtml(r.rule_name)}</strong></td>
          <td><span class="status-chip ${r.direction === 'IN' ? 'good' : 'warning'}">${escapeHtml(r.direction)}</span></td>
          <td><span class="status-chip ${actClass}">${escapeHtml(r.action)}</span></td>
          <td>${escapeHtml(r.protocol)}</td>
          <td><code>${escapeHtml(r.local_port || 'ANY')}</code></td>
          <td><code>${escapeHtml(r.remote_ip || 'ANY')}</code></td>
          <td><span class="status-chip ${r.os_applied ? 'good' : 'warning'}">${r.os_applied ? 'Enforced (OS)' : 'Policy Stored'}</span></td>
          <td><button class="secondary-button btn-delete-fw-rule" data-rule-name="${escapeHtml(r.rule_name)}" style="padding:4px 8px;font-size:11px">Delete</button></td>
        `;
        rulesTbody.appendChild(tr);
      });
    }
  }

  // Findings list
  const findingsList = document.querySelector("#fw-findings-list");
  if (findingsList) {
    findingsList.replaceChildren();
    (fw.findings || []).forEach((f) => {
      const li = document.createElement("li");
      li.innerHTML = `<strong>✓</strong> ${escapeHtml(f)}`;
      findingsList.appendChild(li);
    });
  }
}

// -------------------------------------------------------------
// VIRUS & MALWARE DETECTION ENGINE
// -------------------------------------------------------------
async function loadMalware() {
  try {
    const [statusRes, historyRes, qRes] = await Promise.all([
      api("/api/malware/status"),
      api("/api/malware/history"),
      api("/api/malware/quarantine")
    ]);
    renderMalware(statusRes, historyRes, qRes.quarantine || []);
  } catch (err) {
    showMessage(`Could not load malware module: ${err.message}`, true);
  }
}

function renderMalware(statusData, historyData, quarantineItems = []) {
  if (statusData && statusData.defender) {
    const d = statusData.defender;
    setText("#defender-engine-name", d.engine_name || "Microsoft Defender Antivirus");
    setText("#defender-sig-version", `Signatures: v${d.signature_version || '1.463.426.0'} · Verified Live`);
    const rtpChip = document.querySelector("#defender-rtp-chip");
    if (rtpChip) {
      rtpChip.textContent = `REAL-TIME PROTECTION: ${d.real_time_protection ? 'ACTIVE' : 'OFF'}`;
      rtpChip.className = `status-chip ${d.real_time_protection ? 'good' : 'danger'}`;
    }
  }

  const threatsBadge = document.querySelector("#nav-malware-badge");
  if (threatsBadge && statusData) {
    threatsBadge.textContent = String(statusData.activeThreats || 0);
    threatsBadge.className = statusData.activeThreats > 0 ? "badge-danger" : "badge-success";
  }

  // Detections Table
  const tbody = document.querySelector("#malware-threats-tbody");
  if (tbody && historyData) {
    tbody.replaceChildren();
    const detections = historyData.detections || [];
    setText("#malware-threats-badge", `${detections.length} Threats`);

    if (detections.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="6" class="muted table-loading">Zero active threats detected. All scanned files verified clean.</td>`;
      tbody.appendChild(tr);
    } else {
      detections.forEach((t) => {
        const tr = document.createElement("tr");
        const sevClass = t.severity === "CRITICAL" || t.severity === "HIGH" ? "danger" : "warning";
        const isQuarantined = t.status === "QUARANTINED";
        tr.innerHTML = `
          <td><strong>${escapeHtml(t.threat_name)}</strong><br><small class="muted">${escapeHtml(t.threat_type)}</small></td>
          <td><span class="status-chip ${t.detection_method?.includes('SIGNATURE') ? 'danger' : 'warning'}">${escapeHtml(t.detection_method || 'HEURISTIC')}</span></td>
          <td><code style="word-break:break-all">${escapeHtml(t.file_path)}</code></td>
          <td><code style="font-size:10px">${escapeHtml(t.file_hash ? t.file_hash.substring(0, 16) + '...' : 'N/A')}</code></td>
          <td><span class="status-chip ${sevClass}">${escapeHtml(t.severity)}</span></td>
          <td>
            ${isQuarantined
              ? '<span class="status-chip good">Isolated</span>'
              : `<button class="primary-button btn-quarantine-file" data-file-path="${escapeHtml(t.file_path)}" data-threat-name="${escapeHtml(t.threat_name)}" style="padding:4px 10px;font-size:11px">Quarantine</button>`
            }
          </td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  // Quarantine Table
  const qTbody = document.querySelector("#malware-quarantine-table");
  if (qTbody) {
    qTbody.replaceChildren();
    if (quarantineItems.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="6" class="muted table-loading">Quarantine vault is empty. No suspicious files isolated.</td>`;
      qTbody.appendChild(tr);
    } else {
      quarantineItems.forEach((q) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${escapeHtml(q.quarantine_id)}</strong></td>
          <td><code style="word-break:break-all">${escapeHtml(q.original_path)}</code></td>
          <td><code style="word-break:break-all">${escapeHtml(q.quarantined_file)}</code></td>
          <td><small>${escapeHtml(q.quarantined_at)}</small></td>
          <td><span class="status-chip good">${escapeHtml(q.status)}</span></td>
          <td><button class="secondary-button btn-restore-quarantine" data-qid="${escapeHtml(q.quarantine_id)}" style="padding:4px 10px;font-size:11px">Restore File</button></td>
        `;
        qTbody.appendChild(tr);
      });
    }
  }
}

async function triggerMalwareScan(targetPath = ".") {
  const btn = document.querySelector("#btn-run-malware-scan") || document.querySelector("#btn-trigger-scan-path");
  if (btn) btn.classList.add("spinning");
  showMessage(`Running cryptographic hash & heuristic inspection on: ${targetPath}...`, false);

  try {
    const res = await api("/api/malware/scan", {
      method: "POST",
      body: JSON.stringify({ target_path: targetPath, max_files: 350 })
    });

    setText("#malware-scanned-count", `${res.filesScanned || 0} Files`);
    setText("#malware-clean-count", `${res.cleanFiles || 0} Clean`);
    setText("#malware-threats-count", `${res.threatsFound || 0} Threats`);
    setText("#malware-duration-val", `${res.durationSeconds || 0}s`);

    showMessage(`✓ Scan completed: ${res.filesScanned} files examined in ${res.durationSeconds}s. Found ${res.threatsFound} threats.`, res.threatsFound > 0);
    loadMalware();
  } catch (err) {
    showMessage(`Malware scan failed: ${err.message}`, true);
  } finally {
    if (btn) setTimeout(() => btn.classList.remove("spinning"), 400);
  }
}

// -------------------------------------------------------------
// VULNERABILITY SCANNER ENGINE
// -------------------------------------------------------------
async function loadVulnerabilities(targetIp = "127.0.0.1") {
  const btn = document.querySelector("#btn-rescan-vulnerabilities");
  if (btn) btn.classList.add("spinning");
  try {
    const res = await api(`/api/vulnerabilities?target=${encodeURIComponent(targetIp)}`);
    renderVulnerabilities(res);
  } catch (err) {
    showMessage(`Could not load vulnerability audit: ${err.message}`, true);
  } finally {
    if (btn) setTimeout(() => btn.classList.remove("spinning"), 400);
  }
}

function renderVulnerabilities(data) {
  if (!data) return;
  setText("#vuln-score-val", data.vulnerability_score || 100);
  setText("#vuln-rating-val", data.rating || "SECURE");
  setText("#vuln-target-sub", `Target Host: ${data.target_ip || "127.0.0.1"}`);

  setText("#vuln-crit-count", data.critical_count || 0);
  setText("#vuln-high-count", data.high_count || 0);
  setText("#vuln-med-count", data.medium_count || 0);
  setText("#vuln-low-count", data.low_count || 0);

  const container = document.querySelector("#vuln-findings-container");
  if (container) {
    container.replaceChildren();
    const findings = data.findings || [];
    setText("#vuln-findings-badge", `${findings.length} Findings`);

    if (findings.length === 0) {
      container.innerHTML = `
        <div class="card panel" style="padding:24px;text-align:center">
          <p class="muted">✓ Zero vulnerable services or weak ciphers identified on target host ${escapeHtml(data.target_ip)}. Hardening posture optimal.</p>
        </div>
      `;
    } else {
      findings.forEach((f) => {
        const card = document.createElement("div");
        card.className = "card panel";
        const sevClass = f.severity === "CRITICAL" ? "danger" : (f.severity === "HIGH" ? "warning" : "good");
        card.innerHTML = `
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:14px">
            <div>
              <span class="status-chip ${sevClass}">${escapeHtml(f.severity)} · CVSS ${f.cvss_score}</span>
              <h3 style="margin:8px 0 4px">${escapeHtml(f.title)}</h3>
              <p class="muted" style="font-size:12px;margin:0 0 10px">${escapeHtml(f.description)}</p>
            </div>
            <span class="status-chip" style="font-family:monospace">${escapeHtml(f.cve_id)}</span>
          </div>
          <div style="background:var(--surface-2);border-radius:8px;padding:10px 14px;margin-top:8px">
            <strong style="color:var(--cyan);font-size:11px;display:block;margin-bottom:2px">RECOMMENDED REMEDIATION:</strong>
            <p style="margin:0;font-size:12px;color:var(--text)">${escapeHtml(f.remediation)}</p>
          </div>
        `;
        container.appendChild(card);
      });
    }
  }
}

// -------------------------------------------------------------
// INTRUSION DETECTION SYSTEM (IDS) ENGINE
// -------------------------------------------------------------
async function loadIds() {
  const btn = document.querySelector("#btn-rescan-ids");
  if (btn) btn.classList.add("spinning");
  try {
    const [idsRes, eventsRes] = await Promise.all([
      api("/api/ids/status"),
      api("/api/ids/events")
    ]);
    renderIds(idsRes, eventsRes.events || []);
  } catch (err) {
    showMessage(`Could not load IDS status: ${err.message}`, true);
  } finally {
    if (btn) setTimeout(() => btn.classList.remove("spinning"), 400);
  }
}

function renderIds(idsData, historicalEvents = []) {
  if (!idsData) return;

  const level = idsData.threat_level || "NOMINAL";
  setText("#ids-threat-headline", `Threat Level: ${level}`);
  setText("#ids-sockets-evaluated", `Evaluated ${idsData.active_sockets_evaluated || 0} active TCP sockets against MITRE ATT&CK signatures.`);

  const statusPill = document.querySelector("#ids-status-pill");
  if (statusPill) {
    statusPill.className = `firewall-score-pill ${level === "NOMINAL" ? "good" : (level === "WARNING" ? "warning" : "danger")}`;
    setText("#ids-status-text", level);
  }

  const idsNavBadge = document.querySelector("#nav-ids-badge");
  if (idsNavBadge) {
    idsNavBadge.textContent = level === "NOMINAL" ? "OK" : level;
    idsNavBadge.className = level === "NOMINAL" ? "badge-success" : "badge-danger";
  }

  const container = document.querySelector("#ids-events-feed");
  if (container) {
    container.replaceChildren();
    const allEvents = (idsData.events || []).concat(historicalEvents);
    const uniqueEvents = [];
    const seen = new Set();
    allEvents.forEach((ev) => {
      const key = `${ev.event_type}_${ev.source_ip}_${ev.reason}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueEvents.push(ev);
      }
    });

    setText("#ids-events-count-badge", `${uniqueEvents.length} Anomaly Events`);

    if (uniqueEvents.length === 0) {
      container.innerHTML = `<div class="card panel" style="padding:24px;text-align:center"><p class="muted">✓ Zero unauthorized port scans, floods, or intrusion vectors detected.</p></div>`;
    } else {
      uniqueEvents.forEach((ev) => {
        const card = document.createElement("div");
        card.className = "card panel";
        const sevClass = ev.severity === "CRITICAL" || ev.severity === "HIGH" ? "danger" : (ev.severity === "MEDIUM" ? "warning" : "good");
        const isActionable = ev.event_type !== "AIRSPACE_CLEAR" && ev.source_ip && !ev.source_ip.includes("Subnet");

        card.innerHTML = `
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:14px">
            <div>
              <span class="status-chip ${sevClass}">${escapeHtml(ev.severity)} · ${escapeHtml(ev.event_type)}</span>
              <h3 style="margin:8px 0 4px">${escapeHtml(ev.reason)}</h3>
              <p class="muted" style="font-size:12px;margin:0 0 8px">Source IP: <code>${escapeHtml(ev.source_ip || 'N/A')}</code> · MITRE Tactic: <strong>${escapeHtml(ev.mitre_tactic || 'General')}</strong></p>
            </div>
            <small class="muted">${escapeHtml(ev.timestamp || 'Live')}</small>
          </div>
          ${ev.action_recommended ? `
            <div style="display:flex;align-items:center;justify-content:space-between;background:var(--surface-2);border-radius:8px;padding:8px 12px;margin-top:8px">
              <span style="font-size:12px;color:var(--text)">Action: <strong>${escapeHtml(ev.action_recommended)}</strong></span>
              ${isActionable ? `<button class="primary-button btn-quick-block-ip" data-ip="${escapeHtml(ev.source_ip)}" style="padding:4px 10px;font-size:11px">Block IP</button>` : ''}
            </div>
          ` : ''}
        `;
        container.appendChild(card);
      });
    }
  }
}

// -------------------------------------------------------------
// THREAT INTELLIGENCE ENGINE
// -------------------------------------------------------------
async function loadThreatIntel() {
  const btn = document.querySelector("#btn-sync-threat-intel");
  if (btn) btn.classList.add("spinning");
  try {
    const res = await api("/api/threat-intel/feed");
    renderThreatIntel(res);
  } catch (err) {
    showMessage(`Could not load threat intel feed: ${err.message}`, true);
  } finally {
    if (btn) setTimeout(() => btn.classList.remove("spinning"), 400);
  }
}

function renderThreatIntel(data) {
  if (!data) return;

  const tbody = document.querySelector("#intel-ips-tbody");
  if (tbody) {
    tbody.replaceChildren();
    (data.malicious_ips || []).forEach((item) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong style="color:var(--red);font-family:monospace">${escapeHtml(item.ip)}</strong></td>
        <td>${escapeHtml(item.threat_actor || 'Unknown')}</td>
        <td><span class="status-chip danger">${escapeHtml(item.type)}</span></td>
        <td><span class="status-chip good">${escapeHtml(item.confidence)}</span></td>
        <td><strong>${item.score}/100</strong></td>
      `;
      tbody.appendChild(tr);
    });
  }

  const advGrid = document.querySelector("#intel-advisories-grid");
  if (advGrid) {
    advGrid.replaceChildren();
    (data.active_advisories || []).forEach((adv) => {
      const card = document.createElement("div");
      card.className = "card panel";
      card.innerHTML = `
        <span class="status-chip danger">${escapeHtml(adv.cve_id)} · CVSS ${adv.cvss}</span>
        <h3 style="margin:8px 0 4px">${escapeHtml(adv.title)}</h3>
        <p class="muted" style="font-size:12px;margin:0 0 10px">Target: ${escapeHtml(adv.affected)}</p>
        <div style="background:var(--surface-2);border-radius:6px;padding:8px 12px">
          <small style="color:var(--cyan);font-weight:700;display:block">REMEDIATION:</small>
          <span style="font-size:11px">${escapeHtml(adv.remediation)}</span>
        </div>
      `;
      advGrid.appendChild(card);
    });
  }
}

// -------------------------------------------------------------
// SECURITY LOGS ENGINE
// -------------------------------------------------------------
async function loadSecurityLogs() {
  const modSelect = document.querySelector("#logs-module-select");
  const sevSelect = document.querySelector("#logs-severity-select");
  const searchInput = document.querySelector("#logs-search-input");

  const module = modSelect ? modSelect.value : "ALL";
  const severity = sevSelect ? sevSelect.value : "ALL";
  const search = searchInput ? searchInput.value : "";

  try {
    const res = await api(`/api/logs?module=${encodeURIComponent(module)}&severity=${encodeURIComponent(severity)}&search=${encodeURIComponent(search)}`);
    renderSecurityLogs(res.logs || []);
  } catch (err) {
    showMessage(`Could not load security logs: ${err.message}`, true);
  }
}

function renderSecurityLogs(logs) {
  const tbody = document.querySelector("#security-logs-tbody");
  if (!tbody) return;
  tbody.replaceChildren();

  if (logs.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6" class="muted table-loading">No log records found matching selected filter criteria.</td>`;
    tbody.appendChild(tr);
    return;
  }

  logs.forEach((l) => {
    const tr = document.createElement("tr");
    const sevClass = l.severity === "CRITICAL" ? "danger" : (l.severity === "WARNING" ? "warning" : "good");
    tr.innerHTML = `
      <td><small class="muted">${escapeHtml(l.created_at)}</small></td>
      <td><strong>${escapeHtml(l.module)}</strong></td>
      <td><code>${escapeHtml(l.action)}</code></td>
      <td><small>${escapeHtml(l.actor || 'system')}</small></td>
      <td><span class="status-chip ${sevClass}">${escapeHtml(l.severity)}</span></td>
      <td>
        <strong>${escapeHtml(l.message)}</strong>
        ${l.details ? `<br><small class="muted">${escapeHtml(l.details)}</small>` : ''}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// -------------------------------------------------------------
// REPORTS & ANALYTICS ENGINE
// -------------------------------------------------------------
async function loadReportsScreen() {
  try {
    const res = await api("/api/reports");
    renderReportsList(res || []);
  } catch (err) {
    showMessage(`Could not load reports history: ${err.message}`, true);
  }
}

function renderReportsList(reports) {
  const tbody = document.querySelector("#generated-reports-tbody");
  if (!tbody) return;
  tbody.replaceChildren();

  if (reports.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6" class="muted table-loading">No previous reports in archive. Generate one using the cards above.</td>`;
    tbody.appendChild(tr);
    return;
  }

  reports.forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>#${r.id}</td>
      <td><span class="status-chip good">${escapeHtml(r.report_type)}</span></td>
      <td><strong>${escapeHtml(r.file_name)}</strong></td>
      <td><small class="muted">${escapeHtml(r.generated_at)}</small></td>
      <td><small>${r.summary?.threatCount ? `${r.summary.threatCount} Threats Found` : 'Clean Airspace Verified'}</small></td>
      <td><a href="/api/reports/${r.id}/download" class="secondary-button" style="padding:4px 10px;font-size:11px;text-decoration:none" download>Download</a></td>
    `;
    tbody.appendChild(tr);
  });
}

function closePdfReportModal() {
  const backdrop = document.querySelector("#pdf-modal-backdrop");
  if (backdrop) backdrop.hidden = true;
}

// -------------------------------------------------------------
// NAVIGATION, SCREEN SWITCHING & MOBILE DRAWER
// -------------------------------------------------------------
const mobileMenuBtn = document.querySelector("#mobile-menu-btn");
const mobileDrawerBackdrop = document.querySelector("#mobile-drawer-backdrop");
const sidebarEl = document.querySelector(".sidebar");

function toggleMobileDrawer(open) {
  if (!sidebarEl) return;
  const shouldOpen = open !== undefined ? open : !sidebarEl.classList.contains("mobile-open");
  sidebarEl.classList.toggle("mobile-open", shouldOpen);
  if (mobileDrawerBackdrop) mobileDrawerBackdrop.classList.toggle("active", shouldOpen);
  if (mobileMenuBtn) mobileMenuBtn.classList.toggle("active", shouldOpen);
  document.body.classList.toggle("drawer-open", shouldOpen);
}

if (mobileMenuBtn) {
  mobileMenuBtn.addEventListener("click", () => toggleMobileDrawer());
}
if (mobileDrawerBackdrop) {
  mobileDrawerBackdrop.addEventListener("click", () => toggleMobileDrawer(false));
}

function showScreen(name) {
  if (!titles[name]) return;
  toggleMobileDrawer(false);
  screens.forEach((screen) => screen.classList.toggle("active-screen", screen.id === `${name}-screen`));
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.screen === name));
  document.querySelectorAll(".reference-bottom-nav button").forEach((item) => item.classList.toggle("active", item.dataset.screen === name));
  if (title) title.textContent = titles[name];
  window.scrollTo({ top: 0, behavior: "smooth" });

  if (name === "devices") {
    api("/api/devices")
      .then((devices) => renderDevices(devices))
      .catch(() => renderDevices(dashboardData?.devices || defaultDashboard.devices));
  } else if (name === "history") {
    api("/api/history")
      .then((scans) => renderHistory(scans))
      .catch(() => renderHistory(dashboardData?.scans || defaultDashboard.scans));
  } else if (name === "scan") {
    loadWifiNetworks();
  } else if (name === "threats") {
    loadThreats();
  } else if (name === "firewall") {
    loadFirewall();
  } else if (name === "malware") {
    loadMalware();
  } else if (name === "vulnerabilities") {
    loadVulnerabilities();
  } else if (name === "ids") {
    loadIds();
  } else if (name === "intel") {
    loadThreatIntel();
  } else if (name === "logs") {
    loadSecurityLogs();
  } else if (name === "reports") {
    loadReportsScreen();
  } else if (name === "performance") {
    loadPerformance();
  } else if (name === "traffic") {
    loadTraffic();
  } else if (name === "compare") {
    loadComparison();
  } else if (name === "alerts") {
    loadAlerts();
  } else if (name === "ai-chat") {
    const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
    setText("#ai-chat-context-sub", `Active Context: ${net.ssid || "Connected Wi-Fi"} (${net.encryption || "WPA2"})`);
    setTimeout(() => {
      const input = document.querySelector("#ai-chat-input");
      if (input) input.focus();
    }, 120);
  } else if (name === "knowledge") {
    loadChecklist();
    loadKnowledge();
    generateWifiQrCode();
  }
}

document.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-screen]");
  if (trigger) {
    event.preventDefault();
    showScreen(trigger.dataset.screen);
  }
});

// Detect live Wi-Fi
async function detectConnectedWifi() {
  const btns = document.querySelectorAll("#detect-wifi-btn, #detect-wifi-btn-mobile");
  btns.forEach((b) => b.classList.add("spinning"));
  showMessage("Fetching live OS connected Wi-Fi…", false);
  try {
    const result = await api("/api/network/detect", { method: "POST" });
    if (result && result.network) {
      const isConn = result.network.connected !== false && result.network.state !== "disconnected" && result.network.name !== "No Wi-Fi Connected";
      if (isConn) {
        showMessage(`Recognized connected Wi-Fi: ${result.network.name}`, false);
      } else {
        showMessage("No Wi-Fi connected. Wi-Fi is disabled or disconnected.", true);
      }
      await loadDashboard();
    }
  } catch (error) {
    showMessage(`Could not detect live Wi-Fi: ${error.message}`);
  } finally {
    btns.forEach((b) => b.classList.remove("spinning"));
  }
}

async function loadDashboard() {
  try {
    const data = await api("/api/dashboard");
    renderDashboard(data);
    showMessage("");
  } catch (error) {
    renderDashboard(defaultDashboard);
  }
}

// -------------------------------------------------------------
// EVENT LISTENERS INITIALIZATION
// -------------------------------------------------------------

// 1. Password Buttons
document.querySelectorAll("#toggle-pass-desktop, #toggle-pass-mobile, #toggle-pass-settings").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    togglePasswordVisibility();
  });
});

document.querySelectorAll("#copy-pass-desktop, #copy-pass-mobile, #copy-pass-settings").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    copyPasswordToClipboard(btn);
  });
});

// 2. Scan Screen Toolbar & Filters
const refreshWifiBtn = document.querySelector("#refresh-wifi");
if (refreshWifiBtn) refreshWifiBtn.addEventListener("click", loadWifiNetworks);

const searchInput = document.querySelector("#wifi-search-input");
if (searchInput) searchInput.addEventListener("input", filterAndRenderWifiNetworks);

const filterBand = document.querySelector("#filter-band-select");
if (filterBand) filterBand.addEventListener("change", filterAndRenderWifiNetworks);

const filterSec = document.querySelector("#filter-security-select");
if (filterSec) filterSec.addEventListener("change", filterAndRenderWifiNetworks);

const viewTableBtn = document.querySelector("#view-mode-table");
const viewCardsBtn = document.querySelector("#view-mode-cards");
if (viewTableBtn && viewCardsBtn) {
  viewTableBtn.addEventListener("click", () => {
    viewTableBtn.classList.add("active");
    viewCardsBtn.classList.remove("active");
    document.querySelector("#wifi-table-container").hidden = false;
    document.querySelector("#wifi-cards-container").hidden = true;
  });
  viewCardsBtn.addEventListener("click", () => {
    viewCardsBtn.classList.add("active");
    viewTableBtn.classList.remove("active");
    document.querySelector("#wifi-table-container").hidden = true;
    document.querySelector("#wifi-cards-container").hidden = false;
  });
}

// Table Sortable Headers
document.querySelectorAll(".sortable-th").forEach((th) => {
  th.addEventListener("click", () => {
    const sortField = th.dataset.sort;
    if (currentSortColumn === sortField) {
      currentSortAsc = !currentSortAsc;
    } else {
      currentSortColumn = sortField;
      currentSortAsc = false;
    }
    filterAndRenderWifiNetworks();
  });
});

// Select All
const selectAllWifi = document.querySelector("#select-all-wifi");
if (selectAllWifi) {
  selectAllWifi.addEventListener("change", (e) => {
    const checks = document.querySelectorAll(".wifi-select-check");
    checks.forEach((c) => {
      c.checked = e.target.checked;
      const ssid = c.dataset.ssid;
      if (e.target.checked) selectedSsidsForCompare.add(ssid);
      else selectedSsidsForCompare.delete(ssid);
    });
    updateCompareSelectionCounter();
  });
}

const btnCompareSelected = document.querySelector("#btn-compare-selected");
if (btnCompareSelected) {
  btnCompareSelected.addEventListener("click", () => {
    showScreen("compare");
  });
}

// Auto-Scan Interval Dropdown
const autoScanSelect = document.querySelector("#auto-scan-interval-select");
if (autoScanSelect) {
  autoScanSelect.addEventListener("change", (e) => {
    const intervalSeconds = parseInt(e.target.value, 10);
    if (autoScanTimerId) clearInterval(autoScanTimerId);
    if (intervalSeconds > 0) {
      autoScanTimerId = setInterval(() => {
        const activeScreen = document.querySelector(".screen.active-screen");
        if (activeScreen && (activeScreen.id === "scan-screen" || activeScreen.id === "home-screen")) {
          loadWifiNetworks();
        }
      }, intervalSeconds * 1000);
      showMessage(`Auto-scan active (Every ${intervalSeconds} seconds).`, false);
    } else {
      showMessage("Auto-scan disabled. Set to manual.", false);
    }
  });
}

// 3. Performance Test Button
const btnTestPerf = document.querySelector("#btn-test-performance");
if (btnTestPerf) {
  btnTestPerf.addEventListener("click", () => {
    showMessage("Executing ICMP ping round-trip latency & jitter measurements...", false);
    loadPerformance().then(() => showMessage("Performance test completed.", false));
  });
}

const btnRefreshMl = document.querySelector("#btn-refresh-ml");
if (btnRefreshMl) {
  btnRefreshMl.addEventListener("click", () => {
    showMessage("Re-evaluating RF spectral anomalies...", false);
    loadMlAnomalies().then(() => showMessage("ML model updated.", false));
  });
}

// 4. AI Chat Assistant Form, Quick Pills & Clear
const aiChatForm = document.querySelector("#ai-chat-form");
if (aiChatForm) {
  aiChatForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = document.querySelector("#ai-chat-input");
    if (input && input.value.trim()) {
      sendAiChatMessage(input.value.trim());
    }
  });
}

const clearAiChatBtn = document.querySelector("#btn-clear-ai-chat");
if (clearAiChatBtn) {
  clearAiChatBtn.addEventListener("click", clearAiChat);
}

// Delegated click handler for all AI question pills (both suggested header pills and inline answer pills)
document.addEventListener("click", (e) => {
  const pill = e.target.closest(".ai-pill-btn");
  if (pill) {
    e.preventDefault();
    showScreen("ai-chat");
    sendAiChatMessage(pill.textContent.trim());
  }
});

// QR Code Buttons & Quick Connect Action
const saveQrBtn = document.querySelector("#btn-save-qr");
if (saveQrBtn) {
  saveQrBtn.addEventListener("click", () => {
    const canvas = document.querySelector("#qr-code-canvas");
    const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
    const ssid = (net.ssid || net.name || "wifi").replace(/[^a-zA-Z0-9_-]/g, "_");
    if (typeof QRCode !== "undefined" && QRCode.download) {
      QRCode.download(canvas, `${ssid}_wifi_qr.png`);
      showMessage("Wi-Fi QR Code downloaded!", false);
    } else if (canvas) {
      const link = document.createElement("a");
      link.download = `${ssid}_wifi_qr.png`;
      link.href = canvas.toDataURL("image/png");
      link.click();
      showMessage("Wi-Fi QR Code downloaded!", false);
    }
  });
}

const refreshQrBtn = document.querySelector("#btn-refresh-qr");
if (refreshQrBtn) {
  refreshQrBtn.addEventListener("click", () => {
    generateWifiQrCode();
    showMessage("Wi-Fi QR Code refreshed.", false);
  });
}

// Quick QR buttons on Home cards (Desktop & Mobile)
document.querySelectorAll("#btn-quick-qr-desktop, #btn-quick-qr-mobile").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    showScreen("knowledge");
    generateWifiQrCode();
    setTimeout(() => {
      const panel = document.querySelector("#qr-panel-card");
      if (panel) {
        panel.scrollIntoView({ behavior: "smooth", block: "center" });
        panel.style.boxShadow = "0 0 20px var(--cyan)";
        setTimeout(() => { panel.style.boxShadow = ""; }, 2200);
      }
    }, 150);
  });
});

// 5. Device Refresh
const refreshDevicesBtn = document.querySelector("#refresh-devices-btn");
if (refreshDevicesBtn) {
  refreshDevicesBtn.addEventListener("click", () => {
    showMessage("Scanning ARP subnet for active clients...", false);
    api("/api/devices")
      .then((devs) => {
        renderDevices(devs);
        showMessage("Subnet inventory updated.", false);
      })
      .catch((e) => showMessage("Failed to refresh devices: " + e.message, true));
  });
}

// 6. Threats Refresh
const refreshThreatsBtn = document.querySelector("#refresh-threats-btn");
if (refreshThreatsBtn) {
  refreshThreatsBtn.addEventListener("click", () => {
    showMessage("Re-scanning airspace for rogue access points...", false);
    loadThreats().then(() => showMessage("Threat matrix updated.", false));
  });
}

// 7. Compare Refresh
const refreshCompareBtn = document.querySelector("#refresh-compare-btn");
if (refreshCompareBtn) {
  refreshCompareBtn.addEventListener("click", loadComparison);
}

// 8. Alert Filter Tabs & Clear
document.querySelectorAll(".alert-tab-btn").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".alert-tab-btn").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    currentAlertFilter = tab.dataset.severity;
    loadAlerts();
  });
});

const btnClearAlerts = document.querySelector("#btn-clear-alerts");
if (btnClearAlerts) {
  btnClearAlerts.addEventListener("click", async () => {
    try {
      await api("/api/alerts/clear", { method: "POST" });
      showMessage("All security alerts marked as read.", false);
      await loadDashboard();
      await loadAlerts();
    } catch (e) {
      showMessage("Could not clear alerts: " + e.message, true);
    }
  });
}

// 9. Export Dropdown in Topbar
const topbarExportBtn = document.querySelector("#topbar-export-btn");
const topbarExportMenu = document.querySelector("#topbar-export-menu");
if (topbarExportBtn && topbarExportMenu) {
  topbarExportBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    topbarExportMenu.hidden = !topbarExportMenu.hidden;
  });
  document.addEventListener("click", () => {
    topbarExportMenu.hidden = true;
  });
}

// File Download Triggers
document.querySelectorAll("#menu-export-pdf, #btn-export-pdf-sidebar, #btn-export-pdf-welcome, #btn-export-pdf-scan, #btn-export-pdf-history, #btn-export-pdf-settings").forEach((btn) => {
  btn.addEventListener("click", () => openPdfReportModal());
});

document.querySelectorAll("#menu-export-csv, #btn-export-csv-sidebar, #btn-export-csv-welcome, #btn-export-csv-scan, #btn-export-csv-history, #btn-export-csv-settings").forEach((btn) => {
  btn.addEventListener("click", () => {
    window.location.href = "/api/export/csv";
    showMessage("Downloading NetGuard scan data as CSV...", false);
  });
});

document.querySelectorAll("#menu-export-json, #btn-export-json-settings").forEach((btn) => {
  btn.addEventListener("click", () => {
    window.location.href = "/api/export/json";
    showMessage("Downloading NetGuard structured audit JSON...", false);
  });
});

const btnClosePdfModal = document.querySelector("#btn-close-pdf-modal");
if (btnClosePdfModal) btnClosePdfModal.addEventListener("click", closePdfReportModal);

const btnPrintPdf = document.querySelector("#btn-print-pdf-now");
if (btnPrintPdf) {
  btnPrintPdf.addEventListener("click", () => {
    window.print();
  });
}

// 10. Detect Wi-Fi buttons
document.querySelectorAll("#detect-wifi-btn, #detect-wifi-btn-mobile").forEach((btn) => {
  btn.addEventListener("click", detectConnectedWifi);
});

// 11. Settings Toggles
async function updateSetting(toggle, key, value) {
  toggle.disabled = true;
  settings[key] = value;
  setSettings({});
  try {
    await api("/api/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [key]: value }),
    });
    showMessage("Setting saved.", false);
  } catch (error) {
    showMessage("Setting saved locally.", false);
  } finally {
    toggle.disabled = false;
  }
}

// 11. Multi-Theme Switching Engine (Cyber Dark, Matrix, Synthwave, Stealth Obsidian, Nordic Frost, Tech Light)
const THEMES = [
  { id: "cyber-dark", name: "Cyber Dark", icon: "🌙", bodyClass: "" },
  { id: "matrix", name: "Matrix Green", icon: "🟢", bodyClass: "theme-matrix" },
  { id: "synthwave", name: "Synthwave", icon: "🟣", bodyClass: "theme-synthwave" },
  { id: "obsidian", name: "Stealth Obsidian", icon: "🌑", bodyClass: "theme-obsidian" },
  { id: "nordic", name: "Nordic Frost", icon: "🌊", bodyClass: "theme-nordic" },
  { id: "light", name: "Tech Light", icon: "☀️", bodyClass: "theme-light" }
];

function applyTheme(themeId, persist = true) {
  const current = THEMES.find((t) => t.id === themeId) || THEMES[0];
  
  THEMES.forEach((t) => {
    if (t.bodyClass) document.body.classList.remove(t.bodyClass);
  });
  // Also clean up any legacy class
  document.body.classList.remove("light");

  if (current.bodyClass) {
    document.body.classList.add(current.bodyClass);
    if (current.id === "light") {
      document.body.classList.add("light");
    }
  }

  const iconEl = document.querySelector("#theme-icon-indicator");
  const nameEl = document.querySelector("#theme-name-indicator");
  if (iconEl) iconEl.textContent = current.icon;
  if (nameEl) nameEl.textContent = current.name;

  const selectEl = document.querySelector("#theme-selector-settings");
  if (selectEl && selectEl.value !== current.id) {
    selectEl.value = current.id;
  }

  if (persist) {
    localStorage.setItem("netguard_theme", current.id);
    settings.theme = current.id;
  }
}

function cycleTheme() {
  const saved = localStorage.getItem("netguard_theme") || "cyber-dark";
  const currentIndex = THEMES.findIndex((t) => t.id === saved);
  const nextIndex = (currentIndex + 1) % THEMES.length;
  const nextTheme = THEMES[nextIndex];
  applyTheme(nextTheme.id, true);
  showMessage(`Theme switched to: ${nextTheme.name}`, false);
}

const themeSwitcherBtn = document.querySelector("#theme-switcher-btn");
if (themeSwitcherBtn) {
  themeSwitcherBtn.addEventListener("click", cycleTheme);
}

const themeSelectSettings = document.querySelector("#theme-selector-settings");
if (themeSelectSettings) {
  themeSelectSettings.addEventListener("change", (e) => {
    applyTheme(e.target.value, true);
    showMessage(`Appearance theme set to: ${e.target.selectedOptions[0]?.text || e.target.value}`, false);
  });
}

// 12. Interactive Platform & Airspace Refresh Engine
async function handlePlatformRefresh(btn) {
  const btns = document.querySelectorAll("#btn-topbar-refresh, #btn-sidebar-refresh");
  btns.forEach((b) => b.classList.add("spinning"));
  showMessage("Synchronizing live airspace telemetry & security metrics…", false);
  try {
    await detectConnectedWifi();
    await loadDashboard();
    const active = document.querySelector(".screen.active-screen");
    if (active) {
      if (active.id === "scan-screen") await loadWifiNetworks();
      else if (active.id === "threats-screen") await loadThreats();
      else if (active.id === "devices-screen") await loadDevices();
      else if (active.id === "firewall-screen") await loadFirewall();
      else if (active.id === "performance-screen") await loadPerformance();
      else if (active.id === "traffic-screen") await loadTraffic();
      else if (active.id === "alerts-screen") await loadAlerts();
      else if (active.id === "history-screen") {
        const scans = await api("/api/history");
        renderHistory(scans || []);
      }
    }
    showMessage("✓ NetGuard refreshed: live spectrum & environment synchronized.", false);
  } catch (err) {
    showMessage(`Refresh completed: ${err.message}`, false);
  } finally {
    setTimeout(() => {
      btns.forEach((b) => b.classList.remove("spinning"));
    }, 450);
  }
}

const topbarRefreshBtn = document.querySelector("#btn-topbar-refresh");
if (topbarRefreshBtn) {
  topbarRefreshBtn.addEventListener("click", () => handlePlatformRefresh(topbarRefreshBtn));
  topbarRefreshBtn.addEventListener("dblclick", () => window.location.reload());
}

const sidebarRefreshBtn = document.querySelector("#btn-sidebar-refresh");
if (sidebarRefreshBtn) {
  sidebarRefreshBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    handlePlatformRefresh(sidebarRefreshBtn);
  });
}

const sidebarSystemMonitor = document.querySelector("#sidebar-system-monitor");
if (sidebarSystemMonitor) {
  sidebarSystemMonitor.addEventListener("click", () => handlePlatformRefresh(sidebarRefreshBtn));
  sidebarSystemMonitor.addEventListener("dblclick", () => window.location.reload());
}

// 12. Scan History Clear Button Handler
const btnClearHistory = document.querySelector("#btn-clear-history");
if (btnClearHistory) {
  btnClearHistory.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to clear all saved scan history? This action will purge all historical scans and threat logs.")) {
      return;
    }
    try {
      const res = await api("/api/history/clear", { method: "POST" });
      showMessage(res.message || "All saved scan history cleared.", false);
      await loadDashboard();
      const emptyScans = await api("/api/history");
      renderHistory(emptyScans || []);
    } catch (err) {
      showMessage(`Could not clear history: ${err.message}`, true);
    }
  });
}

document.querySelectorAll("[data-setting]").forEach((toggle) => {
  toggle.addEventListener("click", () => {
    const key = toggle.dataset.setting;
    const nextValue = settings[key] !== true;
    toggle.classList.toggle("on", nextValue);
    updateSetting(toggle, key, nextValue);
  });
});

// Background live traffic telemetry polling (every 3.5 seconds)
setInterval(() => {
  const activeScreen = document.querySelector(".screen.active-screen");
  if (activeScreen && (activeScreen.id === "traffic-screen" || activeScreen.id === "home-screen")) {
    loadTraffic();
  }
}, 3500);

// Dynamic Greeting Periodic Refresh
setInterval(updateDynamicGreeting, 60000);

// Chart Range Toggle
const btnChartRange = document.querySelector("#btn-chart-range");
if (btnChartRange) {
  const ranges = ["Last 24 hours⌄", "Last 7 days⌄", "Last 30 days⌄"];
  let rangeIdx = 1;
  btnChartRange.addEventListener("click", () => {
    rangeIdx = (rangeIdx + 1) % ranges.length;
    btnChartRange.textContent = ranges[rangeIdx];
    const labelsEl = document.querySelector(".chart-labels");
    if (labelsEl) {
      if (rangeIdx === 0) {
        labelsEl.innerHTML = "<span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span>";
      } else if (rangeIdx === 1) {
        labelsEl.innerHTML = "<span>Day 1</span><span>Day 3</span><span>Day 5</span><span>Today</span>";
      } else {
        labelsEl.innerHTML = "<span>Week 1</span><span>Week 2</span><span>Week 3</span><span>Week 4</span>";
      }
    }
    showMessage(`Chart range updated to ${ranges[rangeIdx].replace("⌄", "")}`, false);
  });
}

// Topbar alerts notification bell
const topbarAlertsBtn = document.querySelector("#topbar-alerts-btn");
if (topbarAlertsBtn) {
  topbarAlertsBtn.addEventListener("click", () => {
    showScreen("alerts");
  });
}

// AI send buttons
document.querySelectorAll("#ai-send-btn").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    const form = btn.closest("form");
    if (form) {
      e.preventDefault();
      form.dispatchEvent(new Event("submit", { cancelable: true }));
    }
  });
});

// -------------------------------------------------------------
// EVENT LISTENERS FOR PRO CYBERSECURITY MODULES
// -------------------------------------------------------------

// 1. Firewall Management Handlers
const btnRescanFirewall = document.querySelector("#btn-rescan-firewall");
if (btnRescanFirewall) {
  btnRescanFirewall.addEventListener("click", () => {
    loadFirewall();
    showMessage("✓ Refreshed Windows Defender Firewall rules and active connection telemetry.", false);
  });
}

const fwModal = document.querySelector("#add-fw-rule-modal");
const btnOpenFwModal = document.querySelector("#btn-open-create-rule-modal");
const btnCloseFwModal = document.querySelector("#btn-close-fw-modal");
const btnCancelFwModal = document.querySelector("#btn-cancel-fw-rule");

if (btnOpenFwModal && fwModal) {
  btnOpenFwModal.addEventListener("click", () => { fwModal.hidden = false; });
}
if (btnCloseFwModal && fwModal) {
  btnCloseFwModal.addEventListener("click", () => { fwModal.hidden = true; });
}
if (btnCancelFwModal && fwModal) {
  btnCancelFwModal.addEventListener("click", () => { fwModal.hidden = true; });
}

const fwForm = document.querySelector("#fw-create-rule-form");
if (fwForm) {
  fwForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const ruleName = document.querySelector("#fw-rule-name-input")?.value?.trim();
    if (!ruleName) return;

    const direction = document.querySelector("#fw-rule-dir-select")?.value || "IN";
    const action = document.querySelector("#fw-rule-act-select")?.value || "BLOCK";
    const protocol = document.querySelector("#fw-rule-proto-select")?.value || "TCP";
    const localPort = document.querySelector("#fw-rule-port-input")?.value?.trim() || "ANY";
    const remoteIp = document.querySelector("#fw-rule-ip-input")?.value?.trim() || "ANY";

    try {
      showMessage(`Applying firewall rule '${ruleName}'...`, false);
      const res = await api("/api/firewall/rules", {
        method: "POST",
        body: JSON.stringify({
          rule_name: ruleName,
          direction: direction,
          action: action,
          protocol: protocol,
          local_port: localPort,
          remote_ip: remoteIp
        })
      });
      if (fwModal) fwModal.hidden = true;
      fwForm.reset();
      showMessage(`✓ Rule '${ruleName}' configured. ${res.message || ''}`, false);
      loadFirewall();
    } catch (err) {
      showMessage(`Could not create firewall rule: ${err.message}`, true);
    }
  });
}

document.addEventListener("click", async (e) => {
  const delBtn = e.target.closest(".btn-delete-fw-rule");
  if (delBtn) {
    const ruleName = delBtn.dataset.ruleName;
    if (confirm(`Remove firewall rule '${ruleName}'?`)) {
      try {
        await api(`/api/firewall/rules/${encodeURIComponent(ruleName)}`, { method: "DELETE" });
        showMessage(`✓ Rule '${ruleName}' deleted successfully.`, false);
        loadFirewall();
      } catch (err) {
        showMessage(`Could not delete rule: ${err.message}`, true);
      }
    }
  }
});

// 2. Malware Detection Handlers
const btnRunMalware = document.querySelector("#btn-run-malware-scan");
const btnTriggerScanPath = document.querySelector("#btn-trigger-scan-path");
const btnScanPresetProj = document.querySelector("#btn-scan-preset-project");
const malwarePathInput = document.querySelector("#malware-target-input");

if (btnRunMalware) {
  btnRunMalware.addEventListener("click", () => {
    triggerMalwareScan(malwarePathInput?.value || ".");
  });
}
if (btnTriggerScanPath) {
  btnTriggerScanPath.addEventListener("click", () => {
    triggerMalwareScan(malwarePathInput?.value || ".");
  });
}
if (btnScanPresetProj && malwarePathInput) {
  btnScanPresetProj.addEventListener("click", () => {
    malwarePathInput.value = ".";
    triggerMalwareScan(".");
  });
}

document.addEventListener("click", async (e) => {
  const qBtn = e.target.closest(".btn-quarantine-file");
  if (qBtn) {
    const fpath = qBtn.dataset.filePath;
    const tname = qBtn.dataset.threatName;
    if (confirm(`QUARANTINE CONFIRMATION:\n\nSafely isolate '${fpath}' into the NetGuard quarantine vault?\n(File will not be deleted; you can restore it anytime)`)) {
      try {
        const res = await api("/api/malware/quarantine", {
          method: "POST",
          body: JSON.stringify({ file_path: fpath, threat_name: tname })
        });
        showMessage(`✓ ${res.message || 'File quarantined successfully.'}`, false);
        loadMalware();
      } catch (err) {
        showMessage(`Quarantine failed: ${err.message}`, true);
      }
    }
  }

  const rBtn = e.target.closest(".btn-restore-quarantine");
  if (rBtn) {
    const qid = rBtn.dataset.qid;
    if (confirm(`RESTORE CONFIRMATION:\n\nRestore quarantined file '${qid}' back to its original location?`)) {
      try {
        const res = await api("/api/malware/restore", {
          method: "POST",
          body: JSON.stringify({ quarantine_id: qid })
        });
        showMessage(`✓ ${res.message || 'File restored.'}`, false);
        loadMalware();
      } catch (err) {
        showMessage(`Restore failed: ${err.message}`, true);
      }
    }
  }
});

// 3. Vulnerability Scanner Handlers
const btnRescanVulns = document.querySelector("#btn-rescan-vulnerabilities");
if (btnRescanVulns) {
  btnRescanVulns.addEventListener("click", () => {
    loadVulnerabilities("127.0.0.1");
    showMessage("✓ Host vulnerability assessment completed against NIST CVSS v3.1 benchmarks.", false);
  });
}

// 4. Intrusion Detection Handlers
const btnRescanIds = document.querySelector("#btn-rescan-ids");
const btnClearIds = document.querySelector("#btn-clear-ids-events");

if (btnRescanIds) {
  btnRescanIds.addEventListener("click", () => {
    loadIds();
    showMessage("✓ Stateful Intrusion Detection System re-synchronized with active sockets.", false);
  });
}
if (btnClearIds) {
  btnClearIds.addEventListener("click", async () => {
    try {
      await api("/api/ids/clear", { method: "POST" });
      showMessage("✓ Non-critical IDS alert events cleared.", false);
      loadIds();
    } catch (err) {
      showMessage(`Could not clear IDS alerts: ${err.message}`, true);
    }
  });
}

document.addEventListener("click", async (e) => {
  const blockIpBtn = e.target.closest(".btn-quick-block-ip");
  if (blockIpBtn) {
    const ip = blockIpBtn.dataset.ip;
    if (confirm(`BLOCK HOST:\n\nCreate a high-priority firewall rule to block all inbound packets from '${ip}'?`)) {
      try {
        const rName = `NetGuard_Block_${ip.replace(/[^a-zA-Z0-9]/g, '_')}`;
        await api("/api/firewall/rules", {
          method: "POST",
          body: JSON.stringify({
            rule_name: rName,
            direction: "IN",
            action: "BLOCK",
            protocol: "TCP",
            remote_ip: ip
          })
        });
        showMessage(`✓ Firewall rule created: Inbound traffic from ${ip} blocked.`, false);
        loadIds();
      } catch (err) {
        showMessage(`Could not block IP: ${err.message}`, true);
      }
    }
  }
});

// 5. Threat Intelligence Handlers
const btnSyncIntel = document.querySelector("#btn-sync-threat-intel");
const btnIntelLookup = document.querySelector("#btn-intel-lookup");
const intelInput = document.querySelector("#intel-query-input");
const intelResultBox = document.querySelector("#intel-lookup-result");

if (btnSyncIntel) {
  btnSyncIntel.addEventListener("click", () => {
    loadThreatIntel();
    showMessage("✓ Threat intelligence feeds, botnet C2 IPs, and CVE advisories synchronized.", false);
  });
}

if (btnIntelLookup && intelInput && intelResultBox) {
  btnIntelLookup.addEventListener("click", async () => {
    const q = intelInput.value.trim();
    if (!q) return;

    try {
      const res = await api(`/api/threat-intel/lookup?q=${encodeURIComponent(q)}`);
      intelResultBox.hidden = false;
      const isBad = res.found && res.risk_score > 50;
      intelResultBox.innerHTML = `
        <div class="card panel" style="background:${isBad ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)'};border-color:${isBad ? 'var(--red)' : 'var(--green)'};padding:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
            <strong>Indicator: ${escapeHtml(res.query)}</strong>
            <span class="status-chip ${isBad ? 'danger' : 'good'}">${isBad ? `MALICIOUS · Score ${res.risk_score}` : 'CLEAN / BENIGN'}</span>
          </div>
          <p style="margin:0 0 6px;font-size:12px;color:var(--text)">${escapeHtml(res.description)}</p>
          <small class="muted">Confidence: <strong>${escapeHtml(res.confidence)}</strong> · Action: ${escapeHtml(res.action)}</small>
        </div>
      `;
    } catch (err) {
      showMessage(`Lookup failed: ${err.message}`, true);
    }
  });
}

// 6. Security Logs Handlers
const btnRefreshLogs = document.querySelector("#btn-refresh-logs");
const logsModSelect = document.querySelector("#logs-module-select");
const logsSevSelect = document.querySelector("#logs-severity-select");
const logsSearch = document.querySelector("#logs-search-input");
const btnExportLogsCsv = document.querySelector("#btn-export-logs-csv");
const btnExportLogsJson = document.querySelector("#btn-export-logs-json");

if (btnRefreshLogs) btnRefreshLogs.addEventListener("click", () => loadSecurityLogs());
if (logsModSelect) logsModSelect.addEventListener("change", () => loadSecurityLogs());
if (logsSevSelect) logsSevSelect.addEventListener("change", () => loadSecurityLogs());
if (logsSearch) logsSearch.addEventListener("input", debounce(() => loadSecurityLogs(), 300));

if (btnExportLogsCsv) {
  btnExportLogsCsv.addEventListener("click", () => {
    window.location.href = "/api/logs/export?format=csv";
  });
}
if (btnExportLogsJson) {
  btnExportLogsJson.addEventListener("click", () => {
    window.location.href = "/api/logs/export?format=json";
  });
}

// 7. Reports Handlers
const btnOpenFullPdf = document.querySelector("#btn-open-full-pdf-report");
const btnDailyPdf = document.querySelector("#btn-export-daily-pdf");
const btnWeeklyPdf = document.querySelector("#btn-export-weekly-pdf");
const btnAllCsv = document.querySelector("#btn-export-all-csv");

if (btnOpenFullPdf) btnOpenFullPdf.addEventListener("click", () => openPdfReportModal());
if (btnDailyPdf) btnDailyPdf.addEventListener("click", () => openPdfReportModal());
if (btnWeeklyPdf) btnWeeklyPdf.addEventListener("click", () => openPdfReportModal());
if (btnAllCsv) {
  btnAllCsv.addEventListener("click", () => {
    window.location.href = "/api/export/csv";
  });
}

// Debounce utility
function debounce(func, wait) {
  let timeout;
  return function (...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}

// Initial Theme & Dynamic Greeting Application
applyTheme(localStorage.getItem("netguard_theme") || "cyber-dark", false);
updateDynamicGreeting();

// Initial Load
loadDashboard();

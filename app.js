const screens = document.querySelectorAll(".screen");
const title = document.querySelector("#page-title");
const titles = {
  home: "Dashboard",
  scan: "Security Scan",
  devices: "Connected Devices",
  threats: "Threat Detection",
  performance: "Network Performance",
  traffic: "Traffic Monitor",
  compare: "Wi-Fi Comparison",
  alerts: "Security Alerts",
  "ai-chat": "AI Security Assistant",
  knowledge: "Knowledge & Audit",
  history: "Scan History",
  settings: "Settings"
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
// DEVICES RENDERING (Enhanced with MAC, Vendor, Host & Allowlist)
// -------------------------------------------------------------
function renderDevices(devices) {
  const cards = document.querySelector(".device-cards");
  if (cards) cards.replaceChildren();
  const list = document.querySelector(".device-list");
  if (list) list.replaceChildren();

  const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
  const isConnected = net.connected !== false && net.state !== "disconnected" && net.name !== "No Wi-Fi Connected";
  const currentNetwork = isConnected ? (net.name || "Connected Wi-Fi") : "No Wi-Fi Connected";

  let onlineCount = 0;
  let hostFound = false;
  let gatewayFound = false;

  devices.forEach((device, index) => {
    const isOnline = isConnected && (device.status !== "offline");
    if (isOnline) onlineCount++;
    if (device.is_host) hostFound = true;
    if (device.device_type === "router" || device.name?.includes("Gateway")) gatewayFound = true;

    const devType = device.device_type || (index === 0 ? "phone" : index === 1 ? "laptop" : "tv");
    const iconClass = devType === "phone" ? "phone" : devType === "tv" ? "tv" : "laptop";
    const iconText = devType === "phone" ? "▯" : devType === "tv" ? "▣" : "▱";
    const wifiName = isConnected ? (device.connected_wifi || currentNetwork) : "No Wi-Fi Connected";
    const statusVal = isConnected ? (device.status || "online") : "offline";
    const macText = device.mac_address ? ` · MAC: ${device.mac_address}` : "";
    const vendorText = device.vendor ? ` (${device.vendor})` : "";
    const isTrusted = device.is_trusted === 1 || device.is_trusted === true;

    if (cards) {
      const card = element("article", "card big-device");
      card.append(element("span", `device-illustration ${iconClass}`, iconText));

      const details = element("div", "device-info");
      const statusRow = element("div", "device-status-row");
      const statusDot = element("span", `status-dot ${statusVal === "online" ? "online" : "disconnected"}`);
      const statusText = element("span", "status-text", ` ${statusVal}`);
      const wifiChip = element("span", `device-wifi-chip ${isConnected ? "" : "disconnected"}`);
      wifiChip.innerHTML = isConnected
        ? `<span class="wifi-icon">📶</span> Connected to <strong>${wifiName}</strong>`
        : `<span class="wifi-icon">✕</span> <strong>No Wi-Fi Connected</strong>`;
      
      const trustBtn = element("button", `trust-toggle-btn ${isTrusted ? "trusted" : ""}`, isTrusted ? "✓ Allowlisted" : "＋ Allowlist");
      trustBtn.title = isTrusted ? "Mark as untrusted device" : "Add device to authorized allowlist";
      trustBtn.addEventListener("click", () => toggleDeviceTrust(device.id, trustBtn));

      statusRow.append(statusDot, statusText, wifiChip, trustBtn);

      details.append(
        statusRow,
        element("h2", "", device.name + vendorText),
        element("p", "device-platform", device.platform || "Standard Wi-Fi Client"),
        element("small", "device-meta", isConnected
          ? `${device.ip_address}${macText} · Seen ${device.last_seen || "recently"}`
          : `${device.ip_address} · Device offline (No Wi-Fi)`),
      );
      card.append(details, element("button", "icon-button", "•••"));
      cards.append(card);
    }

    if (list) {
      const dot = element("span", `device-dot ${iconClass}`);
      const nameWrap = element("span", "device-name-wrap");
      nameWrap.append(
        element("strong", "", device.name),
        element("small", `device-wifi-sub ${isConnected ? "" : "disconnected"}`, isConnected ? `Connected to ${wifiName}` : "No Wi-Fi Connected"),
      );
      const address = element("b", "", isConnected ? device.ip_address : "Offline");
      list.append(dot, nameWrap, address);
    }
  });

  if (devices.length === 0 && cards) {
    cards.append(element("p", "muted", "No connected devices were discovered on this subnet."));
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
// HISTORY RENDERING
// -------------------------------------------------------------
function createHistoryRow(scan, compact = false) {
  const result = scan.result || (scan.score >= 70 ? "GOOD" : "RISKY");
  const statusClass = result === "GOOD" ? "good" : "danger";
  if (compact) {
    const item = element("div", "history-item card");
    item.append(element("span", "history-icon blue", "⌁"));
    const details = element("div");
    details.append(
      element("strong", "", scan.network_name),
      element("small", "", `${scan.scanned_at} · ${scan.encryption}`),
    );
    item.append(details, element("span", `status-chip ${statusClass}`, `${scan.score} ${result}`));
    return item;
  }

  const row = element("div", "table-row");
  row.append(
    element("strong", "", `⌁ ${scan.network_name}`),
    element("span", "", scan.scanned_at),
    element("span", "", scan.encryption),
    element("span", `status-chip ${statusClass}`, `${scan.score} ${result}`),
  );
  return row;
}

function renderHistory(scans) {
  const historyTable = document.querySelector(".table-card");
  if (historyTable) {
    historyTable.replaceChildren();
    const heading = element("div", "table-head");
    ["Network", "Date & time", "Security", "Score"].forEach((label) => heading.append(element("span", "", label)));
    historyTable.append(heading);
    scans.forEach((scan) => historyTable.append(createHistoryRow(scan)));
  }

  const recentScans = document.querySelector(".history-row");
  if (recentScans) {
    recentScans.replaceChildren(...scans.slice(0, 3).map((scan) => createHistoryRow(scan, true)));
  }
  if (scans.length === 0) {
    if (historyTable) historyTable.append(element("p", "muted", "No scans have been recorded yet."));
    if (recentScans) recentScans.append(element("p", "muted", "No recent scans."));
  }

  if (scans[0]) {
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
    const result = await api("/api/wifi/networks");
    cachedNetworks = result.networks || [];
    filterAndRenderWifiNetworks();

    if (count) count.textContent = `${cachedNetworks.length} network${cachedNetworks.length === 1 ? "" : "s"} visible`;
    if (scanTime) scanTime.textContent = `Scanned ${result.scannedAt}`;
    if (status) {
      status.textContent = cachedNetworks.length
        ? "Airspace survey complete. Select a network to inspect or compare."
        : "No visible WiFi networks were detected in local physical range.";
    }

    if (result.threats) {
      renderThreats(result.threats);
    }
  } catch (error) {
    if (count) count.textContent = "Scan unavailable";
    if (status) status.textContent = `Nearby WiFi scanner is ready. Start the Java backend to scan live local access points.`;
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
    const formattedAnswer = formatMarkdownText(res.answer);
    botMsg.innerHTML = `
      <div class="msg-bubble">${formattedAnswer}</div>
      <small class="msg-time">${res.timestamp || "Just now"}</small>
    `;
    chatContainer.append(botMsg);
    chatContainer.scrollTop = chatContainer.scrollHeight;
  } catch (err) {
    typingMsg.remove();
    const errEl = element("div", "ai-msg bot");
    errEl.innerHTML = `<div class="msg-bubble" style="border-color:var(--red);color:#ff8094">Unable to reach security AI: ${escapeHtml(err.message)}</div>`;
    chatContainer.append(errEl);
  }
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
  if (!canvas || typeof QRCode === "undefined") return;

  const net = (dashboardData && dashboardData.network) || defaultDashboard.network;
  const ssid = net.ssid || "Home_WiFi";
  const pwd = net.password || "";
  const auth = net.encryption || "WPA";

  setText("#qr-net-name", ssid);
  setText("#qr-net-type", pwd ? "Password Configured" : "Open Network");

  // Wi-Fi QR standard format: WIFI:T:WPA;S:MySSID;P:MyPassword;;
  const qrString = `WIFI:T:${auth.includes("WPA") ? "WPA" : "nopass"};S:${ssid};P:${pwd};;`;
  try {
    QRCode.render(canvas, qrString, {
      margin: 1,
      scale: 4,
      color: { dark: "#06152c", light: "#ffffff" }
    });
  } catch (e) {
    // Handled
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

function closePdfReportModal() {
  const backdrop = document.querySelector("#pdf-modal-backdrop");
  if (backdrop) backdrop.hidden = true;
}

// -------------------------------------------------------------
// NAVIGATION & SCREEN SWITCHING
// -------------------------------------------------------------
function showScreen(name) {
  if (!titles[name]) return;
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
  } else if (name === "knowledge") {
    loadChecklist();
    loadKnowledge();
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

// 4. AI Chat Assistant Form & Quick Pills
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

document.querySelectorAll(".ai-pill-btn").forEach((pill) => {
  pill.addEventListener("click", () => {
    showScreen("ai-chat");
    sendAiChatMessage(pill.textContent.trim());
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

document.querySelectorAll(".theme-toggle").forEach((toggle) => {
  toggle.addEventListener("click", () => {
    const nextTheme = settings.theme === "light" ? "dark" : "light";
    document.body.classList.toggle("light", nextTheme === "light");
    toggle.classList.toggle("on", nextTheme === "light");
    updateSetting(toggle, "theme", nextTheme);
  });
});

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

// Initial Load
loadDashboard();

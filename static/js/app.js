/**
 * CyberShield – Wi-Fi Security Analyzer & Spectrum Auditor
 * Front-End Logic (Vanilla JavaScript ES6+)
 */

document.addEventListener("DOMContentLoaded", () => {
  // State Storage
  let scanResults = { networks: [], total_networks: 0, total_aps: 0, channels: {} };
  let currentConn = {};
  let savedProfiles = [];
  let isScanning = false;
  let expandedRows = new Set();

  // DOM Elements
  const btnScan = document.getElementById("btnScan");
  const btnScanLabel = document.getElementById("btnScanLabel");
  const btnExport = document.getElementById("btnExport");
  const liveStatusText = document.getElementById("liveStatusText");

  // Metrics Elements
  const airspaceHealth = document.getElementById("airspaceHealth");
  const airspaceProgress = document.getElementById("airspaceProgress");
  const airspaceBadge = document.getElementById("airspaceBadge");
  const currentSsidName = document.getElementById("currentSsidName");
  const currentCipher = document.getElementById("currentCipher");
  const currentGradeBadge = document.getElementById("currentGradeBadge");
  const currentLinkRate = document.getElementById("currentLinkRate");
  const criticalCount = document.getElementById("criticalCount");
  const highCount = document.getElementById("highCount");
  const warningCount = document.getElementById("warningCount");
  const safeCount = document.getElementById("safeCount");
  const totalApsCount = document.getElementById("totalApsCount");
  const interferingAps = document.getElementById("interferingAps");
  const congestionBadge = document.getElementById("congestionBadge");

  // Filter Elements
  const networkSearchInput = document.getElementById("networkSearchInput");
  const riskFilter = document.getElementById("riskFilter");
  const bandFilter = document.getElementById("bandFilter");
  const networksTableBody = document.getElementById("networksTableBody");

  // Modal Elements
  const networkModal = document.getElementById("networkModal");
  const modalCloseBtn = document.getElementById("modalCloseBtn");
  const modalDismissBtn = document.getElementById("modalDismissBtn");

  // Passphrase Lab Elements
  const passInput = document.getElementById("passInput");
  const togglePassBtn = document.getElementById("togglePassBtn");
  const entropyFill = document.getElementById("entropyFill");
  const passVerdictText = document.getElementById("passVerdictText");
  const passBitsText = document.getElementById("passBitsText");
  const statPassLength = document.getElementById("statPassLength");
  const statPoolSize = document.getElementById("statPoolSize");
  const statCrackTime = document.getElementById("statCrackTime");
  const passReqsList = document.getElementById("passReqsList");

  // ==========================================
  // TAB NAVIGATION
  // ==========================================
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add("active");
      }

      if (targetId === "tab-channels") {
        drawChannelCharts();
      }
    });
  });

  // ==========================================
  // DATA FETCHING & ORCHESTRATION
  // ==========================================
  async function performFullScan() {
    if (isScanning) return;
    isScanning = true;
    btnScan.disabled = true;
    btnScanLabel.textContent = "Scanning Spectrum...";
    liveStatusText.textContent = "Intercepting 802.11 Beacons...";

    networksTableBody.innerHTML = `
      <tr class="loading-row">
        <td colspan="7">
          <div class="scanner-loader">
            <div class="radar-spinner"></div>
            <span>Intercepting Wi-Fi 802.11 beacon frames across spectrum...</span>
          </div>
        </td>
      </tr>
    `;

    try {
      // Fetch spectrum scan, active connection, and saved profiles in parallel
      const [scanRes, connRes, profRes] = await Promise.all([
        fetch("/api/scan").then(r => r.json()).catch(err => ({ success: false, error: err.message })),
        fetch("/api/current").then(r => r.json()).catch(err => ({ success: false, error: err.message })),
        fetch("/api/profiles").then(r => r.json()).catch(err => ({ success: false, error: err.message }))
      ]);

      if (scanRes.success && scanRes.data) {
        scanResults = scanRes.data;
        updateAirspaceMetrics(scanResults);
        renderNetworksTable();
        drawChannelCharts();
        checkRogueAlerts(scanResults.rogue_alerts);
      } else {
        renderScanError(scanRes.error || "Failed to scan Wi-Fi airspace. Ensure WLAN service is active.");
      }

      if (connRes.success && connRes.data) {
        currentConn = connRes.data;
        updateActiveConnectionUI(currentConn);
        updateDiagnosticsUI(currentConn);
      }

      if (profRes.success && profRes.data) {
        savedProfiles = profRes.data;
        renderProfilesTable(savedProfiles);
      }

      liveStatusText.textContent = "WLAN Spectrum Monitored";
    } catch (err) {
      console.error("Scan error:", err);
      renderScanError(err.message);
      liveStatusText.textContent = "Scan Encountered Error";
    } finally {
      isScanning = false;
      btnScan.disabled = false;
      btnScanLabel.textContent = "Rescan Spectrum";
    }
  }

  function renderScanError(errorMsg) {
    networksTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center" style="padding: 3rem 1.5rem;">
          <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">⚠️</div>
          <div style="color: var(--accent-red); font-weight: 700; font-size: 1rem; margin-bottom: 0.35rem;">
            Wi-Fi Spectrum Scan Failed
          </div>
          <div style="color: var(--text-dim); font-size: 0.85rem; max-width: 500px; margin: 0 auto;">
            ${escapeHtml(errorMsg || "Windows WLAN AutoConfig service is stopped or Wi-Fi adapter is disabled.")}
          </div>
        </td>
      </tr>
    `;
  }

  // ==========================================
  // METRICS & ALERTS RENDERING
  // ==========================================
  function updateAirspaceMetrics(data) {
    const metrics = data.metrics || {};
    const score = metrics.airspace_health !== undefined ? metrics.airspace_health : 100;
    airspaceHealth.textContent = score;
    airspaceProgress.style.width = `${score}%`;

    if (score >= 80) {
      airspaceBadge.className = "badge badge-green";
      airspaceBadge.textContent = metrics.health_status || "Airspace Secure";
    } else if (score >= 60) {
      airspaceBadge.className = "badge badge-amber";
      airspaceBadge.textContent = metrics.health_status || "Airspace Moderate";
    } else {
      airspaceBadge.className = "badge badge-red";
      airspaceBadge.textContent = metrics.health_status || "Airspace Critical";
    }

    criticalCount.textContent = metrics.critical_count || 0;
    if (highCount) highCount.textContent = metrics.high_count || 0;
    warningCount.textContent = metrics.moderate_count !== undefined ? metrics.moderate_count : (metrics.warning_count || 0);
    safeCount.textContent = metrics.safe_count || 0;
    totalApsCount.textContent = `${data.total_aps || 0} Access Point(s) / ${data.total_networks || 0} SSID(s)`;

    // 2.4 GHz Channel Overlap & Congestion
    const interfering = data.channels?.interfering_aps_24 || 0;
    interferingAps.textContent = interfering;
    if (interfering === 0) {
      congestionBadge.className = "badge badge-green";
      congestionBadge.textContent = "Clean Spectrum";
    } else {
      congestionBadge.className = "badge badge-amber";
      congestionBadge.textContent = `${interfering} Overlapping APs`;
    }
  }

  function updateActiveConnectionUI(conn) {
    if (conn && conn.connected) {
      const wifi = conn.wifi || {};
      const sec = conn.security || {};
      const grade = sec.grade || "A";
      const risk = sec.risk_level || "LOW";

      currentSsidName.textContent = wifi.ssid || "Connected";
      currentCipher.textContent = `${wifi.authentication} • ${wifi.cipher}`;
      currentGradeBadge.textContent = `${grade} (${risk})`;
      currentGradeBadge.className = `active-grade-pill grade-${grade[0]}`;
      currentLinkRate.textContent = `Security: ${wifi.authentication} (${wifi.cipher}) • Signal: ${wifi.signal_percent}% • Link: Tx ${wifi.transmit_rate_mbps} Mbps / Rx ${wifi.receive_rate_mbps} Mbps`;
    } else {
      currentSsidName.textContent = "Disconnected";
      currentCipher.textContent = "No active connection";
      currentGradeBadge.textContent = "--";
      currentLinkRate.textContent = "Not connected to any wireless access point";
    }
  }

  function checkRogueAlerts(alerts) {
    const banner = document.getElementById("rogueAlertBanner");
    if (alerts && alerts.length > 0) {
      const first = alerts[0];
      document.getElementById("rogueAlertTitle").textContent = first.title;
      document.getElementById("rogueAlertDesc").textContent = first.description;
      banner.style.display = "flex";
    } else {
      banner.style.display = "none";
    }
  }

  // ==========================================
  // TABLE RENDERING, FILTERING & EXPANSION
  // ==========================================
  function renderNetworksTable() {
    const query = networkSearchInput.value.toLowerCase().trim();
    const risk = riskFilter.value;
    const band = bandFilter.value;

    let filtered = [];

    (scanResults.networks || []).forEach(net => {
      const sec = net.security || {};
      const riskLevel = sec.risk_level || "LOW";
      const grade = sec.grade || "A";

      // Filter by Risk
      if (risk === "critical" && riskLevel !== "CRITICAL") return;
      if (risk === "high" && riskLevel !== "HIGH") return;
      if (risk === "moderate" && riskLevel !== "MODERATE") return;
      if (risk === "safe" && riskLevel !== "LOW") return;

      net.bssids.forEach(b => {
        // Filter by Band
        if (band !== "all" && b.band !== band) return;

        // Filter by Search Query (SSID, BSSID, Vendor)
        const matchSsid = net.ssid.toLowerCase().includes(query);
        const matchBssid = b.bssid.toLowerCase().includes(query);
        const matchVendor = (b.vendor || "").toLowerCase().includes(query);

        if (!query || matchSsid || matchBssid || matchVendor) {
          filtered.push({ network: net, bssid: b });
        }
      });
    });

    if (filtered.length === 0) {
      const isScanEmpty = !scanResults.networks || scanResults.networks.length === 0;
      networksTableBody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center" style="padding: 3rem 1.5rem; color: var(--text-dim);">
            ${isScanEmpty ? `
              <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">📡</div>
              <div style="font-weight: 600; color: #fff; margin-bottom: 0.25rem;">No Wireless Networks Detected</div>
              <div style="font-size: 0.85rem;">No Wi-Fi access points are within range or Wi-Fi adapter is turned off.</div>
            ` : `
              No access points matching the current filter criteria.
            `}
          </td>
        </tr>
      `;
      return;
    }

    // Sort by signal strength descending
    filtered.sort((a, b) => b.bssid.signal_percent - a.bssid.signal_percent);

    let html = "";
    filtered.forEach(({ network, bssid }, index) => {
      const rowId = `net-row-${index}`;
      const sec = network.security || {};
      const grade = sec.grade || "A";
      const gradeClass = grade.startsWith("A") ? "grade-A" : grade === "B" ? "grade-B" : grade === "C" ? "grade-C" : grade === "D" ? "grade-D" : "grade-F";
      const riskLevel = sec.risk_level || "LOW";
      const score = sec.score !== undefined ? sec.score : 85;

      const sig = bssid.signal_percent || 0;
      const sigDbm = bssid.signal_dbm !== undefined ? bssid.signal_dbm : Math.round((sig / 2) - 100);
      const sigClass = sig >= 70 ? "active-green" : sig >= 40 ? "active-amber" : "active-red";
      const barsActive = sig >= 75 ? 4 : sig >= 50 ? 3 : sig >= 25 ? 2 : 1;
      const isExpanded = expandedRows.has(bssid.bssid);

      html += `
        <tr class="network-row ${isExpanded ? 'row-expanded' : ''}" data-bssid="${bssid.bssid}" data-target="${rowId}">
          <td>
            <div class="network-name-col">
              <span class="network-ssid">${escapeHtml(network.ssid)}</span>
              ${network.is_hidden ? '<span class="badge badge-amber" style="font-size: 0.65rem; width: fit-content; margin-top: 0.2rem;">Hidden SSID</span>' : ''}
            </div>
          </td>
          <td>
            <div class="network-bssid-col">
              <span class="bssid-mac">${bssid.bssid}</span>
              <span class="vendor-tag">${escapeHtml(bssid.vendor || 'Generic')}</span>
            </div>
          </td>
          <td>
            <div class="signal-cell">
              <div class="signal-bars">
                <div class="signal-bar ${barsActive >= 1 ? sigClass : ''}"></div>
                <div class="signal-bar ${barsActive >= 2 ? sigClass : ''}"></div>
                <div class="signal-bar ${barsActive >= 3 ? sigClass : ''}"></div>
                <div class="signal-bar ${barsActive >= 4 ? sigClass : ''}"></div>
              </div>
              <span class="font-mono">${sig}%</span>
              <span style="font-size: 0.72rem; color: var(--text-dim);">(${sigDbm} dBm)</span>
            </div>
          </td>
          <td>
            <span class="font-mono">Ch ${bssid.channel}</span>
            <span style="color: var(--text-dim); font-size: 0.75rem;">(${bssid.band})</span>
          </td>
          <td>
            <span style="font-weight: 600;">${network.authentication}</span>
            <div class="font-mono" style="font-size: 0.75rem; color: var(--accent-cyan);">${network.encryption}</div>
          </td>
          <td>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <span class="grade-badge-round ${gradeClass}">${grade}</span>
              <div>
                <div style="font-size: 0.75rem; font-weight: 700; color: ${riskLevel === 'CRITICAL' ? 'var(--accent-red)' : riskLevel === 'HIGH' ? '#f97316' : riskLevel === 'MODERATE' ? 'var(--accent-amber)' : 'var(--accent-green)'};">
                  ${riskLevel}
                </div>
                <div style="font-size: 0.68rem; color: var(--text-dim); font-family: var(--font-mono);">${score}/100</div>
              </div>
            </div>
          </td>
          <td>
            <div style="display: flex; gap: 0.4rem;">
              <button class="btn btn-secondary btn-toggle-details" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" data-bssid="${bssid.bssid}">
                ${isExpanded ? 'Details ▴' : 'Details ▾'}
              </button>
              <button class="btn btn-secondary btn-inspect" style="padding: 0.35rem 0.65rem; font-size: 0.75rem;" data-ssid="${escapeHtml(network.ssid)}" data-bssid="${bssid.bssid}">
                Inspect
              </button>
            </div>
          </td>
        </tr>

        <!-- Expandable Details Row (All 11 required analysis parameters) -->
        <tr class="expandable-details-row" id="${rowId}" style="display: ${isExpanded ? 'table-row' : 'none'};">
          <td colspan="7">
            <div class="network-drawer-grid">
              <div class="drawer-item">
                <span class="drawer-label">1. Network (SSID)</span>
                <span class="drawer-val">${escapeHtml(network.ssid)}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">2. Hardware BSSID</span>
                <span class="drawer-val font-mono">${bssid.bssid}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">3. Signal Strength</span>
                <span class="drawer-val font-mono">${sig}% (${sigDbm} dBm)</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">4. Frequency / Band</span>
                <span class="drawer-val font-mono">${bssid.band}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">5. Operating Channel</span>
                <span class="drawer-val font-mono">Channel ${bssid.channel}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">6. Authentication Suite</span>
                <span class="drawer-val">${network.authentication}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">7. Encryption Cipher</span>
                <span class="drawer-val font-mono cyan-text">${network.encryption}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">8. Risk Level</span>
                <span class="drawer-val" style="color: ${riskLevel === 'CRITICAL' ? 'var(--accent-red)' : riskLevel === 'HIGH' ? '#f97316' : riskLevel === 'MODERATE' ? 'var(--accent-amber)' : 'var(--accent-green)'};">
                  ${riskLevel} RISK (Grade ${grade})
                </span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">9. Security Score</span>
                <span class="drawer-val font-mono cyan-text">${score} / 100</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">Hardware Vendor</span>
                <span class="drawer-val">${escapeHtml(bssid.vendor || 'Generic')}</span>
              </div>

              <!-- 10. Security Posture Explanation -->
              <div class="drawer-full">
                <span class="drawer-label" style="color: var(--accent-cyan); margin-bottom: 0.35rem; display: block;">10. CyberShield Security Explanation</span>
                <div style="font-size: 0.85rem; line-height: 1.55; color: var(--text-main);">
                  ${escapeHtml(sec.explanation || 'Analyzed via CyberShield Project Security Engine.')}
                </div>
              </div>

              <!-- 11. Security Recommendation -->
              <div class="drawer-rec">
                <span class="drawer-label" style="color: var(--accent-green); margin-bottom: 0.35rem; display: block;">11. Security Recommendation</span>
                <div style="font-size: 0.85rem; font-weight: 600; line-height: 1.55; color: var(--accent-green);">
                  ${escapeHtml(sec.recommendation || 'Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication.')}
                </div>
              </div>
            </div>
          </td>
        </tr>
      `;
    });

    networksTableBody.innerHTML = html;

    // Attach Toggle Details listeners
    document.querySelectorAll(".btn-toggle-details").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const bssidMac = btn.getAttribute("data-bssid");
        if (expandedRows.has(bssidMac)) {
          expandedRows.delete(bssidMac);
        } else {
          expandedRows.add(bssidMac);
        }
        renderNetworksTable();
      });
    });

    // Attach Inspect modal listeners
    document.querySelectorAll(".btn-inspect").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const ssid = btn.getAttribute("data-ssid");
        const bssid = btn.getAttribute("data-bssid");
        openNetworkModal(ssid, bssid);
      });
    });
  }

  // Filter event listeners
  networkSearchInput.addEventListener("input", renderNetworksTable);
  riskFilter.addEventListener("change", renderNetworksTable);
  bandFilter.addEventListener("change", renderNetworksTable);

  // ==========================================
  // NETWORK MODAL INSPECTOR
  // ==========================================
  function openNetworkModal(ssid, bssidMac) {
    const net = (scanResults.networks || []).find(n => n.ssid === ssid);
    if (!net) return;
    const bssidObj = net.bssids.find(b => b.bssid === bssidMac) || net.bssids[0] || {};
    const sec = net.security || {};

    const grade = sec.grade || "A";
    const modalGrade = document.getElementById("modalGrade");
    modalGrade.textContent = grade;
    modalGrade.className = `modal-badge-grade grade-${grade[0]}`;

    document.getElementById("modalSsid").textContent = net.ssid;
    document.getElementById("modalBssid").textContent = `${bssidObj.bssid || 'N/A'} • ${bssidObj.vendor || 'Unknown Vendor'}`;

    // Populate all 11 required parameters
    const detailSsid = document.getElementById("modalDetailSsid");
    if (detailSsid) detailSsid.textContent = net.ssid;
    const detailBssid = document.getElementById("modalDetailBssid");
    if (detailBssid) detailBssid.textContent = bssidObj.bssid || "N/A";

    const sig = bssidObj.signal_percent || 0;
    const sigDbm = bssidObj.signal_dbm !== undefined ? bssidObj.signal_dbm : Math.round((sig / 2) - 100);
    document.getElementById("modalSignal").textContent = `${sig}% (~${sigDbm} dBm)`;

    document.getElementById("modalChannel").textContent = `Channel ${bssidObj.channel || 'N/A'}`;
    const modalBand = document.getElementById("modalBand");
    if (modalBand) modalBand.textContent = bssidObj.band || "Unknown Band";

    document.getElementById("modalAuth").textContent = net.authentication;
    document.getElementById("modalCipher").textContent = net.encryption;

    const modalRisk = document.getElementById("modalRisk");
    if (modalRisk) modalRisk.textContent = `${sec.risk_level || 'LOW'} RISK`;

    const modalScore = document.getElementById("modalScore");
    if (modalScore) modalScore.textContent = `${sec.score !== undefined ? sec.score : 85} / 100`;

    document.getElementById("modalVendor").textContent = bssidObj.vendor || "Generic Hardware";

    const modalExplanation = document.getElementById("modalExplanation");
    if (modalExplanation) {
      modalExplanation.textContent = sec.explanation || "Evaluated using the CyberShield Project-Defined Risk Assessment Model.";
    }

    const modalRecommendation = document.getElementById("modalRecommendation");
    if (modalRecommendation) {
      modalRecommendation.textContent = sec.recommendation || "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication.";
    }

    // Render Recommendations List
    const modalRecList = document.getElementById("modalRecList");
    if (sec.recommendations && sec.recommendations.length > 0) {
      modalRecList.innerHTML = sec.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join("");
    } else {
      modalRecList.innerHTML = `<li>Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication.</li><li>Keep router firmware updated with latest security patches.</li>`;
    }

    // Render Vulnerabilities List
    const modalVulnList = document.getElementById("modalVulnList");
    if (sec.vulnerabilities && sec.vulnerabilities.length > 0) {
      modalVulnList.innerHTML = sec.vulnerabilities.map(v => `
        <div class="vuln-card">
          <div class="vuln-title">[${v.severity}] ${escapeHtml(v.title)}</div>
          <div class="vuln-cwe">${escapeHtml(v.cwe || '')}</div>
          <div class="vuln-desc">${escapeHtml(v.description)}</div>
          <div class="vuln-desc" style="margin-top: 0.35rem; color: #fca5a5;"><strong>Impact:</strong> ${escapeHtml(v.impact)}</div>
        </div>
      `).join("");
    } else {
      modalVulnList.innerHTML = `<div class="vuln-empty">✓ No critical protocol vulnerabilities detected. Solid cryptographic configuration.</div>`;
    }

    networkModal.style.display = "flex";
  }

  function closeModal() {
    networkModal.style.display = "none";
  }

  modalCloseBtn.addEventListener("click", closeModal);
  modalDismissBtn.addEventListener("click", closeModal);
  networkModal.addEventListener("click", (e) => {
    if (e.target === networkModal) closeModal();
  });

  // ==========================================
  // SPECTRUM CANVAS CHARTS
  // ==========================================
  function drawChannelCharts() {
    draw24GHzChart();
    draw5GHzChart();
  }

  function draw24GHzChart() {
    const canvas = document.getElementById("channelChart24");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();

    canvas.width = rect.width * dpr;
    canvas.height = 240 * dpr;
    ctx.scale(dpr, dpr);

    const width = rect.width;
    const height = 240;

    ctx.clearRect(0, 0, width, height);

    // Grid baseline
    ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(30, height - 35);
    ctx.lineTo(width - 20, height - 35);
    ctx.stroke();

    const channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    const usableWidth = width - 70;
    const step = usableWidth / (channels.length - 1);

    // Channel tick labels
    ctx.font = "11px Outfit, sans-serif";
    ctx.textAlign = "center";

    channels.forEach((ch, idx) => {
      const x = 40 + (idx * step);
      const isClean = [1, 6, 11].includes(ch);

      if (isClean) {
        ctx.fillStyle = "#05df72";
        ctx.fillText(`CH ${ch}*`, x, height - 15);
      } else {
        ctx.fillStyle = "#64748b";
        ctx.fillText(`CH ${ch}`, x, height - 15);
      }

      // Vertical guideline
      ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
      ctx.beginPath();
      ctx.moveTo(x, 20);
      ctx.lineTo(x, height - 35);
      ctx.stroke();
    });

    // Plot curves for detected APs
    (scanResults.networks || []).forEach(net => {
      net.bssids.forEach(b => {
        if (b.band === "2.4 GHz" && b.channel >= 1 && b.channel <= 14) {
          const chIndex = channels.indexOf(b.channel);
          if (chIndex !== -1) {
            const centerX = 40 + (chIndex * step);
            const peakHeight = Math.max(30, (b.signal_percent / 100) * (height - 80));
            const curveWidth = step * 2.2;

            ctx.save();
            ctx.beginPath();
            ctx.moveTo(centerX - curveWidth, height - 35);
            ctx.quadraticCurveTo(centerX, height - 35 - peakHeight, centerX + curveWidth, height - 35);

            const isStandard = [1, 6, 11].includes(b.channel);
            const strokeColor = isStandard ? "rgba(5, 223, 114, 0.85)" : "rgba(245, 158, 11, 0.85)";
            const fillColor = isStandard ? "rgba(5, 223, 114, 0.12)" : "rgba(245, 158, 11, 0.12)";

            ctx.fillStyle = fillColor;
            ctx.fill();
            ctx.strokeStyle = strokeColor;
            ctx.lineWidth = 2;
            ctx.stroke();

            // AP Label
            ctx.fillStyle = "#ffffff";
            ctx.font = "bold 10px JetBrains Mono, monospace";
            ctx.fillText(net.ssid.substring(0, 14), centerX, height - 42 - peakHeight);
            ctx.restore();
          }
        }
      });
    });
  }

  function draw5GHzChart() {
    const canvas = document.getElementById("channelChart5");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();

    canvas.width = rect.width * dpr;
    canvas.height = 180 * dpr;
    ctx.scale(dpr, dpr);

    const width = rect.width;
    const height = 180;

    ctx.clearRect(0, 0, width, height);

    ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(30, height - 30);
    ctx.lineTo(width - 20, height - 30);
    ctx.stroke();

    const channels5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 149, 153, 157, 161, 165];
    const usableWidth = width - 70;
    const step = usableWidth / (channels5.length - 1);

    ctx.fillStyle = "#64748b";
    ctx.font = "10px Outfit, sans-serif";
    ctx.textAlign = "center";

    channels5.forEach((ch, idx) => {
      const x = 40 + (idx * step);
      ctx.fillText(`${ch}`, x, height - 12);
    });

    let count5 = 0;
    (scanResults.networks || []).forEach(net => {
      net.bssids.forEach(b => {
        if (b.band === "5 GHz") {
          count5++;
          const chIndex = channels5.indexOf(b.channel);
          if (chIndex !== -1) {
            const centerX = 40 + (chIndex * step);
            const peakHeight = Math.max(25, (b.signal_percent / 100) * (height - 65));

            ctx.save();
            ctx.beginPath();
            ctx.moveTo(centerX - 20, height - 30);
            ctx.quadraticCurveTo(centerX, height - 30 - peakHeight, centerX + 20, height - 30);

            ctx.fillStyle = "rgba(0, 242, 254, 0.15)";
            ctx.fill();
            ctx.strokeStyle = "rgba(0, 242, 254, 0.85)";
            ctx.lineWidth = 2;
            ctx.stroke();

            ctx.fillStyle = "#ffffff";
            ctx.font = "bold 9px JetBrains Mono, monospace";
            ctx.fillText(net.ssid.substring(0, 12), centerX, height - 36 - peakHeight);
            ctx.restore();
          }
        }
      });
    });

    if (count5 === 0) {
      ctx.fillStyle = "#64748b";
      ctx.font = "12px Outfit, sans-serif";
      ctx.fillText("No active 5 GHz APs in current range", width / 2, height / 2);
    }
  }

  // ==========================================
  // TAB 3: CONNECTED DEEP DIAGNOSTICS UI
  // ==========================================
  function updateDiagnosticsUI(conn) {
    if (!conn || !conn.connected) {
      document.getElementById("diagConnState").textContent = "Disconnected";
      document.getElementById("diagConnState").className = "diag-tag tag-cyan";
      return;
    }

    const w = conn.wifi || {};
    const ad = conn.adapter || {};
    const dr = conn.driver || {};
    const gw = conn.gateway || {};
    const dns = conn.dns || {};

    document.getElementById("diagConnState").textContent = "Connected & Active";
    document.getElementById("diagAdapterName").textContent = w.name || "Wi-Fi Adapter";
    document.getElementById("diagSsid").textContent = w.ssid || "--";
    document.getElementById("diagBssid").textContent = `${w.bssid} (${w.vendor})`;
    document.getElementById("diagRadio").textContent = w.radio_type || "802.11n";
    document.getElementById("diagChannel").textContent = `Channel ${w.channel}`;
    document.getElementById("diagRates").textContent = `Tx: ${w.transmit_rate_mbps} Mbps / Rx: ${w.receive_rate_mbps} Mbps`;

    document.getElementById("diagIp").textContent = ad.ip_address || "N/A";
    document.getElementById("diagMask").textContent = ad.subnet_mask || "N/A";
    document.getElementById("diagGateway").textContent = ad.default_gateway || "N/A";
    document.getElementById("diagPing").textContent = gw.reachable ? `${gw.latency_ms} ms` : "Unreachable";
    document.getElementById("diagDhcp").textContent = ad.dhcp_enabled ? "DHCP Auto-Assigned" : "Static Configuration";

    document.getElementById("diagAuth").textContent = w.authentication || "--";
    document.getElementById("diagCipher").textContent = w.cipher || "--";
    document.getElementById("diagDnsList").textContent = (dns.servers && dns.servers.length) ? dns.servers.join(", ") : "Default Router DNS";

    const dnsTag = document.getElementById("diagDnsSecurityTag");
    if (dns.has_secure_dns) {
      dnsTag.className = "diag-tag";
      dnsTag.textContent = "Secure DNS Resolvers";
      document.getElementById("diagDnsAssessment").textContent = "Encrypted / Public high-reputation DNS configured.";
    } else {
      dnsTag.className = "diag-tag tag-cyan";
      dnsTag.textContent = "Standard ISP DNS";
      document.getElementById("diagDnsAssessment").textContent = "Standard unencrypted queries (potential ISP logging).";
    }

    document.getElementById("diagPmf").textContent = dr.pmf_supported ? "✓ Supported (802.11w)" : "✗ Not Supported";
    document.getElementById("diagFips").textContent = dr.fips_supported ? "✓ Certified (FIPS 140-2)" : "✗ Not Enabled";
  }

  // ==========================================
  // TAB 4: SAVED PROFILES UI
  // ==========================================
  function renderProfilesTable(profiles) {
    const tbody = document.getElementById("profilesTableBody");
    if (!profiles || profiles.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="padding: 2rem;">No saved Wi-Fi profiles found.</td></tr>`;
      return;
    }

    tbody.innerHTML = profiles.map(p => {
      const isCritical = p.security_risk === "CRITICAL";
      const isHigh = p.security_risk === "HIGH";
      const riskClass = isCritical ? "badge badge-red" : isHigh ? "badge badge-amber" : "badge badge-green";
      const autoClass = (p.auto_connect && isCritical) ? "red-text font-bold" : "";

      return `
        <tr>
          <td><strong class="font-mono">${escapeHtml(p.name)}</strong></td>
          <td class="${autoClass}">${p.auto_connect ? '⚡ Enabled' : 'Disabled'}</td>
          <td>${escapeHtml(p.authentication)}</td>
          <td><span class="font-mono">${escapeHtml(p.cipher)}</span></td>
          <td>${escapeHtml(p.mac_randomization)}</td>
          <td>
            <span class="${riskClass}">${p.security_risk}</span>
            ${p.flags && p.flags.length > 0 ? `<div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.25rem;">${escapeHtml(p.flags[0])}</div>` : ''}
          </td>
        </tr>
      `;
    }).join("");
  }

  // ==========================================
  // TAB 5: PASSPHRASE ENTROPY LAB
  // ==========================================
  let passDebounceTimer = null;

  passInput.addEventListener("input", () => {
    clearTimeout(passDebounceTimer);
    passDebounceTimer = setTimeout(checkPasswordStrength, 180);
  });

  togglePassBtn.addEventListener("click", () => {
    if (passInput.type === "password") {
      passInput.type = "text";
      togglePassBtn.textContent = "🔒";
    } else {
      passInput.type = "password";
      togglePassBtn.textContent = "👁️";
    }
  });

  async function checkPasswordStrength() {
    const pwd = passInput.value;
    if (!pwd) {
      entropyFill.style.width = "0%";
      passVerdictText.textContent = "Waiting for input...";
      passBitsText.textContent = "0.0 bits entropy";
      statPassLength.textContent = "0 chars";
      statPoolSize.textContent = "0";
      statCrackTime.textContent = "Instant";
      passReqsList.innerHTML = "";
      return;
    }

    try {
      const res = await fetch("/api/check-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pwd })
      });
      const json = await res.json();
      if (json.success) {
        renderPasswordResult(json.data);
      }
    } catch (err) {
      console.error(err);
    }
  }

  function renderPasswordResult(data) {
    const score = data.score || 0;
    entropyFill.style.width = `${Math.min(100, Math.max(5, score))}%`;

    if (score >= 85) {
      entropyFill.style.background = "var(--accent-green)";
    } else if (score >= 50) {
      entropyFill.style.background = "var(--accent-amber)";
    } else {
      entropyFill.style.background = "var(--accent-red)";
    }

    passVerdictText.textContent = data.verdict;
    passBitsText.textContent = `${data.entropy_bits} bits entropy`;

    statPassLength.textContent = `${data.length} characters`;
    statPoolSize.textContent = `${data.pool_size} chars pool`;
    statCrackTime.textContent = data.crack_time_estimate;

    passReqsList.innerHTML = `
      <div style="display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 1rem; font-size: 0.8rem;">
        <span class="${data.length >= 12 ? 'green-text' : 'red-text'}">${data.length >= 12 ? '✓' : '✗'} 12+ Characters</span>
        <span class="${data.has_upper ? 'green-text' : 'red-text'}">${data.has_upper ? '✓' : '✗'} Uppercase (A-Z)</span>
        <span class="${data.has_lower ? 'green-text' : 'red-text'}">${data.has_lower ? '✓' : '✗'} Lowercase (a-z)</span>
        <span class="${data.has_digits ? 'green-text' : 'red-text'}">${data.has_digits ? '✓' : '✗'} Numbers (0-9)</span>
        <span class="${data.has_special ? 'green-text' : 'red-text'}">${data.has_special ? '✓' : '✗'} Symbols (!@#$)</span>
      </div>
    `;
  }

  // ==========================================
  // ACTIONS: EXPORT & RESCAN
  // ==========================================
  btnScan.addEventListener("click", performFullScan);
  btnExport.addEventListener("click", () => {
    window.location.href = "/api/export-report";
  });

  // Helpers
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Initial Scan Execution
  performFullScan();

  // Redraw charts on window resize
  window.addEventListener("resize", () => {
    const activeTab = document.querySelector(".tab-btn.active");
    if (activeTab && activeTab.getAttribute("data-tab") === "tab-channels") {
      drawChannelCharts();
    }
  });
});

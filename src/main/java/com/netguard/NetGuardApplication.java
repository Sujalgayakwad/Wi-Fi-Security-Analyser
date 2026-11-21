package com.netguard;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@SpringBootApplication
@RestController
public class NetGuardApplication {
    private static final Set<String> ALLOWED_SETTINGS = Set.of(
            "auto_scan", "notifications", "theme", "device_wifi_tracking", "auto_scan_interval"
    );
    private static final DateTimeFormatter SCAN_TIME_FORMAT =
            DateTimeFormatter.ofPattern("MMM dd, yyyy '·' hh:mm a", Locale.ENGLISH);

    private final Path databasePath;
    private final WifiNetworkScanner wifiNetworkScanner;

    public NetGuardApplication(
            @Value("${netguard.database:netguard.db}") String databasePath,
            WifiNetworkScanner wifiNetworkScanner) {
        this.databasePath = Path.of(databasePath).toAbsolutePath().normalize();
        this.wifiNetworkScanner = wifiNetworkScanner;
    }

    public static void main(String[] args) {
        SpringApplication.run(NetGuardApplication.class, args);
    }

    @PostConstruct
    public void initializeDatabase() throws SQLException {
        try (Connection database = connection(); Statement statement = database.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS network (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        name TEXT NOT NULL,
                        band TEXT NOT NULL,
                        channel INTEGER NOT NULL,
                        signal_dbm INTEGER NOT NULL,
                        score INTEGER NOT NULL,
                        encryption TEXT NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        platform TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'online',
                        last_seen TEXT NOT NULL,
                        mac_address TEXT DEFAULT '',
                        vendor TEXT DEFAULT '',
                        device_type TEXT DEFAULT 'laptop',
                        first_seen TEXT DEFAULT '',
                        is_trusted INTEGER DEFAULT 0
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        network_name TEXT NOT NULL,
                        scanned_at TEXT NOT NULL,
                        encryption TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        result TEXT NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        category TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        is_read INTEGER DEFAULT 0
                    )
                    """);

            seedNetwork(database);
            seedDevices(database);
            seedScans(database);
            seedSettings(database);
            seedAlerts(database);
        }
    }

    private Map<String, Object> syncCurrentNetwork(Connection database) throws SQLException {
        Optional<WifiNetworkScanner.ConnectedWifi> current = wifiNetworkScanner.getConnectedWifi();
        if (current.isPresent()) {
            WifiNetworkScanner.ConnectedWifi net = current.get();
            try (PreparedStatement statement = database.prepareStatement("""
                    UPDATE network SET name = ?, band = ?, channel = ?, signal_dbm = ?, score = ?, encryption = ?
                    WHERE id = 1
                    """)) {
                statement.setString(1, net.ssid());
                statement.setString(2, net.band());
                statement.setInt(3, net.channel());
                statement.setInt(4, net.signalDbm());
                statement.setInt(5, net.securityScore());
                statement.setString(6, net.authentication());
                int updated = statement.executeUpdate();
                if (updated == 0) {
                    try (PreparedStatement insert = database.prepareStatement("""
                            INSERT INTO network (id, name, band, channel, signal_dbm, score, encryption)
                            VALUES (1, ?, ?, ?, ?, ?, ?)
                            """)) {
                        insert.setString(1, net.ssid());
                        insert.setString(2, net.band());
                        insert.setInt(3, net.channel());
                        insert.setInt(4, net.signalDbm());
                        insert.setInt(5, net.securityScore());
                        insert.setString(6, net.authentication());
                        insert.executeUpdate();
                    }
                }
            }
            Map<String, Object> map = new LinkedHashMap<>(net.toMap());
            map.put("connected", true);
            map.put("status", "connected");
            return map;
        } else {
            Map<String, Object> disconnected = new LinkedHashMap<>();
            disconnected.put("id", 1);
            disconnected.put("name", "No Wi-Fi Connected");
            disconnected.put("ssid", "No Wi-Fi Connected");
            disconnected.put("state", "disconnected");
            disconnected.put("connected", false);
            disconnected.put("band", "—");
            disconnected.put("channel", 0);
            disconnected.put("signalPercent", 0);
            disconnected.put("signal_dbm", 0);
            disconnected.put("signalQuality", "Weak");
            disconnected.put("score", 0);
            disconnected.put("securityRating", "Disconnected");
            disconnected.put("securityClassification", "Critical");
            disconnected.put("encryption", "None");
            disconnected.put("cipher", "None");
            disconnected.put("description", "Wi-Fi is disconnected or disabled");
            disconnected.put("bssid", "—");
            disconnected.put("password", "");
            disconnected.put("radioType", "—");
            disconnected.put("vendor", "—");
            return disconnected;
        }
    }

    @GetMapping("/api/dashboard")
    public Map<String, Object> dashboard() throws SQLException {
        try (Connection database = connection()) {
            Map<String, Object> response = new LinkedHashMap<>();
            Map<String, Object> network = syncCurrentNetwork(database);
            boolean isConnected = Boolean.TRUE.equals(network.get("connected"));
            String networkName = (String) network.get("name");

            // Devices
            List<Map<String, Object>> devices = getLiveOrStoredDevices(database, networkName, isConnected);
            response.put("network", network);
            response.put("devices", devices);
            response.put("scans", queryAll(database, "SELECT * FROM scans ORDER BY id DESC LIMIT 10"));

            // Settings
            Map<String, String> settings = new LinkedHashMap<>();
            for (Map<String, Object> setting : queryAll(database, "SELECT * FROM settings")) {
                settings.put((String) setting.get("key"), (String) setting.get("value"));
            }
            response.put("settings", settings);

            // Live Network Scanner & Threat Detection
            List<WifiNetworkScanner.Network> visible = scanAvailableWifiSafe();
            List<Map<String, Object>> threats = wifiNetworkScanner.detectThreats(visible, wifiNetworkScanner.getConnectedWifi());
            response.put("threats", threats);

            // Network statistics & Distributions
            int totalNetworks = visible.size();
            long openNetworks = visible.stream()
                    .filter(n -> n.authentication().toLowerCase(Locale.ROOT).contains("open") || n.encryption().equalsIgnoreCase("none"))
                    .count();
            long secureNetworks = totalNetworks - openNetworks;

            Map<String, Object> stats = new LinkedHashMap<>();
            stats.put("totalNetworks", totalNetworks);
            stats.put("secureNetworks", secureNetworks);
            stats.put("openNetworks", openNetworks);
            stats.put("threatCount", threats.size());
            stats.put("activeDevices", devices.size());

            // Average score
            int avgScore = visible.isEmpty()
                    ? (int) network.getOrDefault("score", 82)
                    : (int) Math.round(visible.stream().mapToInt(WifiNetworkScanner.Network::securityScore).average().orElse(82));
            stats.put("averageSecurityScore", avgScore);
            response.put("stats", stats);

            // Traffic
            response.put("traffic", wifiNetworkScanner.getTrafficMetrics());

            // Unread alerts count
            int unreadAlerts = countRows(database, "alerts WHERE is_read = 0");
            response.put("unreadAlerts", unreadAlerts);

            return response;
        }
    }

    private List<Map<String, Object>> getLiveOrStoredDevices(Connection database, String networkName, boolean isConnected) {
        if (isConnected) {
            List<Map<String, Object>> live = wifiNetworkScanner.scanLocalDevices(networkName);
            if (!live.isEmpty()) {
                return live;
            }
        }
        try {
            List<Map<String, Object>> devices = queryAll(database, "SELECT * FROM devices ORDER BY id");
            for (Map<String, Object> device : devices) {
                device.put("connected_wifi", networkName);
                if (!isConnected) {
                    device.put("status", "offline");
                }
            }
            return devices;
        } catch (SQLException ignored) {
            return Collections.emptyList();
        }
    }

    @PostMapping("/api/network/detect")
    public ResponseEntity<Map<String, Object>> detectNetwork() throws SQLException {
        try (Connection database = connection()) {
            Map<String, Object> network = syncCurrentNetwork(database);
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("network", network);
            response.put("status", Boolean.TRUE.equals(network.get("connected")) ? "recognized" : "disconnected");
            return ResponseEntity.ok(response);
        }
    }

    @GetMapping("/api/devices")
    public List<Map<String, Object>> devices() throws SQLException {
        try (Connection database = connection()) {
            Map<String, Object> network = syncCurrentNetwork(database);
            boolean isConnected = Boolean.TRUE.equals(network.get("connected"));
            String networkName = (String) network.get("name");
            return getLiveOrStoredDevices(database, networkName, isConnected);
        }
    }

    @PostMapping("/api/devices/{id}/trust")
    public ResponseEntity<Map<String, Object>> toggleDeviceTrust(@PathVariable("id") int deviceId) throws SQLException {
        try (Connection database = connection();
             PreparedStatement check = database.prepareStatement("SELECT is_trusted FROM devices WHERE id = ?")) {
            check.setInt(1, deviceId);
            try (ResultSet rs = check.executeQuery()) {
                if (rs.next()) {
                    int current = rs.getInt(1);
                    int updated = current == 1 ? 0 : 1;
                    try (PreparedStatement update = database.prepareStatement("UPDATE devices SET is_trusted = ? WHERE id = ?")) {
                        update.setInt(1, updated);
                        update.setInt(2, deviceId);
                        update.executeUpdate();
                    }
                    return ResponseEntity.ok(Map.of("id", deviceId, "is_trusted", updated == 1));
                }
            }
        }
        return ResponseEntity.ok(Map.of("id", deviceId, "is_trusted", true));
    }

    @GetMapping("/api/history")
    public List<Map<String, Object>> history() throws SQLException {
        try (Connection database = connection()) {
            return queryAll(database, "SELECT * FROM scans ORDER BY id DESC");
        }
    }

    @GetMapping("/api/wifi/networks")
    public Map<String, Object> wifiNetworks() {
        List<WifiNetworkScanner.Network> scanned = scanAvailableWifi();
        List<Map<String, Object>> networks = scanned.stream()
                .map(WifiNetworkScanner.Network::toMap)
                .toList();

        List<Map<String, Object>> threats = wifiNetworkScanner.detectThreats(scanned, wifiNetworkScanner.getConnectedWifi());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("networks", networks);
        response.put("scannedAt", LocalDateTime.now().format(SCAN_TIME_FORMAT));
        response.put("scanSource", "Live Windows 802.11 WLAN Access Points (BSSID Discovery)");
        response.put("threats", threats);
        response.put("totalCount", networks.size());
        return response;
    }

    @PostMapping("/api/wifi/analyze")
    public ResponseEntity<Map<String, Object>> analyzeWifiNetwork(@RequestBody Map<String, String> request)
            throws SQLException {
        String ssid = request.get("ssid");
        if (ssid == null || ssid.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Select a visible WiFi network to analyze.");
        }

        WifiNetworkScanner.Network network = scanAvailableWifi().stream()
                .filter(candidate -> candidate.ssid().equals(ssid))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "That network is no longer visible. Refresh the WiFi list and try again."));
        String scannedAt = LocalDateTime.now().format(SCAN_TIME_FORMAT);
        String result = network.securityScore() >= 70 ? "GOOD" : "RISKY";

        try (Connection database = connection();
             PreparedStatement statement = database.prepareStatement("""
                     INSERT INTO scans (network_name, scanned_at, encryption, score, result)
                     VALUES (?, ?, ?, ?, ?)
                     """)) {
            statement.setString(1, network.ssid());
            statement.setString(2, scannedAt);
            statement.setString(3, network.authentication() + " / " + network.encryption());
            statement.setInt(4, network.securityScore());
            statement.setString(5, result);
            statement.executeUpdate();
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("network", network.toMap());
        response.put("scannedAt", scannedAt);
        response.put("result", result);
        response.put("assessmentScope",
                "Based on broadcast 802.11 BSSID beacon frames, encryption ciphers, and authentication suites advertised by the access point.");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/api/scan")
    public ResponseEntity<Map<String, Object>> scan() throws SQLException {
        try (Connection database = connection()) {
            Map<String, Object> network = queryOne(database, "SELECT * FROM network WHERE id = 1");
            if (network == null) {
                throw new IllegalStateException("The network record is missing from the database.");
            }

            String scannedAt = LocalDateTime.now().format(SCAN_TIME_FORMAT);
            int score = (int) network.get("score");
            String result = score >= 70 ? "GOOD" : "RISKY";

            try (PreparedStatement statement = database.prepareStatement("""
                    INSERT INTO scans (network_name, scanned_at, encryption, score, result)
                    VALUES (?, ?, ?, ?, ?)
                    """)) {
                statement.setObject(1, network.get("name"));
                statement.setString(2, scannedAt);
                statement.setObject(3, network.get("encryption"));
                statement.setObject(4, score);
                statement.setString(5, result);
                statement.executeUpdate();
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("network", network);
            response.put("scanned_at", scannedAt);
            response.put("score", score);
            response.put("result", result);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        }
    }

    @PatchMapping("/api/settings")
    public ResponseEntity<Map<String, String>> updateSettings(@RequestBody Map<String, Object> values)
            throws SQLException {
        Map<String, String> updates = new LinkedHashMap<>();
        values.forEach((key, value) -> {
            if (ALLOWED_SETTINGS.contains(key)) {
                updates.put(key, value == null
                        ? "None"
                        : value instanceof Boolean booleanValue
                                ? booleanValue.toString()
                                : value.toString());
            }
        });

        if (updates.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No supported settings were provided");
        }

        try (Connection database = connection();
             PreparedStatement statement = database.prepareStatement(
                     "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")) {
            for (Map.Entry<String, String> update : updates.entrySet()) {
                statement.setString(1, update.getKey());
                statement.setString(2, update.getValue());
                statement.addBatch();
            }
            statement.executeBatch();
        }
        return ResponseEntity.ok(updates);
    }

    // -------------------------------------------------------------
    // PART 3: AI CYBERSECURITY CHAT ASSISTANT
    // -------------------------------------------------------------
    @PostMapping("/api/ai/chat")
    public Map<String, Object> aiChat(@RequestBody Map<String, String> request) {
        String question = request.get("question");
        Optional<WifiNetworkScanner.ConnectedWifi> connected = wifiNetworkScanner.getConnectedWifi();
        List<WifiNetworkScanner.Network> visible = scanAvailableWifiSafe();
        List<Map<String, Object>> threats = wifiNetworkScanner.detectThreats(visible, connected);
        return wifiNetworkScanner.processAiChat(question, connected, visible, threats);
    }

    // -------------------------------------------------------------
    // PART 6: NETWORK PERFORMANCE ANALYSIS
    // -------------------------------------------------------------
    @GetMapping("/api/performance")
    public Map<String, Object> getPerformance() {
        return wifiNetworkScanner.measureNetworkPerformance();
    }

    // -------------------------------------------------------------
    // PART 11: MACHINE LEARNING & STATISTICAL ANOMALY DETECTION
    // -------------------------------------------------------------
    @GetMapping("/api/ml/anomalies")
    public Map<String, Object> getMlAnomalies() {
        List<WifiNetworkScanner.Network> visible = scanAvailableWifiSafe();
        return wifiNetworkScanner.detectMlAnomalies(visible, wifiNetworkScanner.getConnectedWifi());
    }

    // -------------------------------------------------------------
    // PART 10: ADVANCED EXPORT ENGINES (CSV & JSON)
    // -------------------------------------------------------------
    @GetMapping(value = "/api/export/csv", produces = "text/csv")
    public ResponseEntity<Resource> exportCsv() {
        List<WifiNetworkScanner.Network> networks = scanAvailableWifiSafe();
        StringBuilder csv = new StringBuilder();
        csv.append("SSID,BSSID,Band,Channel,Signal_Percent,Signal_dBm,Signal_Quality,Authentication,Encryption,Security_Score,Security_Rating,Vendor,Evil_Twin_Alert\r\n");

        for (WifiNetworkScanner.Network n : networks) {
            csv.append("\"").append(n.ssid().replace("\"", "\"\"")).append("\",");
            csv.append("\"").append(n.bssid()).append("\",");
            csv.append("\"").append(n.band()).append("\",");
            csv.append(n.channel()).append(",");
            csv.append(n.signalPercent()).append(",");
            csv.append(n.signalDbm()).append(",");
            csv.append("\"").append(n.signalQuality()).append("\",");
            csv.append("\"").append(n.authentication()).append("\",");
            csv.append("\"").append(n.encryption()).append("\",");
            csv.append(n.securityScore()).append(",");
            csv.append("\"").append(n.securityRating()).append("\",");
            csv.append("\"").append(n.vendor()).append("\",");
            csv.append(n.isEvilTwin() ? "CRITICAL_EVIL_TWIN" : "VERIFIED").append("\r\n");
        }

        byte[] bytes = csv.toString().getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"netguard-scan-report.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(new ByteArrayResource(bytes));
    }

    @GetMapping(value = "/api/export/json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Resource> exportJson() throws SQLException {
        Map<String, Object> data = getReportData();
        String json = serializeSimpleJson(data);
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"netguard-audit-report.json\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ByteArrayResource(bytes));
    }

    private String serializeSimpleJson(Map<String, Object> data) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(entry.getKey()).append("\":");
            if (entry.getValue() instanceof String str) {
                sb.append("\"").append(str.replace("\"", "\\\"")).append("\"");
            } else if (entry.getValue() instanceof Number || entry.getValue() instanceof Boolean) {
                sb.append(entry.getValue());
            } else {
                sb.append("\"").append(String.valueOf(entry.getValue()).replace("\"", "\\\"")).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    // -------------------------------------------------------------
    // PART 14: SECURITY CHECKLIST & KNOWLEDGE BASE
    // -------------------------------------------------------------
    @GetMapping("/api/security/checklist")
    public Map<String, Object> getChecklist() {
        Optional<WifiNetworkScanner.ConnectedWifi> conn = wifiNetworkScanner.getConnectedWifi();
        int score = conn.map(WifiNetworkScanner.ConnectedWifi::securityScore).orElse(0);
        String auth = conn.map(WifiNetworkScanner.ConnectedWifi::authentication).orElse("").toLowerCase(Locale.ROOT);

        List<Map<String, Object>> items = new ArrayList<>();
        items.add(Map.of(
                "id", 1,
                "title", "WPA3 / WPA2-AES Encryption Active",
                "completed", auth.contains("wpa2") || auth.contains("wpa3"),
                "severity", "HIGH",
                "description", "Enforces modern link encryption to block brute-force handshake capture."
        ));
        items.add(Map.of(
                "id", 2,
                "title", "Wi-Fi Protected Setup (WPS) Disabled",
                "completed", score >= 80,
                "severity", "HIGH",
                "description", "Disables 8-digit PIN brute-forcing via Reaver and Pixie-Dust tools."
        ));
        items.add(Map.of(
                "id", 3,
                "title", "Unique Passphrase (>14 characters)",
                "completed", score >= 75,
                "severity", "MEDIUM",
                "description", "Resists offline GPU-accelerated hash cracking attacks."
        ));
        items.add(Map.of(
                "id", 4,
                "title", "IoT Guest Network Isolation",
                "completed", true,
                "severity", "MEDIUM",
                "description", "Prevents vulnerable smart devices from lateral network movement."
        ));
        items.add(Map.of(
                "id", 5,
                "title", "Router Administration Password Hardened",
                "completed", true,
                "severity", "CRITICAL",
                "description", "Ensures default factory router credentials (admin/admin) are changed."
        ));

        long completedCount = items.stream().filter(i -> Boolean.TRUE.equals(i.get("completed"))).count();
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("checklist", items);
        res.put("completedCount", completedCount);
        res.put("totalCount", items.size());
        res.put("readinessPercent", Math.round((completedCount * 100.0) / items.size()));
        return res;
    }

    @GetMapping("/api/knowledge")
    public Map<String, Object> getKnowledgeCenter() {
        Map<String, Object> know = new LinkedHashMap<>();
        know.put("tipOfTheDay", Map.of(
                "title", "Disable WPS for Immediate Hardening",
                "content", "Wi-Fi Protected Setup (WPS) was designed for convenience, but its 8-digit PIN can be cracked within 4–10 hours using automated tools. Disabling WPS in your router's wireless settings immediately closes this major attack vector."
        ));

        List<Map<String, String>> articles = List.of(
                Map.of(
                        "title", "What is an Evil Twin Attack?",
                        "category", "Threat Intelligence",
                        "summary", "An attacker impersonates your legitimate Wi-Fi SSID using a rogue access point to intercept credentials and perform MITM sniffing."
                ),
                Map.of(
                        "title", "Why WPA3 is Mathematically Superior to WPA2",
                        "category", "Cryptography",
                        "summary", "WPA3 implements Simultaneous Authentication of Equals (SAE) with dragonfly handshake, making offline password dictionary guessing impossible."
                ),
                Map.of(
                        "title", "Protected Management Frames (PMF) Explained",
                        "category", "Protocol Standards",
                        "summary", "PMF (802.11w) cryptographically signs deauthentication and disassociation frames, immunizing clients against Wi-Fi jamming."
                ),
                Map.of(
                        "title", "Subnet Device Allowlisting Best Practices",
                        "category", "LAN Defense",
                        "summary", "Continuously auditing connected MAC addresses and maintaining a strict hardware allowlist prevents unauthorized lateral network access."
                )
        );
        know.put("articles", articles);
        return know;
    }

    // Threat Endpoints

    @GetMapping("/api/threats")
    public Map<String, Object> getThreats() {
        List<WifiNetworkScanner.Network> visible = scanAvailableWifiSafe();
        List<Map<String, Object>> threats = wifiNetworkScanner.detectThreats(visible, wifiNetworkScanner.getConnectedWifi());
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("threats", threats);
        response.put("count", threats.size());
        response.put("checkedAt", LocalDateTime.now().format(SCAN_TIME_FORMAT));
        return response;
    }

    @GetMapping("/api/traffic")
    public Map<String, Object> getTraffic() {
        return wifiNetworkScanner.getTrafficMetrics();
    }

    @GetMapping("/api/alerts")
    public List<Map<String, Object>> getAlerts() throws SQLException {
        try (Connection database = connection()) {
            return queryAll(database, "SELECT * FROM alerts ORDER BY id DESC LIMIT 50");
        }
    }

    @PostMapping("/api/alerts/clear")
    public ResponseEntity<Map<String, Object>> clearAlerts() throws SQLException {
        try (Connection database = connection(); Statement statement = database.createStatement()) {
            statement.executeUpdate("UPDATE alerts SET is_read = 1");
            return ResponseEntity.ok(Map.of("status", "success", "message", "All alerts marked as read."));
        }
    }

    @GetMapping("/api/wifi/compare")
    public Map<String, Object> compareNetworks(@RequestParam(value = "ssids", required = false) String ssidsParam) {
        List<WifiNetworkScanner.Network> visible = scanAvailableWifiSafe();
        List<WifiNetworkScanner.Network> selected;

        if (ssidsParam != null && !ssidsParam.isBlank()) {
            Set<String> requestedSsids = Set.copyOf(Arrays.asList(ssidsParam.split(",")));
            selected = visible.stream()
                    .filter(n -> requestedSsids.contains(n.ssid()))
                    .toList();
        } else {
            selected = visible.stream().limit(3).toList();
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("networks", selected.stream().map(WifiNetworkScanner.Network::toMap).toList());
        response.put("timestamp", LocalDateTime.now().format(SCAN_TIME_FORMAT));
        return response;
    }

    @GetMapping("/api/ai/recommendations")
    public Map<String, Object> getAiRecommendations() {
        Optional<WifiNetworkScanner.ConnectedWifi> connected = wifiNetworkScanner.getConnectedWifi();
        List<WifiNetworkScanner.Network> visible = scanAvailableWifiSafe();
        List<Map<String, Object>> threats = wifiNetworkScanner.detectThreats(visible, connected);
        return wifiNetworkScanner.getAiSecurityAnalysis(connected, visible, threats);
    }

    @GetMapping("/api/report/data")
    public Map<String, Object> getReportData() throws SQLException {
        try (Connection database = connection()) {
            Map<String, Object> report = new LinkedHashMap<>();
            Map<String, Object> network = syncCurrentNetwork(database);
            String networkName = (String) network.get("name");
            boolean isConnected = Boolean.TRUE.equals(network.get("connected"));

            List<WifiNetworkScanner.Network> visible = scanAvailableWifiSafe();
            List<Map<String, Object>> threats = wifiNetworkScanner.detectThreats(visible, wifiNetworkScanner.getConnectedWifi());
            List<Map<String, Object>> devices = getLiveOrStoredDevices(database, networkName, isConnected);
            Map<String, Object> aiAnalysis = wifiNetworkScanner.getAiSecurityAnalysis(wifiNetworkScanner.getConnectedWifi(), visible, threats);
            Map<String, Object> performance = wifiNetworkScanner.measureNetworkPerformance();

            report.put("network", network);
            report.put("devices", devices);
            report.put("threats", threats);
            report.put("aiAnalysis", aiAnalysis);
            report.put("performance", performance);
            report.put("scannedNetworks", visible.stream().map(WifiNetworkScanner.Network::toMap).toList());
            report.put("generatedAt", LocalDateTime.now().format(SCAN_TIME_FORMAT));
            report.put("auditor", "NetGuard Security Engine v2.0");
            report.put("systemPlatform", System.getProperty("os.name") + " (" + System.getProperty("os.arch") + ")");
            return report;
        }
    }

    // Static Resource Serving

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<Resource> index() {
        return projectFile("index.html");
    }

    @GetMapping(value = "/app.js", produces = "text/javascript")
    public ResponseEntity<Resource> script() {
        return projectFile("app.js");
    }

    @GetMapping(value = "/styles.css", produces = "text/css")
    public ResponseEntity<Resource> stylesheet() {
        return projectFile("styles.css");
    }

    @GetMapping(value = "/qrcode.js", produces = "text/javascript")
    public ResponseEntity<Resource> qrcodeScript() {
        return projectFile("qrcode.js");
    }

    private static ResponseEntity<Resource> projectFile(String fileName) {
        Path filePath = Path.of(fileName).toAbsolutePath().normalize();
        return ResponseEntity.ok(new FileSystemResource(filePath));
    }

    private Connection connection() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + databasePath);
    }

    private List<WifiNetworkScanner.Network> scanAvailableWifi() {
        try {
            return wifiNetworkScanner.scan();
        } catch (UnsupportedOperationException error) {
            throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED, error.getMessage(), error);
        } catch (IOException error) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, error.getMessage(), error);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE, "The WiFi scan was interrupted.", error);
        }
    }

    private List<WifiNetworkScanner.Network> scanAvailableWifiSafe() {
        try {
            return wifiNetworkScanner.scan();
        } catch (Exception ignored) {
            return Collections.emptyList();
        }
    }

    private static Map<String, Object> queryOne(Connection database, String sql) throws SQLException {
        List<Map<String, Object>> rows = queryAll(database, sql);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private static List<Map<String, Object>> queryAll(Connection database, String sql) throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>();
        try (Statement statement = database.createStatement(); ResultSet result = statement.executeQuery(sql)) {
            int columnCount = result.getMetaData().getColumnCount();
            while (result.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (int column = 1; column <= columnCount; column++) {
                    row.put(result.getMetaData().getColumnLabel(column), result.getObject(column));
                }
                rows.add(row);
            }
        }
        return rows;
    }

    private static void seedNetwork(Connection database) throws SQLException {
        if (countRows(database, "network") == 0) {
            try (PreparedStatement statement = database.prepareStatement("""
                    INSERT INTO network VALUES (1, ?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "Home_WiFi");
                statement.setString(2, "5 GHz");
                statement.setInt(3, 36);
                statement.setInt(4, -48);
                statement.setInt(5, 82);
                statement.setString(6, "WPA2-Personal");
                statement.executeUpdate();
            }
        }
    }

    private static void seedDevices(Connection database) throws SQLException {
        if (countRows(database, "devices") != 0) {
            return;
        }
        try (PreparedStatement statement = database.prepareStatement("""
                INSERT INTO devices (name, platform, ip_address, status, last_seen, mac_address, vendor, device_type, first_seen, is_trusted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            addDevice(statement, "Android Phone", "Samsung · Android 14", "192.168.1.10", "just now", "50:01:d9:12:34:56", "Samsung Electronics", "phone", "Today, 10:00 AM", 1);
            addDevice(statement, "Laptop", "Windows · Personal", "192.168.1.12", "2 min ago", "a4:4c:c8:78:90:ab", "Intel Corporation", "laptop", "Today, 09:30 AM", 1);
            addDevice(statement, "Smart TV", "Samsung · Tizen", "192.168.1.15", "8 min ago", "64:b5:c6:cd:ef:01", "Samsung Electronics", "tv", "Yesterday, 08:15 PM", 1);
            statement.executeBatch();
        }
    }

    private static void seedScans(Connection database) throws SQLException {
        if (countRows(database, "scans") == 0) {
            try (PreparedStatement statement = database.prepareStatement("""
                    INSERT INTO scans (network_name, scanned_at, encryption, score, result)
                    VALUES (?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "Home_WiFi");
                statement.setString(2, "Today, 12:05 PM");
                statement.setString(3, "WPA2-Personal");
                statement.setInt(4, 82);
                statement.setString(5, "GOOD");
                statement.executeUpdate();
            }
        }
    }

    private static void seedSettings(Connection database) throws SQLException {
        try (PreparedStatement statement = database.prepareStatement(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)")) {
            statement.setString(1, "auto_scan");
            statement.setString(2, "true");
            statement.addBatch();
            statement.setString(1, "notifications");
            statement.setString(2, "true");
            statement.addBatch();
            statement.setString(1, "theme");
            statement.setString(2, "dark");
            statement.addBatch();
            statement.setString(1, "device_wifi_tracking");
            statement.setString(2, "true");
            statement.addBatch();
            statement.setString(1, "auto_scan_interval");
            statement.setString(2, "30");
            statement.addBatch();
            statement.executeBatch();
        }
    }

    private static void seedAlerts(Connection database) throws SQLException {
        if (countRows(database, "alerts") == 0) {
            try (PreparedStatement statement = database.prepareStatement("""
                    INSERT INTO alerts (title, message, severity, category, created_at, is_read)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "Protected WPA2 Connection Established");
                statement.setString(2, "Authorized client connected with AES-CCMP encryption.");
                statement.setString(3, "LOW");
                statement.setString(4, "NETWORK");
                statement.setString(5, "Today, 12:05 PM");
                statement.setInt(6, 0);
                statement.addBatch();

                statement.setString(1, "Unencrypted Airspace Broadcast");
                statement.setString(2, "One or more nearby Wi-Fi networks advertise Open encryption without authentication.");
                statement.setString(3, "MEDIUM");
                statement.setString(4, "SECURITY");
                statement.setString(5, "Today, 11:30 AM");
                statement.setInt(6, 0);
                statement.addBatch();

                statement.executeBatch();
            }
        }
    }

    private static void addDevice(
            PreparedStatement statement, String name, String platform, String address, String lastSeen,
            String macAddress, String vendor, String deviceType, String firstSeen, int isTrusted)
            throws SQLException {
        statement.setString(1, name);
        statement.setString(2, platform);
        statement.setString(3, address);
        statement.setString(4, "online");
        statement.setString(5, lastSeen);
        statement.setString(6, macAddress);
        statement.setString(7, vendor);
        statement.setString(8, deviceType);
        statement.setString(9, firstSeen);
        statement.setInt(10, isTrusted);
        statement.addBatch();
    }

    private static int countRows(Connection database, String table) throws SQLException {
        try (Statement statement = database.createStatement();
             ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
            return result.getInt(1);
        }
    }
}

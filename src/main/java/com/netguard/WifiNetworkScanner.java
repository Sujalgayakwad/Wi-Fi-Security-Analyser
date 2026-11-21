package com.netguard;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

@Component
public class WifiNetworkScanner {
    private static final Pattern SSID_LINE = Pattern.compile("^SSID\\s+\\d+\\s*:\\s*(.*)$");
    private static final Pattern BSSID_LINE = Pattern.compile("^BSSID\\s+\\d+\\s*:\\s*([0-9a-fA-F:-]{17}).*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern SIGNAL_LINE = Pattern.compile("^Signal\\s*:\\s*(\\d+)\\s*%?.*$");
    private static final Pattern CHANNEL_LINE = Pattern.compile("^Channel\\s*:\\s*(\\d+).*$");
    private static final Pattern RADIO_LINE = Pattern.compile("^Radio\\s+type\\s*:\\s*(.*)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern NETSTAT_BYTES = Pattern.compile("^Bytes\\s+(\\d+)\\s+(\\d+).*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern NETSTAT_UNICAST = Pattern.compile("^Unicast\\s+packets\\s+(\\d+)\\s+(\\d+).*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern NETSTAT_ERRORS = Pattern.compile("^Errors\\s+(\\d+)\\s+(\\d+).*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern NETSTAT_DISCARDS = Pattern.compile("^Discards\\s+(\\d+)\\s+(\\d+).*$", Pattern.CASE_INSENSITIVE);

    private static final Pattern PING_TIMES = Pattern.compile("Minimum\\s*=\\s*(\\d+)ms,\\s*Maximum\\s*=\\s*(\\d+)ms,\\s*Average\\s*=\\s*(\\d+)ms", Pattern.CASE_INSENSITIVE);
    private static final Pattern PING_LOSS = Pattern.compile("Lost\\s*=\\s*(\\d+)\\s*\\((\\d+)%\\s*loss\\)", Pattern.CASE_INSENSITIVE);

    // State for calculating live network throughput
    private static final AtomicLong lastSampleTime = new AtomicLong(0);
    private static final AtomicLong lastBytesIn = new AtomicLong(0);
    private static final AtomicLong lastBytesOut = new AtomicLong(0);
    private static final AtomicReference<Map<String, Object>> lastTrafficReport = new AtomicReference<>(null);

    public record ConnectedWifi(
            String ssid,
            String state,
            String band,
            int channel,
            int signalPercent,
            int signalDbm,
            String authentication,
            String cipher,
            int securityScore,
            String securityRating,
            String description,
            String bssid,
            String password,
            String radioType,
            String vendor) {

        public ConnectedWifi(
                String ssid,
                String state,
                String band,
                int channel,
                int signalPercent,
                int signalDbm,
                String authentication,
                String cipher,
                int securityScore,
                String securityRating,
                String description,
                String bssid,
                String password) {
            this(ssid, state, band, channel, signalPercent, signalDbm, authentication, cipher,
                 securityScore, securityRating, description, bssid, password, "802.11ac", resolveVendor(bssid));
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("id", 1);
            map.put("name", ssid);
            map.put("ssid", ssid);
            map.put("state", state);
            map.put("band", band != null && !band.isBlank() ? band : deriveBand(channel));
            map.put("channel", channel > 0 ? channel : 36);
            map.put("signalPercent", signalPercent);
            map.put("signal_dbm", signalDbm != 0 ? signalDbm : calculateDbm(signalPercent));
            map.put("signalQuality", classifySignalQuality(signalDbm != 0 ? signalDbm : calculateDbm(signalPercent)));
            map.put("score", securityScore);
            map.put("securityRating", securityRating);
            map.put("securityClassification", classifyScore(securityScore));
            map.put("encryption", authentication != null && !authentication.isBlank() ? authentication : "WPA2-Personal");
            map.put("cipher", cipher != null ? cipher : "CCMP");
            map.put("description", description);
            map.put("bssid", bssid != null ? bssid : "");
            map.put("password", password != null ? password : "");
            map.put("radioType", radioType != null ? radioType : "802.11ac");
            map.put("vendor", vendor != null ? vendor : resolveVendor(bssid));
            return map;
        }
    }

    public Optional<ConnectedWifi> getConnectedWifi() {
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")) {
            return Optional.empty();
        }
        try {
            Process process = new ProcessBuilder("netsh", "wlan", "show", "interfaces")
                    .redirectErrorStream(true)
                    .start();
            CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> {
                try {
                    return process.getInputStream().readAllBytes();
                } catch (IOException error) {
                    throw new java.util.concurrent.CompletionException(error);
                }
            });

            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return Optional.empty();
            }

            String text = new String(output.get(2, TimeUnit.SECONDS), Charset.defaultCharset());
            if (process.exitValue() != 0) {
                return Optional.empty();
            }
            Optional<ConnectedWifi> parsed = parseConnectedWifi(text);
            if (parsed.isPresent()) {
                ConnectedWifi net = parsed.get();
                String pwd = getWifiPassword(net.ssid());
                return Optional.of(new ConnectedWifi(
                        net.ssid(),
                        net.state(),
                        net.band(),
                        net.channel(),
                        net.signalPercent(),
                        net.signalDbm(),
                        net.authentication(),
                        net.cipher(),
                        net.securityScore(),
                        net.securityRating(),
                        net.description(),
                        net.bssid(),
                        pwd,
                        net.radioType(),
                        resolveVendor(net.bssid())));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public String getWifiPassword(String ssid) {
        if (ssid == null || ssid.isBlank() || !System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")) {
            return "";
        }
        try {
            Process process = new ProcessBuilder("netsh", "wlan", "show", "profile", "name=" + ssid, "key=clear")
                    .redirectErrorStream(true)
                    .start();
            CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> {
                try {
                    return process.getInputStream().readAllBytes();
                } catch (IOException error) {
                    throw new java.util.concurrent.CompletionException(error);
                }
            });
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return "";
            }
            String text = new String(output.get(2, TimeUnit.SECONDS), Charset.defaultCharset());
            for (String rawLine : text.split("\\R")) {
                String line = rawLine.trim();
                int idx = line.indexOf(':');
                if (idx > 0) {
                    String key = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
                    if (key.equals("key content")) {
                        return line.substring(idx + 1).trim();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    public List<Map<String, Object>> scanLocalDevices(String networkName) {
        List<Map<String, Object>> devices = new ArrayList<>();
        // 1. Host Device (This PC)
        try {
            String hostName = System.getenv("COMPUTERNAME");
            if (hostName == null || hostName.isBlank()) {
                hostName = InetAddress.getLocalHost().getHostName();
            }
            String hostIp = InetAddress.getLocalHost().getHostAddress();
            Map<String, Object> host = new LinkedHashMap<>();
            host.put("id", 1);
            host.put("name", hostName + " (This PC)");
            host.put("hostname", hostName);
            host.put("platform", System.getProperty("os.name") + " · Active Host Device");
            host.put("ip_address", hostIp);
            host.put("mac_address", "Local Host Interface");
            host.put("vendor", "Local Host System");
            host.put("device_type", "laptop");
            host.put("status", "online");
            host.put("last_seen", "Active now");
            host.put("connected_wifi", networkName != null ? networkName : "Connected Wi-Fi");
            host.put("is_host", true);
            host.put("is_trusted", true);
            devices.add(host);
        } catch (Exception ignored) {}

        // 2. ARP Discovery for Gateway and active LAN neighbors
        try {
            Process process = new ProcessBuilder("arp", "-a").redirectErrorStream(true).start();
            CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> {
                try {
                    return process.getInputStream().readAllBytes();
                } catch (IOException error) {
                    throw new java.util.concurrent.CompletionException(error);
                }
            });
            if (process.waitFor(3, TimeUnit.SECONDS)) {
                String arpText = new String(output.get(1, TimeUnit.SECONDS), Charset.defaultCharset());
                int id = 2;
                for (String rawLine : arpText.split("\\R")) {
                    String line = rawLine.trim();
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 3) {
                        String ip = parts[0];
                        String mac = parts[1].replace('-', ':').toLowerCase(Locale.ROOT);
                        String type = parts[2];
                        if (type.equalsIgnoreCase("dynamic") && !ip.endsWith(".255") && !ip.startsWith("224.") && !ip.startsWith("239.")) {
                            boolean isGateway = ip.endsWith(".1");
                            String vendor = resolveVendor(mac);
                            String deviceType = isGateway ? "router" : inferDeviceType(vendor, ip);
                            String deviceName = isGateway ? "Default Gateway / Router (" + vendor + ")" : "Connected Device (" + ip + ")";

                            Map<String, Object> dev = new LinkedHashMap<>();
                            dev.put("id", id++);
                            dev.put("name", deviceName);
                            dev.put("hostname", "host-" + ip.replace('.', '-'));
                            dev.put("platform", "MAC: " + mac + " · " + vendor);
                            dev.put("ip_address", ip);
                            dev.put("mac_address", mac);
                            dev.put("vendor", vendor);
                            dev.put("device_type", deviceType);
                            dev.put("status", "online");
                            dev.put("last_seen", "Active");
                            dev.put("connected_wifi", networkName != null ? networkName : "Connected Wi-Fi");
                            dev.put("is_host", false);
                            dev.put("is_trusted", isGateway);
                            devices.add(dev);
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        return devices;
    }

    static Optional<ConnectedWifi> parseConnectedWifi(String output) {
        String[] blocks = output.split("(?m)(?=^\\s*Name\\s*:)");
        for (String block : blocks) {
            String state = null;
            String ssid = null;
            String band = null;
            int channel = 0;
            int signalPercent = 80;
            int signalDbm = 0;
            String authentication = "WPA2-Personal";
            String cipher = "CCMP";
            String description = "WiFi Adapter";
            String bssid = "";
            String radioType = "802.11ac";

            for (String rawLine : block.split("\\R")) {
                String line = rawLine.trim();
                int colonIndex = line.indexOf(':');
                if (colonIndex < 0) continue;
                String key = line.substring(0, colonIndex).trim().toLowerCase(Locale.ROOT);
                String val = line.substring(colonIndex + 1).trim();

                switch (key) {
                    case "state" -> state = val;
                    case "ssid" -> {
                        if (!val.isEmpty()) ssid = val;
                    }
                    case "band" -> {
                        if (!val.isEmpty()) band = val;
                    }
                    case "channel" -> {
                        try { channel = Integer.parseInt(val.replaceAll("\\D+", "")); } catch (Exception ignored) {}
                    }
                    case "authentication" -> {
                        if (!val.isEmpty()) authentication = val;
                    }
                    case "cipher" -> {
                        if (!val.isEmpty()) cipher = val;
                    }
                    case "signal" -> {
                        try { signalPercent = Integer.parseInt(val.replaceAll("\\D+", "")); } catch (Exception ignored) {}
                    }
                    case "rssi" -> {
                        try { signalDbm = Integer.parseInt(val.trim()); } catch (Exception ignored) {}
                    }
                    case "description" -> description = val;
                    case "bssid", "ap bssid" -> bssid = val;
                    case "radio type" -> radioType = val;
                }
            }

            if ("connected".equalsIgnoreCase(state) && ssid != null && !ssid.isBlank()) {
                if (channel > 0 && (band == null || band.isBlank())) {
                    band = deriveBand(channel);
                }
                if (signalDbm == 0) {
                    signalDbm = calculateDbm(signalPercent);
                }

                int score = 82;
                String rating = "Good";
                String authLower = authentication.toLowerCase(Locale.ROOT);
                if (authLower.contains("wpa3")) {
                    score = 100;
                    rating = "Strong";
                } else if (authLower.contains("wpa2")) {
                    score = 82;
                    rating = "Good";
                } else if (authLower.contains("wpa")) {
                    score = 55;
                    rating = "Fair";
                } else if (authLower.contains("wep")) {
                    score = 20;
                    rating = "Weak";
                } else if (authLower.contains("open") || cipher.equalsIgnoreCase("none")) {
                    score = 10;
                    rating = "Unsafe";
                }

                return Optional.of(new ConnectedWifi(
                        ssid,
                        state,
                        band != null ? band : "2.4 GHz",
                        channel > 0 ? channel : 11,
                        signalPercent,
                        signalDbm,
                        authentication,
                        cipher,
                        score,
                        rating,
                        description,
                        bssid,
                        "",
                        radioType,
                        resolveVendor(bssid)));
            }
        }
        return Optional.empty();
    }

    public List<Network> scan() throws IOException, InterruptedException {
        if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")) {
            throw new UnsupportedOperationException("Live WiFi discovery is currently supported on Windows.");
        }

        Process process = new ProcessBuilder("netsh", "wlan", "show", "networks", "mode=bssid")
                .redirectErrorStream(true)
                .start();
        CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> {
            try {
                return process.getInputStream().readAllBytes();
            } catch (IOException error) {
                throw new java.util.concurrent.CompletionException(error);
            }
        });

        try {
            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IOException("The Windows WiFi scan timed out. Check that the WLAN service is running.");
            }

            String text = new String(output.get(3, TimeUnit.SECONDS), Charset.defaultCharset());
            if (process.exitValue() != 0) {
                throw new IOException("Windows could not scan nearby WiFi networks: " + lastOutputLine(text));
            }
            return parse(text);
        } catch (ExecutionException error) {
            throw new IOException("Could not read the Windows WiFi scan result.", error.getCause());
        } catch (TimeoutException error) {
            throw new IOException("Timed out while reading the Windows WiFi scan result.", error);
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.getInputStream().close();
        }
    }

    static List<Network> parse(String output) {
        List<NetworkBuilder> rawAps = new ArrayList<>();
        Map<String, List<String>> ssidBssidMap = new LinkedHashMap<>();
        NetworkBuilder current = null;

        for (String rawLine : output.split("\\R")) {
            String line = rawLine.trim();
            Matcher ssid = SSID_LINE.matcher(line);
            if (ssid.matches()) {
                if (current != null && current.bssid != null && !current.bssid.isBlank()) {
                    rawAps.add(current);
                }
                String name = ssid.group(1).trim();
                current = new NetworkBuilder(name.isEmpty() ? "[Hidden SSID]" : name);
                continue;
            }
            if (current == null) {
                continue;
            }
            if (line.regionMatches(true, 0, "Authentication", 0, "Authentication".length())) {
                current.authentication = fieldValue(line);
            } else if (line.regionMatches(true, 0, "Encryption", 0, "Encryption".length())) {
                current.encryption = fieldValue(line);
            } else if (line.regionMatches(true, 0, "Radio type", 0, "Radio type".length())) {
                current.radioType = fieldValue(line);
            } else if (line.startsWith("BSSID") || line.startsWith("bssid")) {
                Matcher bssidMatch = BSSID_LINE.matcher(line);
                if (bssidMatch.matches()) {
                    if (current.bssid != null && !current.bssid.isBlank()) {
                        rawAps.add(current.copy());
                    }
                    current.bssid = bssidMatch.group(1).trim();
                    ssidBssidMap.computeIfAbsent(current.ssid, k -> new ArrayList<>()).add(current.bssid);
                }
            } else if (line.startsWith("Signal")) {
                Matcher signal = SIGNAL_LINE.matcher(line);
                if (signal.matches()) {
                    current.signalPercent = Integer.parseInt(signal.group(1));
                }
            } else if (line.startsWith("Channel")) {
                Matcher channel = CHANNEL_LINE.matcher(line);
                if (channel.matches()) {
                    current.channel = Integer.parseInt(channel.group(1));
                    current.band = deriveBand(current.channel);
                }
            }
        }
        if (current != null && current.bssid != null && !current.bssid.isBlank()) {
            rawAps.add(current);
        }

        List<Network> analyzedList = new ArrayList<>();
        for (NetworkBuilder ap : rawAps) {
            List<String> bssids = ssidBssidMap.getOrDefault(ap.ssid, Collections.emptyList());
            ap.isDuplicate = bssids.size() > 1;
            analyzedList.add(ap.build());
        }

        return analyzedList.stream()
                .sorted(Comparator.comparingInt(Network::signalPercent).reversed().thenComparing(Network::ssid))
                .toList();
    }

    private static String fieldValue(String line) {
        int separator = line.indexOf(':');
        return separator < 0 ? "Unknown" : line.substring(separator + 1).trim();
    }

    public static String deriveBand(int channel) {
        if (channel >= 1 && channel <= 14) {
            return "2.4 GHz";
        } else if (channel >= 32 && channel <= 177) {
            return "5 GHz";
        } else if (channel > 177) {
            return "6 GHz";
        }
        return "2.4 GHz";
    }

    public static int calculateDbm(int signalPercent) {
        if (signalPercent <= 0) return -100;
        if (signalPercent >= 100) return -45;
        return (signalPercent / 2) - 100;
    }

    public static String classifySignalQuality(int signalDbm) {
        if (signalDbm >= -55) return "Excellent";
        if (signalDbm >= -67) return "Good";
        if (signalDbm >= -78) return "Fair";
        return "Weak";
    }

    public static String classifyScore(int score) {
        if (score >= 90) return "Excellent";
        if (score >= 75) return "Good";
        if (score >= 50) return "Moderate";
        if (score >= 25) return "Poor";
        return "Critical";
    }

    public static String resolveVendor(String macAddress) {
        if (macAddress == null || macAddress.length() < 8) {
            return "Standard Wi-Fi Device";
        }
        String clean = macAddress.replace("-", ":").toLowerCase(Locale.ROOT);
        String prefix = clean.substring(0, Math.min(8, clean.length()));

        if (prefix.startsWith("8e:29:31") || prefix.startsWith("d8:9c:67") || prefix.startsWith("00:e0:4c")) {
            return "Realtek Semiconductor";
        } else if (prefix.startsWith("00:03:93") || prefix.startsWith("f0:18:98") || prefix.startsWith("88:66:5a") || prefix.startsWith("ac:de:48")) {
            return "Apple Inc.";
        } else if (prefix.startsWith("00:00:f0") || prefix.startsWith("50:01:d9") || prefix.startsWith("64:b5:c6")) {
            return "Samsung Electronics";
        } else if (prefix.startsWith("00:02:b3") || prefix.startsWith("7c:21:4a") || prefix.startsWith("a4:4c:c8")) {
            return "Intel Corporation";
        } else if (prefix.startsWith("50:c7:bf") || prefix.startsWith("60:32:b1") || prefix.startsWith("98:42:65") || prefix.startsWith("00:27:19")) {
            return "TP-Link Technologies";
        } else if (prefix.startsWith("00:09:5b") || prefix.startsWith("20:e5:2a") || prefix.startsWith("84:1b:5e")) {
            return "Netgear Inc.";
        } else if (prefix.startsWith("00:00:0c") || prefix.startsWith("00:01:42") || prefix.startsWith("00:01:43")) {
            return "Cisco Systems";
        } else if (prefix.startsWith("64:09:80") || prefix.startsWith("74:51:ba") || prefix.startsWith("ac:c1:ee")) {
            return "Xiaomi Communications";
        } else if (prefix.startsWith("00:18:82") || prefix.startsWith("08:19:a6") || prefix.startsWith("28:6e:d4")) {
            return "Huawei Technologies";
        } else if (prefix.startsWith("24:0a:c4") || prefix.startsWith("24:6f:28") || prefix.startsWith("84:0d:8e")) {
            return "Espressif IoT Device";
        } else if (prefix.startsWith("b8:27:eb") || prefix.startsWith("dc:a6:32") || prefix.startsWith("e4:5f:01")) {
            return "Raspberry Pi Foundation";
        } else if (prefix.startsWith("00:1a:11") || prefix.startsWith("f4:f5:e8") || prefix.startsWith("3c:5a:37")) {
            return "Google LLC";
        } else if (prefix.startsWith("00:bb:3a") || prefix.startsWith("40:b4:cd") || prefix.startsWith("68:37:e9")) {
            return "Amazon Technologies";
        } else if (prefix.startsWith("00:1d:7e") || prefix.startsWith("74:ea:3a")) {
            return "Cisco Linksys";
        } else if (prefix.startsWith("00:18:e7") || prefix.startsWith("04:d9:f5")) {
            return "ASUSTeK Computer";
        }
        return "Authorized Hardware (" + prefix.toUpperCase(Locale.ROOT) + ")";
    }

    private static String inferDeviceType(String vendor, String ip) {
        String lower = vendor.toLowerCase(Locale.ROOT);
        if (lower.contains("apple") || lower.contains("samsung") || lower.contains("xiaomi")) {
            return "phone";
        } else if (lower.contains("intel") || lower.contains("realtek")) {
            return "laptop";
        } else if (lower.contains("tp-link") || lower.contains("netgear") || lower.contains("cisco") || lower.contains("linksys")) {
            return "router";
        } else if (lower.contains("espressif") || lower.contains("raspberry") || lower.contains("amazon") || lower.contains("google")) {
            return "tv";
        }
        return "laptop";
    }

    private static String lastOutputLine(String output) {
        return output.lines().map(String::trim).filter(line -> !line.isEmpty())
                .reduce((first, second) -> second).orElse("No additional details were provided.");
    }

    private static Network analyze(NetworkBuilder network) {
        String authentication = network.authentication.toLowerCase(Locale.ROOT);
        String encryption = network.encryption.toLowerCase(Locale.ROOT);
        int score;
        String rating;
        List<String> recommendations = new ArrayList<>();
        List<String> scoreFactors = new ArrayList<>();

        if (authentication.contains("wpa3")) {
            score = 100;
            rating = "Strong";
            scoreFactors.add("+100: WPA3 Simultaneous Authentication of Equals (SAE) with protected management frames (PMF).");
            recommendations.add("WPA3 authentication active. Keep router firmware updated.");
        } else if (authentication.contains("wpa2")) {
            score = 85;
            rating = "Good";
            scoreFactors.add("+85: Robust WPA2-Personal authentication with CCMP (AES-128) cipher.");
            recommendations.add("WPA2 active. Consider transitioning to WPA3 if your hardware supports it.");
            recommendations.add("Ensure the Wi-Fi passphrase contains at least 14 alphanumeric/special characters.");
        } else if (authentication.contains("wpa")) {
            score = 50;
            rating = "Fair";
            scoreFactors.add("+50: Deprecated WPA protocol detected. Prone to handshake capture.");
            recommendations.add("Upgrade legacy WPA to WPA2-AES or WPA3 in your router configuration.");
        } else if (authentication.contains("wep")) {
            score = 15;
            rating = "Weak";
            scoreFactors.add("+15: Insecure WEP protocol in use. Cryptographic keys can be cracked in minutes.");
            recommendations.add("Critical: Replace WEP immediately. WEP is obsolete and offers no effective protection.");
        } else if (authentication.contains("open") || encryption.contains("none")) {
            score = 10;
            rating = "Unsafe";
            scoreFactors.add("+10: Unencrypted Open network. Air traffic is transmitted in unencrypted cleartext.");
            recommendations.add("High Risk: Avoid transmitting passwords or personal data without an encrypted VPN.");
            recommendations.add("Enable WPA2/WPA3 password protection on the access point.");
        } else {
            score = 40;
            rating = "Unverified";
            scoreFactors.add("+40: Unverified security configuration.");
            recommendations.add("Authentication parameters could not be verified. Inspect the router administration panel.");
        }

        if (network.isDuplicate) {
            score = Math.max(10, score - 15);
            scoreFactors.add("-15: Multiple access points detected advertising the identical SSID.");
            recommendations.add("Multiple BSSIDs found for this SSID. Verify whether these are authorized mesh APs or rogue clones.");
        }

        if (network.isEvilTwin) {
            score = 5;
            rating = "Critical";
            scoreFactors.add("-70: HIGH THREAT: Possible Evil Twin access point spoofing an authorized network name.");
            recommendations.add("CRITICAL ALERT: Do NOT connect to this access point. Possible Evil Twin Wi-Fi spoofing attack!");
        }

        int dbm = calculateDbm(network.signalPercent);
        String signalQuality = classifySignalQuality(dbm);

        return new Network(
                network.ssid,
                network.bssid != null ? network.bssid : "00:00:00:00:00:00",
                network.authentication,
                network.encryption,
                network.signalPercent,
                dbm,
                signalQuality,
                network.band != null ? network.band : deriveBand(network.channel != null ? network.channel : 11),
                network.channel != null ? network.channel : 11,
                network.radioType != null ? network.radioType : "802.11n",
                resolveVendor(network.bssid),
                score,
                rating,
                classifyScore(score),
                List.copyOf(scoreFactors),
                List.copyOf(recommendations),
                network.isEvilTwin,
                network.isDuplicate,
                score < 60 || network.isEvilTwin);
    }

    public List<Map<String, Object>> detectThreats(List<Network> networks, Optional<ConnectedWifi> connected) {
        List<Map<String, Object>> threats = new ArrayList<>();
        int threatId = 1;

        String connectedSsid = connected.map(ConnectedWifi::ssid).orElse("");
        String connectedBssid = connected.map(ConnectedWifi::bssid).orElse("").toLowerCase(Locale.ROOT);
        String connectedAuth = connected.map(ConnectedWifi::authentication).orElse("").toLowerCase(Locale.ROOT);

        Map<String, List<Network>> ssidGroups = new LinkedHashMap<>();
        for (Network net : networks) {
            ssidGroups.computeIfAbsent(net.ssid(), k -> new ArrayList<>()).add(net);
        }

        // 1. Detect Evil Twin targeting connected network
        if (!connectedSsid.isBlank() && !connectedSsid.equalsIgnoreCase("No Wi-Fi Connected")) {
            for (Network net : networks) {
                if (net.ssid().equalsIgnoreCase(connectedSsid)) {
                    String netBssid = net.bssid().toLowerCase(Locale.ROOT);
                    if (!connectedBssid.isBlank() && !netBssid.isBlank() && !netBssid.equalsIgnoreCase(connectedBssid)) {
                        boolean differentSecurity = !net.authentication().toLowerCase(Locale.ROOT).equals(connectedAuth);
                        String severity = differentSecurity ? "CRITICAL" : "HIGH";
                        String status = differentSecurity ? "CONFIRMED" : "POTENTIAL";

                        Map<String, Object> threat = new LinkedHashMap<>();
                        threat.put("id", threatId++);
                        threat.put("type", "EVIL_TWIN");
                        threat.put("severity", severity);
                        threat.put("status", status);
                        threat.put("title", "Possible Evil Twin Access Point Detected");
                        threat.put("description", "A secondary access point (" + net.bssid() + ") is advertising your connected network SSID '" + connectedSsid + "' with " + net.authentication() + " security. This may be an attacker attempting to intercept your Wi-Fi credentials.");
                        threat.put("affectedNetwork", connectedSsid);
                        threat.put("bssid", net.bssid());
                        threat.put("vendor", net.vendor());
                        threat.put("recommendation", "Confirm whether this is a legitimate range extender or mesh node. If not, disconnect immediately and enable MAC filtering.");
                        threats.add(threat);
                    }
                }
            }
        }

        // 2. Detect Duplicate SSIDs across the airspace
        for (Map.Entry<String, List<Network>> entry : ssidGroups.entrySet()) {
            if (entry.getValue().size() > 1 && !entry.getKey().isBlank()) {
                Network primary = entry.getValue().get(0);
                Map<String, Object> threat = new LinkedHashMap<>();
                threat.put("id", threatId++);
                threat.put("type", "DUPLICATE_SSID");
                threat.put("severity", "MEDIUM");
                threat.put("status", "POTENTIAL");
                threat.put("title", "Duplicate SSID in Airspace ('" + entry.getKey() + "')");
                threat.put("description", entry.getValue().size() + " separate access points are broadcasting the SSID '" + entry.getKey() + "' on channels " + entry.getValue().stream().map(n -> String.valueOf(n.channel())).toList() + ".");
                threat.put("affectedNetwork", entry.getKey());
                threat.put("bssid", primary.bssid());
                threat.put("vendor", primary.vendor());
                threat.put("recommendation", "If not an authorized mesh network, inspect BSSIDs to ensure no rogue AP is spoofing client connections.");
                threats.add(threat);
            }
        }

        // 3. Detect Open and Unsecured Wi-Fi networks
        for (Network net : networks) {
            String auth = net.authentication().toLowerCase(Locale.ROOT);
            if (auth.contains("open") || net.encryption().equalsIgnoreCase("none")) {
                Map<String, Object> threat = new LinkedHashMap<>();
                threat.put("id", threatId++);
                threat.put("type", "UNSECURED_NETWORK");
                threat.put("severity", net.ssid().equalsIgnoreCase(connectedSsid) ? "CRITICAL" : "HIGH");
                threat.put("status", "CONFIRMED");
                threat.put("title", "Unencrypted Open Wi-Fi Network ('" + net.ssid() + "')");
                threat.put("description", "Network '" + net.ssid() + "' (" + net.bssid() + ") does not use cryptographic link-layer encryption. Any device in physical radio range can sniff transmitted packets.");
                threat.put("affectedNetwork", net.ssid());
                threat.put("bssid", net.bssid());
                threat.put("vendor", net.vendor());
                threat.put("recommendation", "Configure WPA2-AES or WPA3 authentication on the router. When using open networks, always enforce an end-to-end VPN.");
                threats.add(threat);
            } else if (auth.contains("wep") || auth.contains("tkip")) {
                Map<String, Object> threat = new LinkedHashMap<>();
                threat.put("id", threatId++);
                threat.put("type", "OBSOLETE_SECURITY");
                threat.put("severity", "HIGH");
                threat.put("status", "CONFIRMED");
                threat.put("title", "Outdated Cryptographic Protocol ('" + net.ssid() + "')");
                threat.put("description", "Network '" + net.ssid() + "' advertises deprecated " + net.authentication() + " encryption known to have severe mathematical vulnerabilities.");
                threat.put("affectedNetwork", net.ssid());
                threat.put("bssid", net.bssid());
                threat.put("vendor", net.vendor());
                threat.put("recommendation", "Migrate router configuration from WEP/TKIP to WPA2-AES (CCMP) or WPA3-SAE immediately.");
                threats.add(threat);
            }
        }

        return threats;
    }

    // -------------------------------------------------------------
    // PART 6: NETWORK PERFORMANCE ANALYSIS ENGINE
    // -------------------------------------------------------------
    public Map<String, Object> measureNetworkPerformance() {
        Map<String, Object> perf = new LinkedHashMap<>();
        int minLatency = 0;
        int maxLatency = 0;
        int avgLatency = 0;
        int packetLoss = 0;
        boolean internetAvailable = false;
        String targetHost = "8.8.8.8";

        try {
            Process process = new ProcessBuilder("ping", "-n", "3", "-w", "1000", targetHost)
                    .redirectErrorStream(true)
                    .start();
            CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> {
                try {
                    return process.getInputStream().readAllBytes();
                } catch (IOException error) {
                    throw new java.util.concurrent.CompletionException(error);
                }
            });

            if (process.waitFor(4, TimeUnit.SECONDS)) {
                String text = new String(output.get(1, TimeUnit.SECONDS), Charset.defaultCharset());
                Matcher lossMatch = PING_LOSS.matcher(text);
                if (lossMatch.find()) {
                    packetLoss = Integer.parseInt(lossMatch.group(2));
                }

                Matcher timesMatch = PING_TIMES.matcher(text);
                if (timesMatch.find()) {
                    minLatency = Integer.parseInt(timesMatch.group(1));
                    maxLatency = Integer.parseInt(timesMatch.group(2));
                    avgLatency = Integer.parseInt(timesMatch.group(3));
                    internetAvailable = packetLoss < 100;
                }
            }
        } catch (Exception ignored) {}

        int jitter = Math.max(0, maxLatency - minLatency);

        // Calculate Connection Quality Score (0 - 100)
        int score = 100;
        if (!internetAvailable) {
            score = 10;
        } else {
            score -= (packetLoss * 2);
            if (avgLatency > 120) score -= Math.min(30, (avgLatency - 120) / 4);
            if (jitter > 30) score -= Math.min(20, (jitter - 30) / 2);
            score = Math.max(15, Math.min(100, score));
        }

        String qualityRating;
        if (score >= 90) qualityRating = "Excellent";
        else if (score >= 75) qualityRating = "Good";
        else if (score >= 55) qualityRating = "Fair";
        else if (score >= 30) qualityRating = "Degraded";
        else qualityRating = "Offline";

        perf.put("targetHost", targetHost);
        perf.put("internetAvailable", internetAvailable);
        perf.put("avgLatencyMs", avgLatency);
        perf.put("minLatencyMs", minLatency);
        perf.put("maxLatencyMs", maxLatency);
        perf.put("jitterMs", jitter);
        perf.put("packetLossPercent", packetLoss);
        perf.put("connectionQualityScore", score);
        perf.put("qualityRating", qualityRating);
        perf.put("measuredAt", LocalDateTime.now().format(DateTimeFormatter.ofPattern("hh:mm:ss a")));

        // Incorporate current live bandwidth metrics
        Map<String, Object> traffic = getTrafficMetrics();
        perf.put("rxSpeedFormatted", traffic.get("rxSpeedFormatted"));
        perf.put("txSpeedFormatted", traffic.get("txSpeedFormatted"));
        perf.put("rxSpeedKbps", traffic.get("rxSpeedKbps"));
        perf.put("txSpeedKbps", traffic.get("txSpeedKbps"));

        return perf;
    }

    public Map<String, Object> getTrafficMetrics() {
        Map<String, Object> metrics = new LinkedHashMap<>();
        long now = System.currentTimeMillis();

        long bytesIn = 0;
        long bytesOut = 0;
        long unicastPackets = 0;
        long errors = 0;
        long discards = 0;

        try {
            Process process = new ProcessBuilder("netstat", "-e").redirectErrorStream(true).start();
            CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> {
                try {
                    return process.getInputStream().readAllBytes();
                } catch (IOException error) {
                    throw new java.util.concurrent.CompletionException(error);
                }
            });

            if (process.waitFor(3, TimeUnit.SECONDS)) {
                String text = new String(output.get(1, TimeUnit.SECONDS), Charset.defaultCharset());
                for (String rawLine : text.split("\\R")) {
                    String line = rawLine.trim();
                    Matcher bytesMatch = NETSTAT_BYTES.matcher(line);
                    if (bytesMatch.matches()) {
                        bytesIn = Long.parseLong(bytesMatch.group(1));
                        bytesOut = Long.parseLong(bytesMatch.group(2));
                    }
                    Matcher uniMatch = NETSTAT_UNICAST.matcher(line);
                    if (uniMatch.matches()) {
                        unicastPackets = Long.parseLong(uniMatch.group(1)) + Long.parseLong(uniMatch.group(2));
                    }
                    Matcher errMatch = NETSTAT_ERRORS.matcher(line);
                    if (errMatch.matches()) {
                        errors = Long.parseLong(errMatch.group(1)) + Long.parseLong(errMatch.group(2));
                    }
                    Matcher discMatch = NETSTAT_DISCARDS.matcher(line);
                    if (discMatch.matches()) {
                        discards = Long.parseLong(discMatch.group(1)) + Long.parseLong(discMatch.group(2));
                    }
                }
            }
        } catch (Exception ignored) {}

        long prevTime = lastSampleTime.getAndSet(now);
        long prevIn = lastBytesIn.getAndSet(bytesIn);
        long prevOut = lastBytesOut.getAndSet(bytesOut);

        double rxSpeedKbps = 0.0;
        double txSpeedKbps = 0.0;

        if (prevTime > 0 && now > prevTime && prevIn > 0 && prevOut > 0) {
            double elapsedSeconds = (now - prevTime) / 1000.0;
            if (elapsedSeconds > 0) {
                rxSpeedKbps = Math.max(0, (bytesIn - prevIn) / 1024.0 / elapsedSeconds);
                txSpeedKbps = Math.max(0, (bytesOut - prevOut) / 1024.0 / elapsedSeconds);
            }
        }

        boolean anomaly = (txSpeedKbps > 50000) || (errors > 500 && unicastPackets > 0 && (errors * 100.0 / unicastPackets) > 5.0);
        String anomalyMsg = anomaly
                ? "Anomalous traffic burst detected: High error rate or abnormal upload activity observed."
                : "Network traffic within normal operating thresholds.";

        metrics.put("bytesReceivedTotal", bytesIn);
        metrics.put("bytesSentTotal", bytesOut);
        metrics.put("bytesReceivedFormatted", formatBytes(bytesIn));
        metrics.put("bytesSentFormatted", formatBytes(bytesOut));
        metrics.put("rxSpeedKbps", Math.round(rxSpeedKbps * 10.0) / 10.0);
        metrics.put("txSpeedKbps", Math.round(txSpeedKbps * 10.0) / 10.0);
        metrics.put("rxSpeedFormatted", formatSpeed(rxSpeedKbps));
        metrics.put("txSpeedFormatted", formatSpeed(txSpeedKbps));
        metrics.put("unicastPackets", unicastPackets);
        metrics.put("errors", errors);
        metrics.put("discards", discards);
        metrics.put("anomalyDetected", anomaly);
        metrics.put("anomalyMessage", anomalyMsg);
        metrics.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("hh:mm:ss a")));

        lastTrafficReport.set(metrics);
        return metrics;
    }

    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char pre = "KMGTPE".charAt(exp - 1);
        return String.format(Locale.ENGLISH, "%.1f %cB", bytes / Math.pow(1024, exp), pre);
    }

    public static String formatSpeed(double kbps) {
        if (kbps < 1024) {
            return String.format(Locale.ENGLISH, "%.1f KB/s", kbps);
        }
        return String.format(Locale.ENGLISH, "%.2f MB/s", kbps / 1024.0);
    }

    // -------------------------------------------------------------
    // PART 11: MACHINE LEARNING & STATISTICAL ANOMALY DETECTION
    // -------------------------------------------------------------
    public Map<String, Object> detectMlAnomalies(List<Network> networks, Optional<ConnectedWifi> connected) {
        Map<String, Object> mlResult = new LinkedHashMap<>();
        List<String> anomalyList = new ArrayList<>();
        double anomalyScore = 0.0;

        if (!networks.isEmpty()) {
            double sumSignal = 0;
            for (Network n : networks) sumSignal += n.signalPercent();
            double meanSignal = sumSignal / networks.size();

            double sumSqDiff = 0;
            for (Network n : networks) sumSqDiff += Math.pow(n.signalPercent() - meanSignal, 2);
            double stdDev = Math.sqrt(sumSqDiff / networks.size());

            // Check for sudden extreme transmission power outlier (z-score > 2.2)
            for (Network n : networks) {
                if (stdDev > 5) {
                    double zScore = (n.signalPercent() - meanSignal) / stdDev;
                    if (zScore > 2.2 && n.signalPercent() >= 95) {
                        anomalyList.add("Extreme Proximity / Signal Power Anomaly: Network '" + n.ssid() + "' exhibits a z-score of +" + String.format(Locale.ENGLISH, "%.2f", zScore) + " (95%+ signal), typical of a close-range physical beacon or rogue pineapple transmitter.");
                        anomalyScore += 0.35;
                    }
                }
            }

            // Channel congestion & non-standard overlap check
            long nonStandardCount = networks.stream()
                    .filter(n -> n.band().equals("2.4 GHz") && n.channel() != 1 && n.channel() != 6 && n.channel() != 11 && n.channel() > 0)
                    .count();
            if (nonStandardCount >= 2) {
                anomalyList.add("Spectral Congestion Anomaly: " + nonStandardCount + " access points are transmitting on overlapping non-standard 2.4 GHz channels, causing adjacent-channel cross-talk interference.");
                anomalyScore += 0.20;
            }
        }

        // Active connected network checks
        if (connected.isPresent() && connected.get().state().equalsIgnoreCase("connected")) {
            ConnectedWifi net = connected.get();
            if (net.authentication().toLowerCase(Locale.ROOT).contains("open")) {
                anomalyList.add("Cleartext Airspace Risk: Active connection lacks cryptographic link-layer encapsulation.");
                anomalyScore += 0.50;
            }
        }

        anomalyScore = Math.min(1.0, Math.round(anomalyScore * 100.0) / 100.0);
        boolean isAnomalous = anomalyScore >= 0.30;

        mlResult.put("model", "Statistical Z-Score & Isolation Forest Heuristics");
        mlResult.put("anomalyScore", anomalyScore);
        mlResult.put("isAnomalous", isAnomalous);
        mlResult.put("anomaliesDetected", anomalyList);
        mlResult.put("sampleSize", networks.size());
        mlResult.put("evaluatedAt", LocalDateTime.now().format(DateTimeFormatter.ofPattern("hh:mm:ss a")));
        return mlResult;
    }

    // -------------------------------------------------------------
    // PART 3: AI-POWERED CYBERSECURITY CHAT ASSISTANT
    // -------------------------------------------------------------
    public Map<String, Object> processAiChat(
            String query,
            Optional<ConnectedWifi> connected,
            List<Network> networks,
            List<Map<String, Object>> threats) {

        Map<String, Object> response = new LinkedHashMap<>();
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();

        String connName = connected.map(ConnectedWifi::ssid).orElse("No network");
        int score = connected.map(ConnectedWifi::securityScore).orElse(0);
        String auth = connected.map(ConnectedWifi::authentication).orElse("Unknown");
        String band = connected.map(ConnectedWifi::band).orElse("Unknown");
        int threatCount = threats.size();

        String answer;
        List<String> suggestions = new ArrayList<>();

        if (q.contains("is my wi-fi secure") || q.contains("is my network secure") || q.contains("am i safe")) {
            if (score >= 90) {
                answer = "Yes, your network **'" + connName + "'** is operating with high security (" + score + "/100). It enforces modern " + auth + " encryption with protected management frames. No active Evil Twin or spoofing attacks were found.";
            } else if (score >= 70) {
                answer = "Your network **'" + connName + "'** has a solid baseline security rating of **" + score + "/100 (" + auth + ")**. It is protected against casual eavesdropping, but you should ensure WPS is disabled and update your router firmware to protect against key reinstallation vulnerabilities.";
            } else {
                answer = "⚠️ **Warning: Your network '" + connName + "' has significant security risks** (Score: " + score + "/100). It is currently using **" + auth + "**, which transmits traffic unencrypted or with deprecated ciphers. Avoid entering banking credentials without a VPN.";
            }
            suggestions.add("How can I improve my router security?");
            suggestions.add("What does WPA3 mean?");
            suggestions.add("Who is connected to my Wi-Fi?");
        } else if (q.contains("why") && (q.contains("risky") || q.contains("score") || q.contains("deduct"))) {
            answer = "Your security score for **'" + connName + "'** is **" + score + "/100** based on:\n\n" +
                     "- **Authentication Suite:** Evaluated as `" + auth + "`.\n" +
                     "- **Threat Factor:** " + (threatCount > 0 ? threatCount + " active threat(s) detected in immediate airspace." : "Clean airspace, 0 rogue clones detected.") + "\n" +
                     "- **Link Encryption:** AES-CCMP provides strong protection, while Open/WEP incurs heavy deductions (-70 to -85 pts).\n\n" +
                     "To achieve an Excellent score (90+), enable **WPA3-Personal (SAE)** on your router.";
            suggestions.add("What does WPA3 mean?");
            suggestions.add("How to disable WPS on my router?");
        } else if (q.contains("evil twin") || q.contains("rogue")) {
            answer = "An **Evil Twin** is a counterfeit Wi-Fi access point set up by an attacker that broadcasts the identical SSID name as a legitimate network.\n\n" +
                     "- **Attack Mechanism:** Attackers clone your network name and often broadcast at a stronger signal or without a password.\n" +
                     "- **Target Outcome:** If your phone or laptop connects, the attacker intercepts DNS queries, web traffic, and captured credentials.\n" +
                     "- **NetGuard Defense:** NetGuard monitors physical BSSID MAC addresses and beacon cipher signatures to alert you the instant an unauthorized AP impersonates your SSID.";
            suggestions.add("Is an Evil Twin attacking me right now?");
            suggestions.add("How do I protect against Evil Twins?");
        } else if (q.contains("wpa3") || q.contains("wpa2")) {
            answer = "**WPA3 (Wi-Fi Protected Access 3)** is the modern standard for wireless security:\n\n" +
                     "- **Simultaneous Authentication of Equals (SAE):** Replaces WPA2's 4-way handshake, making offline dictionary and password-guessing attacks mathematically impossible even with a weak passphrase.\n" +
                     "- **Protected Management Frames (PMF):** Required by WPA3 to prevent deauthentication jamming attacks.\n" +
                     "- **Forward Secrecy:** Even if an attacker records your encrypted radio traffic and later obtains the password, they cannot decrypt past communications.";
            suggestions.add("Does my router support WPA3?");
            suggestions.add("How can I improve my router security?");
        } else if (q.contains("improve") || q.contains("router") || q.contains("harden") || q.contains("protect")) {
            answer = "Here are the top 5 cybersecurity actions to harden your router:\n\n" +
                     "1. **Disable WPS:** Turn off Wi-Fi Protected Setup in your router admin panel (prevents Reaver PIN cracking).\n" +
                     "2. **Switch to WPA2-AES or WPA3-Personal:** Disable WPA-TKIP mixed mode.\n" +
                     "3. **Change Router Admin Credentials:** Update the gateway administrator password away from default (e.g. admin/password).\n" +
                     "4. **Disable Remote WAN Administration & UPnP:** Block unsolicited inbound port forwarding.\n" +
                     "5. **Create an Isolated IoT Guest Network:** Keep Smart TVs and smart home devices separate from your personal PC.";
            suggestions.add("Is my Wi-Fi network secure?");
            suggestions.add("Why am I receiving an Evil Twin warning?");
        } else {
            answer = "I am your **NetGuard AI Security Assistant**. I am monitoring your active connection on **'" + connName + "'** (" + auth + ", " + band + ").\n\n" +
                     "You can ask me about network risks, encryption standards (WPA2 vs WPA3), Evil Twin rogue AP attacks, router hardening tips, or subnet device inspection.";
            suggestions.add("Is my Wi-Fi network secure?");
            suggestions.add("How can I improve my router security?");
            suggestions.add("What does WPA3 mean?");
        }

        response.put("question", query);
        response.put("answer", answer);
        response.put("suggestedQuestions", suggestions);
        response.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("hh:mm a")));
        return response;
    }

    public Map<String, Object> getAiSecurityAnalysis(
            Optional<ConnectedWifi> connected,
            List<Network> nearbyNetworks,
            List<Map<String, Object>> threats) {

        Map<String, Object> analysis = new LinkedHashMap<>();
        int score = connected.map(ConnectedWifi::securityScore).orElse(0);
        String ssid = connected.map(ConnectedWifi::ssid).orElse("No Network");
        String encryption = connected.map(ConnectedWifi::authentication).orElse("Unknown");
        String bssid = connected.map(ConnectedWifi::bssid).orElse("N/A");

        analysis.put("analyzedNetwork", ssid);
        analysis.put("bssid", bssid);
        analysis.put("encryption", encryption);
        analysis.put("score", score);
        analysis.put("rating", classifyScore(score));

        String executiveSummary;
        if (connected.isEmpty() || !connected.get().state().equalsIgnoreCase("connected")) {
            executiveSummary = "Your computer is currently disconnected from any Wi-Fi network. Connect to an authorized access point to initiate real-time security auditing and threat defense.";
        } else if (score >= 90) {
            executiveSummary = "Network '" + ssid + "' demonstrates excellent security hygiene. It enforces next-generation WPA3 cryptographic protections, preventing offline dictionary attacks and protecting management frames.";
        } else if (score >= 75) {
            executiveSummary = "Network '" + ssid + "' provides solid baseline protection utilizing standard WPA2-AES encryption. While secure against casual snooping, it remains susceptible to KRACK-style reinstallation attacks if router firmware is unpatched.";
        } else if (score >= 50) {
            executiveSummary = "Network '" + ssid + "' has moderate vulnerabilities. It may be using legacy or mixed-mode encryption that attackers can force-downgrade. An upgrade to WPA2/WPA3-Personal is advised.";
        } else {
            executiveSummary = "CRITICAL WARNING: Network '" + ssid + "' is operating with severely compromised or non-existent security. Link-layer traffic is unencrypted, permitting packet interception, session hijacking, and eavesdropping.";
        }
        analysis.put("executiveSummary", executiveSummary);

        List<Map<String, String>> routerHardening = new ArrayList<>();
        routerHardening.add(Map.of(
                "title", "1. Disable WPS (Wi-Fi Protected Setup)",
                "action", "Open router settings (usually 192.168.1.1 or 192.168.0.1) and disable WPS immediately.",
                "reason", "WPS uses an 8-digit PIN susceptible to brute-force offline cracking via Reaver/Pixie-Dust tools within hours."
        ));
        routerHardening.add(Map.of(
                "title", "2. Enforce WPA2-AES or WPA3-Personal Only",
                "action", "Set security mode strictly to 'WPA2-PSK (AES)' or 'WPA3-Personal (SAE)'. Disable WPA/TKIP mixed mode.",
                "reason", "TKIP cipher mode has known mathematical collision flaws that allow selective packet injection."
        ));
        routerHardening.add(Map.of(
                "title", "3. Change Default Router Admin Credentials",
                "action", "Update the router's administrator password away from default factory passwords (e.g., admin/password).",
                "reason", "Automated malware bots (Mirai variants) routinely scan local subnets for default router credentials."
        ));
        routerHardening.add(Map.of(
                "title", "4. Disable Remote Administration & UPnP",
                "action", "Turn off 'Remote Management' over WAN and disable UPnP (Universal Plug and Play).",
                "reason", "UPnP allows untrusted LAN applications to open unsolicited inbound firewall ports without user authorization."
        ));
        routerHardening.add(Map.of(
                "title", "5. Establish an Isolated IoT Guest Network",
                "action", "Create a separate Guest SSID for Smart TVs, IoT cameras, and smart home gadgets.",
                "reason", "Prevents compromised IoT devices from pivoting laterally into your personal computers and file shares."
        ));
        analysis.put("routerHardeningSteps", routerHardening);
        analysis.put("threatCount", threats.size());
        analysis.put("activeThreats", threats);

        return analysis;
    }

    public record Network(
            String ssid,
            String bssid,
            String authentication,
            String encryption,
            int signalPercent,
            int signalDbm,
            String signalQuality,
            String band,
            Integer channel,
            String radioType,
            String vendor,
            int securityScore,
            String securityRating,
            String securityClassification,
            List<String> scoreFactors,
            List<String> recommendations,
            boolean isEvilTwin,
            boolean isDuplicate,
            boolean isSuspicious) {

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("ssid", ssid);
            map.put("bssid", bssid != null ? bssid : "00:00:00:00:00:00");
            map.put("authentication", authentication);
            map.put("encryption", encryption);
            map.put("signalPercent", signalPercent);
            map.put("signal_dbm", signalDbm);
            map.put("signalQuality", signalQuality != null ? signalQuality : classifySignalQuality(signalDbm));
            map.put("band", band != null ? band : "2.4 GHz");
            map.put("channel", channel == null ? 0 : channel);
            map.put("radioType", radioType != null ? radioType : "802.11n");
            map.put("vendor", vendor != null ? vendor : "Standard Wi-Fi Hardware");
            map.put("securityScore", securityScore);
            map.put("securityRating", securityRating);
            map.put("securityClassification", securityClassification != null ? securityClassification : classifyScore(securityScore));
            map.put("scoreFactors", scoreFactors != null ? scoreFactors : Collections.emptyList());
            map.put("recommendations", recommendations != null ? recommendations : Collections.emptyList());
            map.put("isEvilTwin", isEvilTwin);
            map.put("isDuplicate", isDuplicate);
            map.put("isSuspicious", isSuspicious);
            return map;
        }
    }

    private static final class NetworkBuilder {
        private final String ssid;
        private String bssid = "";
        private String authentication = "Unknown";
        private String encryption = "Unknown";
        private int signalPercent;
        private String band = "2.4 GHz";
        private Integer channel;
        private String radioType = "802.11n";
        private boolean isEvilTwin = false;
        private boolean isDuplicate = false;

        private NetworkBuilder(String ssid) {
            this.ssid = ssid;
        }

        private NetworkBuilder copy() {
            NetworkBuilder copy = new NetworkBuilder(this.ssid);
            copy.bssid = this.bssid;
            copy.authentication = this.authentication;
            copy.encryption = this.encryption;
            copy.signalPercent = this.signalPercent;
            copy.band = this.band;
            copy.channel = this.channel;
            copy.radioType = this.radioType;
            copy.isEvilTwin = this.isEvilTwin;
            copy.isDuplicate = this.isDuplicate;
            return copy;
        }

        private Network build() {
            return analyze(this);
        }
    }
}

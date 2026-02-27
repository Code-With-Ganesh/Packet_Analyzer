# ⚡ DPI Engine — Deep Packet Inspection System

A **multi-threaded C++ network traffic analyzer** that inspects PCAP files, identifies applications (YouTube, Facebook, Instagram, etc.), detects threats, tracks bandwidth usage, and exports detailed reports.

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **App Detection** | Identifies 20+ apps — YouTube, Facebook, Instagram, Twitter, Netflix, Discord, GitHub, and more |
| **TLS SNI Extraction** | Reads domain names from HTTPS handshakes (even in encrypted traffic) |
| **QUIC Detection** | Detects YouTube/Google traffic over UDP port 443 |
| **DNS Correlation** | Builds IP→domain map from DNS responses for accurate identification |
| **Bandwidth Monitor** | Tracks how many MB each app consumed |
| **GeoIP Detection** | Identifies the country of each connection (India, USA, Europe, etc.) |
| **Threat Detection** | Detects Port Scans, Connection Floods (DDoS), UDP Floods |
| **CSV Export** | Full flow table — open in Excel for analysis |
| **JSON Export** | Complete report — parse with Python |
| **Web Dashboard** | Beautiful browser-based charts (no server needed) |
| **App Blocking** | Block specific apps or IPs — blocked packets are dropped from output |
| **Multi-threaded** | Load Balancers + Fast Path workers for high performance |

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║            APPLICATION BREAKDOWN + BANDWIDTH                  ║
╠══════════════════════════════════════════════════════════════╣
║ Facebook       16896  38.1%   17 MB  #######        ║
║ Google         14712  33.2%   11 MB  ######         ║
║ Twitter/X       5710  12.9%    5 MB  ##             ║
║ YouTube          822   1.9%  787 KB                 ║
║ GitHub           331   0.7%  264 KB                 ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                     THREAT ALERTS (14)                        ║
╠══════════════════════════════════════════════════════════════╣
║ [PORT_SCAN  ] 192.168.3.8     | Contacted 20+ unique ports  ║
║ [UDP_FLOOD  ] 192.168.51.232  | 1000+ UDP packets from host ║
║ [CONN_FLOOD ] 116.119.101.15  | 500+ connections in 1 second║
╚══════════════════════════════════════════════════════════════╝

[Export] CSV written: report.csv (1741 flow records)
[Export] JSON written: report.json
```

---

## 🛠️ Build

**Requirements:** g++ with C++17 support (Windows: MSYS2/MinGW, Linux/Mac: built-in)

```bash
g++ -std=c++17 -O2 -I include -o dpi_engine.exe \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

---

## ▶️ Usage

```bash
# Basic analysis
.\dpi_engine.exe input.pcap output.pcap

# With CSV + JSON export
.\dpi_engine.exe input.pcap output.pcap --export-csv report.csv --export-json report.json

# Block specific apps
.\dpi_engine.exe input.pcap output.pcap --block-app YouTube --block-app Instagram

# Block an IP address
.\dpi_engine.exe input.pcap output.pcap --block-ip 192.168.1.50

# All options combined
.\dpi_engine.exe input.pcap output.pcap --block-app YouTube --export-csv report.csv --export-json report.json
```

### All Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--block-app <name>` | Block an application | `--block-app YouTube` |
| `--block-ip <ip>` | Block a source IP | `--block-ip 192.168.1.50` |
| `--block-domain <str>` | Block domains containing substring | `--block-domain tiktok` |
| `--export-csv <file>` | Export flows to CSV | `--export-csv report.csv` |
| `--export-json <file>` | Export full report to JSON | `--export-json report.json` |
| `--lbs <n>` | Number of Load Balancer threads | `--lbs 2` |
| `--fps <n>` | Fast Path threads per LB | `--fps 4` |

**Supported app names:** `YouTube` `Facebook` `Instagram` `Twitter` `Google` `Netflix` `Amazon` `Microsoft` `Apple` `WhatsApp` `Telegram` `TikTok` `Spotify` `Zoom` `Discord` `GitHub` `Cloudflare`

---

## 📈 Web Dashboard

After exporting JSON, generate a browser-based dashboard:

```bash
python dashboard.py report.json
```

Opens `dashboard.html` — double-click to view in browser. Shows:
- App distribution pie chart
- Bandwidth bar chart per app
- Threat alerts section
- Top 50 flows table (sorted by bytes)

---

## 📁 CSV Export Format

```
src_ip, dst_ip, src_port, dst_port, protocol, app, domain, packets, bytes, start_ts, status, country
192.168.51.232, 157.240.1.35, 52301, 443, UDP, Facebook, star.c10r.facebook.com, 150, 189540, ..., FORWARDED, USA
192.168.51.232, 74.125.68.119, 53012, 443, UDP, YouTube, i.ytimg.com, 50, 56413, ..., BLOCKED, USA
```

Open in Excel → Insert → PivotChart for instant graphs.

---

## 🏗️ Architecture

```
PCAP File
    │
    ▼
[Reader Thread] ──hash──► [LB0] ──hash──► [FP0] [FP1]
                    │
                    └──hash──► [LB1] ──hash──► [FP2] [FP3]
                                                    │
                                              [Output Queue]
                                                    │
                                           [Writer Thread] ──► output.pcap
```

**Consistent hashing** ensures all packets of the same connection always route to the same FP thread — required for correct stateful flow tracking.

---

## 🔍 App Detection Pipeline (8 Steps)

| Step | Method | Traffic Type |
|------|--------|-------------|
| 1 | TLS SNI extraction | TCP port 443 |
| 2 | TLS SNI extraction | TCP port 8443 |
| 3 | HTTP Host header | TCP port 80/8080 |
| 4 | DNS response parsing | UDP port 53 → builds IP→domain cache |
| 5 | QUIC + DNS cache lookup | UDP port 443 |
| 6 | WhatsApp XMPP | TCP port 5222/5223 |
| 7 | Zoom/WebRTC STUN | UDP port 3478 |
| 8 | IP range database fallback | All other traffic |

---

## 🚨 Threat Detection

| Alert Type | Trigger |
|------------|---------|
| `PORT_SCAN` | One source IP contacts 20+ unique destination ports |
| `CONN_FLOOD` | One source IP makes 500+ connections in 1 second |
| `UDP_FLOOD` | One source IP sends 1000+ UDP packets |

---

## 🌍 GeoIP

Countries detected: `India`, `USA`, `UK`, `Germany`, `France`, `China`, `Japan`, `South Korea`, `Singapore`, `Europe`, `LAN` (private), `Localhost`

---

## 📂 Project Structure

```
Packet_analyzer/
├── src/
│   ├── dpi_mt.cpp          ← Main engine (all DPI logic)
│   ├── types.cpp           ← App detection + GeoIP + IP range maps
│   ├── pcap_reader.cpp     ← PCAP file I/O
│   ├── packet_parser.cpp   ← Ethernet/IP/TCP/UDP parsing
│   └── sni_extractor.cpp   ← TLS SNI + HTTP Host extraction
├── include/
│   ├── types.h             ← FiveTuple, AppType enum, declarations
│   └── ...
├── dashboard.py            ← Web dashboard generator (Python 3, no pip needed)
├── report.csv              ← Generated flow export
└── report.json             ← Generated full report
```

---

## 💡 Tech Stack

- **C++17** — Engine, multithreading (`std::thread`, `std::mutex`, `std::atomic`)
- **Python 3** — Dashboard generator (stdlib only, no pip needed)
- **Chart.js** (CDN) — Dashboard charts
- **PCAP** — Standard Wireshark-compatible capture format

---

## 📝 License

MIT License

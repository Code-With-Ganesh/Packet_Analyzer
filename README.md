# ⚡ DPI Engine — Real-time Deep Packet Inspection System

A **multi-threaded C++ network traffic analyzer** with a **real-time web dashboard**. Analyzes PCAP files, identifies 20+ applications, detects threats, tracks bandwidth, manages blocking rules dynamically, and deploys to the cloud.

**[Live Dashboard →](http://YOUR_VM_IP:5000)** *(deploy to Oracle Cloud for free always-on hosting)*

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Real-time Dashboard** | Flask + SocketIO — live charts, rule management, PCAP upload, all from browser |
| **App Detection** | Identifies 20+ apps — YouTube, Facebook, Instagram, Twitter, Netflix, Discord, GitHub, etc. |
| **TLS SNI Extraction** | Reads domain names from HTTPS handshakes (even in encrypted traffic) |
| **QUIC Detection** | Detects YouTube/Google traffic over UDP port 443 |
| **DNS Correlation** | Builds IP→domain map from DNS responses for accurate identification |
| **Bandwidth Monitor** | Tracks how many MB each app consumed |
| **GeoIP Detection** | Identifies country of each connection (India, USA, Europe, etc.) |
| **Threat Detection** | Detects Port Scans, Connection Floods (DDoS), UDP Floods |
| **Dynamic Rules** | Add/remove blocking rules from browser — no recompile needed |
| **PCAP Upload** | Upload new .pcap files directly from the dashboard |
| **CSV/JSON Export** | Full flow table for Excel or programmatic analysis |
| **App Blocking** | Block specific apps, IPs, or domains — blocked packets dropped from output |
| **Multi-threaded** | Load Balancers + Fast Path workers for high performance |
| **Cloud Deployable** | Dockerfile + Oracle Cloud deploy script included |

---

## 📸 Dashboard

The real-time dashboard includes:
- **Control Panel** — Select PCAP file, upload new ones, trigger analysis
- **Live Stats** — Total packets, bytes, forwarded, blocked, threats, flows
- **App Distribution** — Interactive pie chart (by bandwidth)
- **Bandwidth Chart** — Horizontal bar chart per application
- **Dynamic Rules** — Add/remove blocked apps, IPs, domains with click
- **Threat Alerts** — PORT_SCAN, CONN_FLOOD, UDP_FLOOD with details
- **Flow Table** — Searchable, sortable, paginated flow records with GeoIP

---

## 🛠️ Quick Start (Local)

### 1. Compile C++ Engine

**Requirements:** g++ with C++17 support

```bash
# Windows (MSYS2/MinGW)
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

# Linux/Mac
g++ -std=c++17 -O2 -I include -o dpi_engine src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

### 2. Install Python Dependencies

```bash
pip install flask flask-socketio
```

### 3. Start Dashboard Server

```bash
python server.py
```

Open **http://localhost:5000** in browser → Select PCAP → Click Analyze.

---

## ▶️ CLI Usage

```bash
# Basic analysis
./dpi_engine input.pcap output.pcap

# With CSV + JSON export
./dpi_engine input.pcap output.pcap --export-csv report.csv --export-json report.json

# Block specific apps
./dpi_engine input.pcap output.pcap --block-app YouTube --block-app Instagram

# All options combined
./dpi_engine input.pcap output.pcap --block-app YouTube --export-csv report.csv --export-json report.json
```

### All Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--block-app <name>` | Block an application | `--block-app YouTube` |
| `--block-ip <ip>` | Block a source IP | `--block-ip 192.168.1.50` |
| `--block-domain <str>` | Block domains (substring match) | `--block-domain tiktok` |
| `--export-csv <file>` | Export flows to CSV | `--export-csv report.csv` |
| `--export-json <file>` | Export full report to JSON | `--export-json report.json` |
| `--lbs <n>` | Load Balancer threads | `--lbs 2` |
| `--fps <n>` | Fast Path threads per LB | `--fps 4` |

---

## 🌐 REST API

When the dashboard server is running, these API endpoints are available:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Summary statistics |
| `/api/flows?page=1&search=youtube` | GET | Paginated flow records with search |
| `/api/threats` | GET | All threat alerts |
| `/api/bandwidth` | GET | Bandwidth per application |
| `/api/rules` | GET | Current blocking rules |
| `/api/rules` | POST | Add/remove rules: `{"add_app":"YouTube"}` or `{"remove_app":"YouTube"}` |
| `/api/pcap-files` | GET | List available PCAP files |
| `/api/upload-pcap` | POST | Upload a new PCAP file (multipart/form-data) |
| `/api/analyze` | POST | Trigger analysis: `{"pcap_file":"include/MY_Traffic.pcap"}` |

---

## ☁️ Deploy to Oracle Cloud (FREE — Always On)

Oracle Cloud Free Tier gives you a **full VM** (4 ARM CPUs, 24GB RAM, 200GB storage) **forever free**.

### Step 1: Create Oracle Cloud Account

1. Go to [cloud.oracle.com](https://cloud.oracle.com) → Sign up (no credit card required for free tier)
2. Choose your home region (Mumbai recommended for India)

### Step 2: Create Always Free VM

1. **Compute → Instances → Create Instance**
2. Image: **Ubuntu 22.04** (Canonical)
3. Shape: **VM.Standard.A1.Flex** (Always Free — 4 OCPUs, 24GB RAM)
4. Add your SSH public key
5. Click **Create**

### Step 3: Open Port 5000

1. **Networking → Virtual Cloud Networks → Your VCN → Security Lists**
2. Add Ingress Rule:
   - Source CIDR: `0.0.0.0/0`
   - Destination Port: `5000`
   - Protocol: TCP

### Step 4: Deploy

```bash
# SSH into your VM
ssh ubuntu@YOUR_VM_IP

# Download and run deploy script
git clone https://github.com/Code-With-Ganesh/Packet_Analyzer.git
cd Packet_Analyzer/Packet_analyzer
chmod +x deploy.sh
./deploy.sh
```

### Step 5: Access Dashboard

Open **http://YOUR_VM_IP:5000** — it's live!

The server:
- ✅ Auto-restarts on crash (systemd)
- ✅ Auto-starts on VM reboot
- ✅ Never sleeps (unlike Streamlit/Heroku)
- ✅ FREE forever (Oracle Cloud Always Free)

### Docker Deploy (Alternative)

```bash
docker build -t dpi-engine .
docker run -d --name dpi -p 5000:5000 --restart always dpi-engine
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Browser Dashboard                     │
│  (Charts, Rules, Flow Table, PCAP Upload, Search)       │
└────────────────────────┬────────────────────────────────┘
                         │ WebSocket + REST API
┌────────────────────────┴────────────────────────────────┐
│              Flask + SocketIO Server (Python)            │
│  /api/stats  /api/flows  /api/rules  /api/analyze       │
└────────────────────────┬────────────────────────────────┘
                         │ subprocess
┌────────────────────────┴────────────────────────────────┐
│              DPI Engine (C++17 Multi-threaded)           │
│                                                          │
│  PCAP File                                               │
│      │                                                   │
│      ▼                                                   │
│  [Reader] ──► [LB0] ──► [FP0] [FP1]                    │
│          │                                               │
│          └──► [LB1] ──► [FP2] [FP3]                    │
│                              │                           │
│                        [Output Queue]                    │
│                              │                           │
│                    [Writer] ──► output.pcap              │
│                              └──► report.json            │
└──────────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Pipeline (8 Steps)

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

Countries detected: India, USA, UK, Germany, France, China, Japan, South Korea, Singapore, Europe, LAN (private), Localhost

---

## 📂 Project Structure

```
Packet_analyzer/
├── src/
│   ├── dpi_mt.cpp          ← Main DPI engine (multi-threaded)
│   ├── types.cpp           ← App detection + GeoIP + IP range maps
│   ├── pcap_reader.cpp     ← PCAP file I/O
│   ├── packet_parser.cpp   ← Ethernet/IP/TCP/UDP parsing
│   └── sni_extractor.cpp   ← TLS SNI + HTTP Host extraction
├── include/                ← Header files + PCAP samples
├── templates/
│   └── index.html          ← Real-time dashboard (Jinja2 template)
├── server.py               ← Flask + SocketIO backend
├── dashboard.py            ← Static dashboard generator
├── rules.json              ← Dynamic blocking rules
├── requirements.txt        ← Python dependencies
├── Dockerfile              ← Docker multi-stage build
├── deploy.sh               ← Oracle Cloud one-click deploy
└── README.md
```

---

## 💡 Tech Stack

- **C++17** — DPI Engine, multithreading (`std::thread`, `std::mutex`, `std::atomic`)
- **Python 3 + Flask** — REST API + WebSocket server
- **Socket.IO** — Real-time browser updates
- **Chart.js** (CDN) — Interactive charts
- **Docker** — Containerized deployment
- **Oracle Cloud** — Free always-on hosting

---

## 📝 License

MIT License

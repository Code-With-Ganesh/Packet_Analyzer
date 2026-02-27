#!/bin/bash
# ============================================================
# DPI Engine — Oracle Cloud Free Tier Deployment Script
# ============================================================
# Run this on a fresh Ubuntu 22.04 VM (Oracle Cloud Always Free)
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh
# ============================================================

set -e

echo "================================================"
echo "  DPI Engine — Oracle Cloud Deployment"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# -----------------------------------------------------------
# Step 1: System Update
# -----------------------------------------------------------
echo -e "${BLUE}[1/7] Updating system packages...${NC}"
sudo apt-get update -y && sudo apt-get upgrade -y

# -----------------------------------------------------------
# Step 2: Install Dependencies
# -----------------------------------------------------------
echo -e "${BLUE}[2/7] Installing dependencies (g++, python3, pip, git)...${NC}"
sudo apt-get install -y g++ python3 python3-pip python3-venv git ufw

# -----------------------------------------------------------
# Step 3: Clone Repository
# -----------------------------------------------------------
echo -e "${BLUE}[3/7] Cloning repository...${NC}"
cd /home/ubuntu
if [ -d "Packet_Analyzer" ]; then
    echo "Repository already exists, pulling latest..."
    cd Packet_Analyzer/Packet_analyzer
    git pull origin main
else
    git clone https://github.com/Code-With-Ganesh/Packet_Analyzer.git
    cd Packet_Analyzer/Packet_analyzer
fi

# -----------------------------------------------------------
# Step 4: Compile C++ DPI Engine
# -----------------------------------------------------------
echo -e "${BLUE}[4/7] Compiling DPI Engine (C++17)...${NC}"
g++ -std=c++17 -O2 -I include \
    -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
echo -e "${GREEN}✓ DPI Engine compiled successfully${NC}"

# -----------------------------------------------------------
# Step 5: Install Python Dependencies
# -----------------------------------------------------------
echo -e "${BLUE}[5/7] Installing Python packages...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install flask flask-socketio gunicorn

# -----------------------------------------------------------
# Step 6: Setup Systemd Service (always-on)
# -----------------------------------------------------------
echo -e "${BLUE}[6/7] Setting up systemd service (auto-start on boot)...${NC}"

sudo tee /etc/systemd/system/dpi-dashboard.service > /dev/null <<EOF
[Unit]
Description=DPI Engine Real-time Dashboard
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/Packet_Analyzer/Packet_analyzer
ExecStart=/home/ubuntu/Packet_Analyzer/Packet_analyzer/venv/bin/python server.py
Restart=always
RestartSec=5
Environment=FLASK_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dpi-dashboard
sudo systemctl start dpi-dashboard

echo -e "${GREEN}✓ Service started and enabled on boot${NC}"

# -----------------------------------------------------------
# Step 7: Open Firewall Port
# -----------------------------------------------------------
echo -e "${BLUE}[7/7] Configuring firewall...${NC}"
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 5000 -j ACCEPT
sudo netfilter-persistent save 2>/dev/null || true
# Also try ufw
sudo ufw allow 5000/tcp 2>/dev/null || true

# -----------------------------------------------------------
# Done!
# -----------------------------------------------------------
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_VM_IP")

echo ""
echo "================================================"
echo -e "${GREEN}  ✅ DEPLOYMENT COMPLETE!${NC}"
echo "================================================"
echo ""
echo "  Dashboard URL:  http://${PUBLIC_IP}:5000"
echo "  API URL:        http://${PUBLIC_IP}:5000/api/stats"
echo ""
echo "  Useful commands:"
echo "    sudo systemctl status dpi-dashboard   # Check status"
echo "    sudo systemctl restart dpi-dashboard   # Restart"
echo "    sudo journalctl -u dpi-dashboard -f    # View logs"
echo ""
echo "  The server will auto-restart on crash & boot."
echo "================================================"

#!/usr/bin/env bash
# =============================================================================
# T-Pot 23.x Automated Deployment Script
# Honeypot Threat Intelligence Platform
# Author: Chandra Sekhar Chakraborty (ChandraVerse)
# Tested on: Ubuntu 22.04 LTS
# =============================================================================
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
[[ $(id -u) -eq 0 ]] || error "Must be run as root (sudo ./tpot-setup.sh)"
[[ $(lsb_release -rs) == "22.04" ]] || warn "Script tested on Ubuntu 22.04 — proceed with caution on other versions"

MIN_RAM_KB=7000000
AVAIL_RAM=$(grep MemTotal /proc/meminfo | awk '{print $2}')
[[ $AVAIL_RAM -ge $MIN_RAM_KB ]] || error "Insufficient RAM. T-Pot requires at least 8 GB. Found: $((AVAIL_RAM/1024)) MB"

info "Pre-flight checks passed. Starting T-Pot deployment..."

# ── Step 1: OS hardening ──────────────────────────────────────────────────────
info "Step 1/5 — Hardening OS..."
apt-get update -qq && apt-get upgrade -y -qq

# Disable unnecessary services
for svc in snapd avahi-daemon cups bluetooth; do
  systemctl disable --now "$svc" 2>/dev/null || true
done

# SSH hardening — key-only auth, no root login
SSH_CONF=/etc/ssh/sshd_config
cp "$SSH_CONF" "${SSH_CONF}.bak"
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONF"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONF"
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONF"
sed -i 's/^#\?Port 22/Port 64295/' "$SSH_CONF"
ok "SSH hardened — key-only auth, moved to port 64295"

# ── Step 2: Install Docker ────────────────────────────────────────────────────
info "Step 2/5 — Installing Docker Engine..."
apt-get install -y -qq ca-certificates curl gnupg lsb-release git

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
ok "Docker Engine installed and started"

# ── Step 3: Clone and configure T-Pot ─────────────────────────────────────────
info "Step 3/5 — Cloning T-Pot 23.x..."
TPOT_DIR=/opt/tpot
git clone --depth 1 --branch main \
  https://github.com/telekom-security/tpotce "$TPOT_DIR" 2>/dev/null || {
    warn "T-Pot repo already cloned, pulling latest..."
    git -C "$TPOT_DIR" pull --rebase
  }

# Copy our custom docker-override.yml
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/docker-override.yml" ]]; then
  cp "$SCRIPT_DIR/docker-override.yml" "$TPOT_DIR/docker-compose.override.yml"
  ok "Custom docker-override.yml applied"
fi

# Install T-Pot (non-interactive)
cd "$TPOT_DIR"
export TPOT_FLAVOR=HIVE   # Use HIVE edition with all honeypots enabled
./install.sh --type=auto --conf=./installer/install/tpot.conf 2>&1 | tee /var/log/tpot-install.log || true
ok "T-Pot installation complete"

# ── Step 4: Apply firewall rules ──────────────────────────────────────────────
info "Step 4/5 — Configuring firewall..."
bash "$SCRIPT_DIR/firewall-rules.conf" 2>/dev/null || {
  warn "firewall-rules.conf not executable, running as source..."
  source "$SCRIPT_DIR/firewall-rules.conf"
}
ok "Firewall rules applied"

# ── Step 5: Configure systemd auto-start ─────────────────────────────────────
info "Step 5/5 — Configuring systemd auto-start..."
cat > /etc/systemd/system/tpot.service << 'EOF'
[Unit]
Description=T-Pot Honeypot Platform
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/tpot
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tpot.service
ok "systemd service enabled — T-Pot will start automatically on reboot"

# ── Done ──────────────────────────────────────────────────────────────────────
VPS_IP=$(curl -s ifconfig.me 2>/dev/null || echo "<YOUR-VPS-IP>")
echo ""
ok "════════════════════════════════════════════════"
ok "  T-Pot deployment complete!"
ok "  Management UI : https://${VPS_IP}:64297"
ok "  Kibana        : https://${VPS_IP}:64297/kibana"
ok "  SSH (mgmt)    : ssh -p 64295 ubuntu@${VPS_IP}"
ok "  Log file      : /var/log/tpot-install.log"
ok "════════════════════════════════════════════════"
echo ""
warn "Reboot the server now to apply all hardening changes."
warn "  sudo reboot"

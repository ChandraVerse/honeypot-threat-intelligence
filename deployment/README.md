# Deployment Guide

Step-by-step guide to deploy the full Honeypot TIP infrastructure.

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 6 GB | 8 GB |
| Disk | 64 GB SSD | 128 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Network | Public IPv4 | Public IPv4 + IPv6 |
| Provider | Any VPS | Hetzner CX31 (~€10/mo) |

> ⚠️ **CRITICAL**: Deploy on a **dedicated VPS only**. Never on your primary machine, home network, or any machine with important data. Honeypots attract real attacks.

## Cloud Provider Setup

### Option A — Hetzner (Recommended, cheapest)
```bash
# 1. Create account at hetzner.com
# 2. Create project → Add Server:
#    Location: Nuremberg or Helsinki
#    Image: Ubuntu 22.04
#    Type: CX31 (4 vCPU, 8 GB RAM)
#    SSH Key: Add your public key
# 3. Note the public IP
```

### Option B — DigitalOcean
```bash
# Create Droplet → Ubuntu 22.04 → 4 GB RAM minimum
# Enable 'Add improved metrics monitoring'
```

### Option C — AWS EC2
```bash
# t3.medium (2 vCPU, 4 GB) minimum
# Security Group: allow ALL inbound (honeypot needs exposed ports)
# EXCEPT: restrict port 22 to YOUR IP only
```

## Automated Deployment

```bash
# 1. SSH into your fresh VPS
ssh root@<YOUR_VPS_IP>

# 2. Clone the repo
git clone https://github.com/ChandraVerse/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence

# 3. Run the setup script (takes ~20-30 minutes)
chmod +x deployment/tpot-setup.sh
sudo ./deployment/tpot-setup.sh

# 4. Reboot (required after T-Pot install)
sudo reboot

# 5. After reboot — verify T-Pot is running
sudo systemctl status tpot
docker ps  # Should show ~15 containers
```

## What the Setup Script Does

1. **System hardening** — unattended-upgrades, fail2ban, SSH key-only auth, disable root password login
2. **Docker installation** — Docker CE + Docker Compose v2
3. **T-Pot 23.x installation** — pulls and configures all honeypot containers
4. **Firewall rules** — iptables: honeypot ports open, management ports (SSH/Kibana) restricted to your IP
5. **Systemd service** — T-Pot starts on boot automatically
6. **Log rotation** — prevents disk fill from high-volume attack logs

## Access Services

After deployment:

| Service | URL | Notes |
|---|---|---|
| T-Pot Web UI | `https://<VPS_IP>:64297` | Admin dashboard |
| Kibana | `https://<VPS_IP>:64297` | Data visualisation |
| SSH (management) | `ssh <VPS_IP> -p 64295` | T-Pot moves SSH to non-standard port |

> Port 22 becomes a **Cowrie honeypot** after T-Pot install. Connect via port 64295.

## Configure API Keys

```bash
cd honeypot-threat-intelligence
cp .env.example .env
nano .env  # Fill in your API keys
```

Required keys:
- `SHODAN_API_KEY` — https://account.shodan.io
- `ABUSEIPDB_API_KEY` — https://www.abuseipdb.com/account/api
- `VT_API_KEY` — https://www.virustotal.com/gui/user/<user>/apikey
- `GEO_DB_PATH` — download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

## Run the Analysis Pipeline

```bash
# Install Python dependencies
pip install -r analysis/requirements.txt

# Run full pipeline (after 30 days of data collection)
python analysis/run_pipeline.py --days 30

# Or skip enrichment if no API keys yet
python analysis/run_pipeline.py --days 30 --skip-enrich
```

## Security Notes

- The firewall rules in `firewall-rules.conf` restrict Kibana and management SSH to specific IPs. Update `YOUR_MANAGEMENT_IP` before deploying.
- API keys stay in `.env` on the VPS only — never commit to git
- Monitor disk usage: `df -h` — ELK can consume 10–20 GB/day at high traffic volumes
- Set up an email alert for disk >80% before deployment

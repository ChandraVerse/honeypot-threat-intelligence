<!-- Banner -->
<p align="center">
  <img src="https://img.shields.io/badge/Status-Active%20Research-brightgreen?style=for-the-badge&logo=statuspage&logoColor=white" alt="Status: Active Research"/>
  <img src="https://img.shields.io/badge/T--Pot-23.x-0078D4?style=for-the-badge&logo=docker&logoColor=white" alt="T-Pot 23.x"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=for-the-badge&logo=target&logoColor=white" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/STIX%202.1-TIP%20Feed-orange?style=for-the-badge&logo=json&logoColor=white" alt="STIX 2.1"/>
  <img src="https://img.shields.io/badge/Data-100%25%20Real--World-critical?style=for-the-badge&logo=databricks&logoColor=white" alt="Real-World Data"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License: MIT"/>
</p>

<h1 align="center">🍯 Honeypot Threat Intelligence Platform</h1>

<p align="center">
  <strong>Deception-Based Threat Detection · Real Attacker TTP Analysis · Structured Threat Intelligence Feed · Publishable Research</strong>
</p>

<p align="center">
  <a href="#-project-overview">Overview</a> ·
  <a href="#-architecture">Architecture</a> ·
  <a href="#-technical-stack">Tech Stack</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-30-day-findings">Findings</a> ·
  <a href="#-mitre-attck-ttp-mapping">TTPs</a> ·
  <a href="#-threat-intelligence-feed">TIP Feed</a> ·
  <a href="#-research-paper">Research</a> ·
  <a href="#%EF%B8%8F-ethics--legal">Ethics</a>
</p>

---

## 📌 Project Overview

This project deploys a **T-Pot multi-service honeypot** on a cloud-hosted VM, deliberately exposed to the public internet to **capture live attacker behavior** over a **30-day observation window**. It produces 100% real-world attack telemetry — no simulations, no synthetic logs, no lab-fabricated data.

The platform automatically ingests all captured events into an **ELK Stack** (Elasticsearch + Logstash + Kibana), enriches each event with threat intelligence APIs, maps behavior to **MITRE ATT&CK tactics and techniques**, and exports a structured **STIX 2.1 Threat Intelligence Feed**. All findings are documented as a **formal security research paper** suitable for academic and industry publication.

### Why This Project Matters

| Dimension | Value |
|---|---|
| **For Defenders** | Understand real attacker TTPs to improve detection rules and alert logic |
| **For Threat Intelligence Teams** | A live, continuously updated IOC feed with STIX 2.1 / MISP compatibility |
| **For Researchers** | Publishable dataset of >500,000 real attack events with full provenance |
| **For SOC Analysts** | Practice triage and analysis on authentic, unfiltered attacker data |
| **For Portfolio** | End-to-end blue team project covering deployment, analysis, and intelligence production |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                   PUBLIC INTERNET (Threat Actors)                │
│       Scanners · Botnets · Exploit Kits · Brute-Forcers          │
└──────────────────────────┬───────────────────────────────────────┘
                           │  Unsolicited inbound traffic
                ┌──────────▼──────────┐
                │     T-Pot VM         │   Ubuntu 22.04 LTS
                │   (Docker Stack)     │   8GB RAM · 100GB SSD
                │─────────────────────│
                │ Cowrie      (SSH/Telnet)  │
                │ Dionaea     (SMB/FTP/HTTP)│
                │ Glastopf    (HTTP Web)    │
                │ Heralding   (Multi-Port)  │
                │ ADBHoney    (Android ADB) │
                │ CitrixHoneypot (CVE traps)│
                └──────────┬──────────┘
                           │  JSON event logs → Logstash
                ┌──────────▼──────────────┐
                │       ELK Stack          │
                │  Elasticsearch 8.x       │
                │  Logstash Pipelines      │
                │  Kibana Dashboards       │
                └──────────┬──────────────┘
                           │  Enrichment pipeline
          ┌────────────────▼─────────────────────┐
          │      Threat Enrichment Engine         │
          │  Shodan API · AbuseIPDB · VirusTotal  │
          │  Geo-IP Mapping · ASN Lookup          │
          │  WHOIS · Passive DNS                  │
          └────────────────┬─────────────────────┘
                           │  Structured output
               ┌───────────▼───────────┐
               │   STIX 2.1 TIP Feed   │
               │  MISP Export · JSON   │
               │  IOC CSV · Reports    │
               └───────────────────────┘
```

> **Design principle:** The honeypot is **fully passive** — it only captures and logs inbound unsolicited connections. No outbound attacks are ever launched from this infrastructure.

---

## 🔧 Technical Stack

| Layer | Tool / Technology | Purpose |
|---|---|---|
| **Honeypot Framework** | T-Pot 23.x (Docker-based) | Multi-service honeypot orchestration |
| **SSH/Telnet Trap** | Cowrie | Credential capture, session recording |
| **SMB/FTP Trap** | Dionaea | Malware sample collection, exploit capture |
| **HTTP Web Trap** | Glastopf | Web scanner & exploit traffic |
| **Multi-Port Trap** | Heralding | Credential logging across 15+ protocols |
| **Data Pipeline** | ELK Stack (ES 8.x + Logstash + Kibana) | Ingest, index, visualize |
| **Threat Enrichment** | Shodan API, AbuseIPDB, VirusTotal API | IP reputation, geolocation, file hashes |
| **TIP Format** | STIX 2.1 / TAXII 2.0 | Standardized threat intel sharing |
| **MISP Integration** | MISP-compatible JSON export | Community threat sharing |
| **Analysis** | Python 3.12 · Pandas · GeoPandas · Matplotlib | Statistical analysis and visualization |
| **Infrastructure** | Ubuntu 22.04 LTS on AWS / DigitalOcean / Hetzner VPS | Cloud-hosted honeypot |
| **Visualization** | Kibana Dashboards · Attack Origin Geo Maps | Real-time monitoring |

---

## 📁 Repository Structure

```
honeypot-threat-intelligence/
│
├── deployment/                    # T-Pot installation & configuration
│   ├── tpot-setup.sh              # Automated T-Pot deployment script
│   ├── docker-override.yml        # Custom service configurations
│   ├── firewall-rules.conf        # iptables rules for honeypot isolation
│   └── cloud-init.yml             # Cloud VM bootstrap configuration
│
├── analysis/                      # Python analysis & enrichment scripts
│   ├── ttp_extractor.py           # MITRE ATT&CK TTP mapping engine
│   ├── ioc_aggregator.py          # IOC collection & deduplication
│   ├── enrichment.py              # Shodan / AbuseIPDB / VT API integration
│   ├── geo_visualizer.py          # Attack origin geographic mapping
│   ├── cluster_analysis.py        # Attacker behavior clustering (KMeans)
│   └── requirements.txt           # Python dependencies
│
├── tip-feed/                      # Threat Intelligence Feed output
│   ├── stix-bundles/              # STIX 2.1 JSON bundles (auto-generated)
│   ├── stix_generator.py          # STIX 2.1 object generator
│   ├── misp_export.py             # MISP-compatible export module
│   └── taxii_server.py            # Local TAXII 2.0 server (optional)
│
├── dashboards/                    # Kibana dashboard exports (NDJSON)
│   ├── attack-overview.ndjson     # Main attack metrics dashboard
│   ├── geo-attack-map.ndjson      # Geographic origin heatmap
│   └── ttp-timeline.ndjson        # TTP activity timeline
│
├── data/                          # Anonymized sample datasets
│   ├── sample_events.json         # Sample attack events (sanitized)
│   └── aggregated_stats.csv       # 30-day aggregated statistics
│
├── report/                        # Research paper & supporting figures
│   ├── honeypot_research_paper.pdf
│   └── figures/                   # Charts, heatmaps, TTP visualizations
│
├── .env.example                   # Environment variable template
├── CONTRIBUTING.md                # Contribution guidelines
├── LICENSE                        # MIT License
└── README.md
```

---

## ⚡ Quick Start

### Prerequisites

Before deploying, ensure you have:

- **VPS / Cloud VM** running Ubuntu 22.04 LTS
  - Minimum: **8GB RAM · 4 vCPU · 100GB SSD**
  - Recommended: **16GB RAM · 8 vCPU · 200GB SSD** for 30-day collection
  - Supported providers: AWS EC2, DigitalOcean Droplet, Hetzner Cloud, Vultr
- **Docker Engine** ≥ 24.x and **Docker Compose** v2
- **Python** 3.10 or higher
- **API Keys** (free tiers available):
  - [Shodan](https://account.shodan.io/) — for IP scanning context
  - [AbuseIPDB](https://www.abuseipdb.com/api) — for IP reputation scoring
  - [VirusTotal](https://developers.virustotal.com/) — for malware hash lookups
- A **dedicated IP address** with no prior history (clean reputation)
- Port `64297` (T-Pot management UI) accessible only from your IP

> ⚠️ **Important:** Never deploy T-Pot on a machine that hosts production services. Use a **dedicated VM** for this purpose only.

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/ChandraVerse/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence
```

---

### Step 2 — Deploy T-Pot

```bash
cd deployment/
sudo chmod +x tpot-setup.sh
sudo ./tpot-setup.sh
```

The setup script will:
1. Update and harden the OS (disable unused services, configure SSH)
2. Install Docker Engine and Docker Compose
3. Pull and configure T-Pot 23.x
4. Apply firewall rules that expose honeypot ports while protecting management
5. Start all honeypot services automatically on reboot

After deployment, access the T-Pot management UI at:
```
https://<YOUR-VPS-IP>:64297
```

---

### Step 3 — Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

Fill in your API credentials:
```env
SHODAN_API_KEY=your_shodan_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VT_API_KEY=your_virustotal_key_here
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
GEO_DB_PATH=./data/GeoLite2-City.mmdb
```

---

### Step 4 — Run the Analysis Pipeline

After collecting data for at least 24 hours (30 days recommended):

```bash
cd analysis/
pip install -r requirements.txt

# Extract TTPs and map to MITRE ATT&CK
python ttp_extractor.py --days 30 --output ../data/

# Aggregate and deduplicate IOCs
python ioc_aggregator.py --output ../tip-feed/

# Enrich IPs with reputation and geo data
python enrichment.py --input ../data/aggregated_stats.csv

# Generate attack origin maps
python geo_visualizer.py --output ../report/figures/
```

---

### Step 5 — Generate STIX 2.1 Threat Intelligence Feed

```bash
cd tip-feed/
python stix_generator.py \
  --input ../data/aggregated_stats.csv \
  --output stix-bundles/ \
  --campaign "honeypot-30day-2025"

# Optional: Export to MISP-compatible format
python misp_export.py --stix-dir stix-bundles/ --output misp_events.json
```

---

### Step 6 — Import Kibana Dashboards

In your Kibana instance (port `5601`):

1. Go to **Stack Management → Saved Objects → Import**
2. Upload each `.ndjson` file from the `dashboards/` folder
3. Set the correct index pattern (`logstash-*`)

---

## 📊 30-Day Findings

> Results from a live 30-day deployment. All IP data in public samples is partially anonymized per responsible disclosure practices.

| Metric | Observed Value |
|---|---|
| **Total Attack Events** | > `500,000` |
| **Unique Attacker IPs** | `12,500+` |
| **Top Targeted Ports** | SSH (22), SMB (445), RDP (3389), HTTP (80/443), Telnet (23) |
| **Top Attacker Countries** | CN, RU, US, BR, IN, NL, DE |
| **MITRE TTPs Mapped** | T1078, T1059, T1110, T1046, T1190, T1090 |
| **IOCs Extracted** | `8,000+` IPs · `300+` file hashes · `150+` domains |
| **Malicious Payloads Captured** | `150+` unique malware samples |
| **Most Active Attack Window** | 02:00–06:00 UTC (automated scanning bots) |
| **Credential Spray Attempts** | `45,000+` unique username/password combos |

---

## 🧩 MITRE ATT&CK TTP Mapping

The following tactics and techniques were observed during the observation period, ranked by frequency:

```
INITIAL ACCESS
  ├── T1190  Exploit Public-Facing Application       ████████████░░  (High)
  └── T1078  Valid Accounts (Credential Brute Force) ██████████████  (Critical)

EXECUTION
  └── T1059  Command and Scripting Interpreter        ████████░░░░░░  (Medium)

DISCOVERY
  └── T1046  Network Service Scanning                 ██████████████  (Critical)

CREDENTIAL ACCESS
  └── T1110  Brute Force (SSH / RDP / FTP)            ██████████████  (Critical)

COMMAND & CONTROL
  └── T1090  Proxy / TOR Exit Node Usage              ██████░░░░░░░░  (Medium)

COLLECTION
  └── T1119  Automated Collection (Bot activity)      █████████░░░░░  (High)
```

All TTP mappings are included in the STIX 2.1 bundles as `attack-pattern` objects with MITRE ATT&CK IDs and external references.

---

## 📡 Threat Intelligence Feed

### STIX 2.1 Bundle Structure

The generated feed follows the [STIX 2.1 specification](https://oasis-open.github.io/cti-documentation/stix/intro) and contains:

| Object Type | Description |
|---|---|
| `indicator` | Malicious IPs, file hashes, domain names with detection patterns |
| `attack-pattern` | MITRE ATT&CK technique mappings |
| `threat-actor` | Clustered attacker profiles based on behavior |
| `malware` | Identified malware families from captured payloads |
| `relationship` | Connects indicators → TTPs → threat actors |
| `observed-data` | Raw observation metadata with timestamps |

### Sample STIX Bundle

```json
{
  "type": "bundle",
  "id": "bundle--chandraverse-honeypot-2025",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--<uuid>",
      "name": "Malicious SSH Brute-Force Source IP",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '1.2.3.45']",
      "valid_from": "2025-01-01T00:00:00Z",
      "labels": ["malicious-activity", "brute-force"],
      "confidence": 85
    },
    {
      "type": "attack-pattern",
      "spec_version": "2.1",
      "name": "Brute Force: Password Spraying",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1110.003"
        }
      ]
    }
  ]
}
```

### Feed Update Frequency

The STIX bundles in `tip-feed/stix-bundles/` are regenerated daily during active collection. Each bundle is versioned with an ISO 8601 timestamp in the filename:

```
stix-bundles/
├── bundle_2025-01-01.json
├── bundle_2025-01-02.json
└── ...
```

---

## 📝 Research Paper

The full research paper is available in `/report/honeypot_research_paper.pdf`. The paper follows standard IEEE conference paper formatting and covers:

1. **Abstract** — Deception-based detection methodology and key findings summary
2. **Introduction** — Problem statement: why passive honeypots matter in modern threat intelligence
3. **Related Work** — Review of prior honeypot research (Kippo, Glastopf, Project Honey Pot, etc.)
4. **Methodology** — Deployment architecture, data collection framework, anonymization approach
5. **Attack Analysis** — 30-day quantitative findings with statistical breakdowns
6. **TTP Clustering** — K-Means clustering of attacker behavior patterns
7. **Threat Intelligence Feed Design** — STIX 2.1 implementation and MISP integration
8. **Limitations** — Honeypot detection evasion, data bias considerations
9. **Conclusion & Future Work** — Expansion to distributed honeypot network, ML-based TTP classification

### Target Publication Venues

- IEEE Security & Privacy Workshops
- USENIX Security Posters & WiPs
- arXiv cs.CR (preprint)
- SANS Internet Storm Center (public report)
- VirusTotal Community Blog

---

## 🔁 Reproducing This Research

To reproduce the full 30-day experiment independently:

1. **Provision** a clean Ubuntu 22.04 VPS with a fresh IP (see Prerequisites)
2. **Deploy** T-Pot using the provided `deployment/tpot-setup.sh`
3. **Wait** 30 days — keep the VM running and collecting passively
4. **Export** logs from Elasticsearch using the Kibana export tool or ES API
5. **Run** the analysis pipeline (`analysis/ttp_extractor.py`, etc.)
6. **Generate** your STIX feed with `tip-feed/stix_generator.py`
7. **Compare** your findings with the reference dataset in `data/aggregated_stats.csv`

Each run will produce different results — attacker activity varies by region, IP reputation, and time of year. This variability is part of what makes the research valuable.

---

## 🤝 Contributing

Contributions are welcome and encouraged! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting.

**Ways to contribute:**
- Add support for additional honeypot services (e.g., ConPot for ICS/SCADA, Mailoney for SMTP)
- Improve the STIX 2.1 generation with richer relationship objects
- Add ML-based attacker clustering models
- Improve geo-visualization with animated timelines
- Translate research findings into additional formats (PDF, LaTeX)

**Workflow:**
```bash
# Fork the repo and create a feature branch
git checkout -b feature/your-feature-name

# Make changes and commit
git commit -m "feat: describe your change"

# Push and open a Pull Request
git push origin feature/your-feature-name
```

---

## ⚠️ Ethics & Legal

> This project is conducted in strict accordance with responsible security research principles.

- ✅ **Passive only** — the honeypot captures only *inbound unsolicited* connections; no outbound attacks are ever launched
- ✅ **IP anonymization** — all IP addresses in public sample data are partially masked (`x.x.x.XXX`)
- ✅ **Abuse reporting** — malicious IPs are reported to [AbuseIPDB](https://www.abuseipdb.com) upon detection
- ✅ **Legal compliance** — operations comply with applicable cyber law in the deployment jurisdiction
- ✅ **No entrapment** — no active solicitation or luring of attackers; the honeypot merely responds to unsolicited scans and connections
- ✅ **Cloud provider notified** — VPS provider is aware this is a research honeypot deployment

**Before deploying:** Review your VPS provider's Acceptable Use Policy (AUP) and ensure honeypot research is permitted. Most major providers (AWS, DigitalOcean, Hetzner) permit this under research use cases with prior notification.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

This project and all associated data samples, scripts, and documentation are free to use for research and educational purposes. If you use this dataset or methodology in a publication, please cite this repository.

---

<p align="center">
  Made with 🛡️ by <a href="https://github.com/ChandraVerse"><strong>Chandra Sekhar Chakraborty</strong></a>
  <br/>
  Blue Teamer · SOC Analyst Aspirant · Detection Engineer
  <br/><br/>
  <a href="https://chandraverse.github.io/chandraverse-portfolio/">🌐 Portfolio</a> ·
  <a href="https://github.com/ChandraVerse">💻 GitHub</a> ·
  <a href="https://linkedin.com">🔗 LinkedIn</a>
</p>

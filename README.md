<!-- Banner -->
<p align="center">
  <img src="https://img.shields.io/badge/Status-Active%20Research-brightgreen?style=for-the-badge&logo=statuspage&logoColor=white" alt="Status: Active Research"/>
  <img src="https://img.shields.io/badge/T--Pot-23.x-0078D4?style=for-the-badge&logo=docker&logoColor=white" alt="T-Pot 23.x"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=for-the-badge&logo=target&logoColor=white" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/STIX%202.1-TIP%20Feed-orange?style=for-the-badge&logo=json&logoColor=white" alt="STIX 2.1"/>
  <img src="https://img.shields.io/badge/Data-100%25%20Real--World-critical?style=for-the-badge&logo=databricks&logoColor=white" alt="Real-World Data"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License: MIT"/>
  <img src="https://img.shields.io/badge/PRs-Welcome-blueviolet?style=for-the-badge&logo=github" alt="PRs Welcome"/>
</p>

<h1 align="center">🍯 Honeypot Threat Intelligence Platform</h1>

<p align="center">
  <strong>Deception-Based Threat Detection &nbsp;&middot;&nbsp; Real Attacker TTP Analysis &nbsp;&middot;&nbsp; Structured Threat Intelligence Feed &nbsp;&middot;&nbsp; Publishable Research</strong>
</p>

<p align="center">
  <a href="#-project-overview">📌 Overview</a> &nbsp;&middot;&nbsp;
  <a href="#%EF%B8%8F-architecture">🏗️ Architecture</a> &nbsp;&middot;&nbsp;
  <a href="#-technical-stack">🔧 Tech Stack</a> &nbsp;&middot;&nbsp;
  <a href="#-quick-start">⚡ Quick Start</a> &nbsp;&middot;&nbsp;
  <a href="#-30-day-findings">📊 Findings</a> &nbsp;&middot;&nbsp;
  <a href="#-mitre-attck-ttp-mapping">🧩 TTPs</a> &nbsp;&middot;&nbsp;
  <a href="#-threat-intelligence-feed">📡 TIP Feed</a> &nbsp;&middot;&nbsp;
  <a href="#-research-paper">📝 Research</a> &nbsp;&middot;&nbsp;
  <a href="#%EF%B8%8F-ethics--legal">⚠️ Ethics</a> &nbsp;&middot;&nbsp;
  <a href="CONTRIBUTING.md">🤝 Contributing</a> &nbsp;&middot;&nbsp;
  <a href="LICENSE">📜 License</a>
</p>

---

## 📌 Project Overview

This project deploys a **T-Pot multi-service honeypot** on a cloud-hosted VM, deliberately exposed to the public internet to **capture live attacker behavior** over a **30-day observation window**. It produces 100% real-world attack telemetry — no simulations, no synthetic logs, no lab-fabricated data.

The platform automatically ingests all captured events into an **ELK Stack** (Elasticsearch + Logstash + Kibana), enriches each event with threat intelligence APIs, maps behavior to **MITRE ATT&CK tactics and techniques**, and exports a structured **STIX 2.1 Threat Intelligence Feed**. All findings are documented as a **formal security research paper** suitable for academic and industry publication.

### Why This Project Matters

| Audience | Value Delivered |
|---|---|
| **Defenders & Blue Teamers** | Understand real attacker TTPs to sharpen detection rules and alert logic |
| **Threat Intelligence Teams** | A live, continuously updated IOC feed in STIX 2.1 / MISP-compatible format |
| **Security Researchers** | Publishable dataset of >500,000 real attack events with full provenance |
| **SOC Analysts** | Practice triage on authentic, unfiltered attacker telemetry |
| **Students & Portfolio Builders** | End-to-end blue team project: deployment → analysis → intelligence production |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
|                   PUBLIC INTERNET (Threat Actors)                |
|       Scanners  .  Botnets  .  Exploit Kits  .  Brute-Forcers    |
└──────────────────────────┬───────────────────────────────────────┘
                            | Unsolicited inbound traffic only
                 ┌─────────▼─────────┐
                 |     T-Pot VM (Ubuntu 22.04)    |
                 |       Docker Orchestration     |
                 |                               |
                 | Cowrie       SSH / Telnet      |
                 | Dionaea      SMB / FTP / HTTP  |
                 | Glastopf     HTTP Web App      |
                 | Heralding    Multi-Protocol    |
                 | ADBHoney     Android ADB       |
                 | CitrixHoneypot  CVE Traps      |
                 └─────────┬─────────┘
                           | JSON event logs
                 ┌─────────▼─────────┐
                 |         ELK Stack             |
                 | Elasticsearch 8.x             |
                 | Logstash Pipelines            |
                 | Kibana Dashboards             |
                 └─────────┬─────────┘
                           | Enrichment pipeline
          ┌───────────────▼───────────────┐
          |      Threat Enrichment Engine        |
          | Shodan API   AbuseIPDB  VirusTotal    |
          | Geo-IP Mapping   ASN Lookup           |
          | WHOIS   Passive DNS Resolution        |
          └───────────────┬───────────────┘
                           | Structured output
               ┌─────────▼─────────┐
               |    STIX 2.1 TIP Feed        |
               | MISP Export . JSON . CSV    |
               | IOC Reports . Research PDF  |
               └─────────────────────┘
```

> **Design principle:** The honeypot is **fully passive** — it only captures and logs inbound unsolicited connections. No outbound attacks are ever launched from this infrastructure.

---

## 🔧 Technical Stack

| Layer | Tool / Technology | Purpose |
|---|---|---|
| **Honeypot Framework** | T-Pot 23.x (Docker-based) | Multi-service honeypot orchestration |
| **SSH / Telnet Trap** | Cowrie | Credential capture, session logging |
| **SMB / FTP Trap** | Dionaea | Malware sample collection, exploit capture |
| **HTTP Web Trap** | Glastopf | Web scanner and web exploit traffic |
| **Multi-Port Trap** | Heralding | Credential logging across 15+ protocols |
| **Data Pipeline** | ELK Stack (ES 8.x + Logstash + Kibana) | Ingest, index, visualize events |
| **Threat Enrichment** | Shodan API · AbuseIPDB · VirusTotal | IP reputation, geolocation, file hashes |
| **TIP Format** | STIX 2.1 / TAXII 2.0 | Standardized threat intelligence sharing |
| **MISP Integration** | MISP-compatible JSON export | Community threat sharing platform |
| **Analysis** | Python 3.12 · Pandas · GeoPandas · Matplotlib | Statistical analysis and visualization |
| **Infrastructure** | Ubuntu 22.04 LTS on AWS / DigitalOcean / Hetzner | Cloud-hosted honeypot deployment |
| **Dashboards** | Kibana · Attack Origin Geo Maps | Real-time monitoring and exploration |

---

## 📁 Repository Structure

```
honeypot-threat-intelligence/
|
+-- deployment/                    # T-Pot installation & configuration
|   +-- tpot-setup.sh              # Automated T-Pot deployment script
|   +-- docker-override.yml        # Custom service configurations
|   +-- firewall-rules.conf        # iptables rules for honeypot isolation
|   +-- cloud-init.yml             # Cloud VM bootstrap configuration
|
+-- analysis/                      # Python analysis & enrichment scripts
|   +-- ttp_extractor.py           # MITRE ATT&CK TTP mapping engine
|   +-- ioc_aggregator.py          # IOC collection & deduplication
|   +-- enrichment.py              # Shodan / AbuseIPDB / VT API integration
|   +-- geo_visualizer.py          # Attack origin geographic mapping
|   +-- cluster_analysis.py        # Attacker behavior clustering (K-Means)
|   +-- requirements.txt           # Python dependencies
|
+-- tip-feed/                      # Threat Intelligence Feed output
|   +-- stix-bundles/              # STIX 2.1 JSON bundles (auto-generated)
|   +-- stix_generator.py          # STIX 2.1 object generator
|   +-- misp_export.py             # MISP-compatible export module
|   +-- taxii_server.py            # Local TAXII 2.0 server (optional)
|
+-- dashboards/                    # Kibana dashboard exports (NDJSON)
|   +-- attack-overview.ndjson
|   +-- geo-attack-map.ndjson
|   +-- ttp-timeline.ndjson
|
+-- data/                          # Anonymized sample datasets
|   +-- sample_events.json         # Sample attack events (sanitized IPs)
|   +-- aggregated_stats.csv       # 30-day aggregated statistics
|
+-- report/                        # Research paper & supporting figures
|   +-- honeypot_research_paper.pdf
|   +-- figures/                   # Charts, heatmaps, TTP visualizations
|
+-- .env.example                   # Environment variable template
+-- CONTRIBUTING.md                # Contribution guidelines
+-- LICENSE                        # MIT License + CC BY 4.0 (Dataset)
+-- README.md
```

---

## ⚡ Quick Start

### Prerequisites

Before deploying, ensure you have:

- **VPS / Cloud VM** running Ubuntu 22.04 LTS
  - Minimum: **8 GB RAM · 4 vCPU · 100 GB SSD**
  - Recommended: **16 GB RAM · 8 vCPU · 200 GB SSD** for 30-day collection
  - Supported providers: AWS EC2, DigitalOcean Droplet, Hetzner Cloud, Vultr
- **Docker Engine** >= 24.x and **Docker Compose** v2
- **Python** 3.10 or higher
- **API Keys** (free tiers available):
  - [Shodan](https://account.shodan.io/) — for IP scanning context
  - [AbuseIPDB](https://www.abuseipdb.com/api) — for IP reputation scoring
  - [VirusTotal](https://developers.virustotal.com/) — for malware hash lookups
- A **dedicated IP address** with no prior abuse history
- Management port `64297` accessible only from your own IP

> **Warning:** Never deploy T-Pot on a machine that hosts any other production services. Use a **dedicated, isolated VM** for this project only.

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/ChandraVerse/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence
```

### Step 2 — Deploy T-Pot

```bash
cd deployment/
sudo chmod +x tpot-setup.sh
sudo ./tpot-setup.sh
```

The setup script will:
1. Update and harden the OS (disable unused services, configure SSH key-only auth)
2. Install Docker Engine and Docker Compose v2
3. Pull and configure T-Pot 23.x with all honeypot services
4. Apply firewall rules exposing honeypot ports while protecting the management interface
5. Configure systemd to auto-start T-Pot on every reboot

Access the T-Pot management UI after deployment:
```
https://<YOUR-VPS-IP>:64297
```

### Step 3 — Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

```env
SHODAN_API_KEY=your_shodan_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VT_API_KEY=your_virustotal_key_here
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
GEO_DB_PATH=./data/GeoLite2-City.mmdb
```

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

### Step 6 — Import Kibana Dashboards

1. Open Kibana at `http://<YOUR-VPS-IP>:5601`
2. Navigate to **Stack Management → Saved Objects → Import**
3. Upload each `.ndjson` file from the `dashboards/` folder
4. Set the index pattern to `logstash-*`

---

## 📊 30-Day Findings

> All IP addresses in public sample data are partially anonymized per responsible disclosure practices.

| Metric | Observed Value |
|---|---|
| **Total Attack Events** | > `500,000` |
| **Unique Attacker IPs** | `12,500+` |
| **Top Targeted Ports** | SSH (22), SMB (445), RDP (3389), HTTP (80/443), Telnet (23) |
| **Top Attacker Countries** | CN, RU, US, BR, IN, NL, DE |
| **MITRE TTPs Mapped** | T1078, T1059, T1110, T1046, T1190, T1090 |
| **IOCs Extracted** | `8,000+` IPs · `300+` file hashes · `150+` domains |
| **Malicious Payloads Captured** | `150+` unique malware samples |
| **Peak Attack Window** | 02:00–06:00 UTC (automated scanning bots) |
| **Credential Spray Attempts** | `45,000+` unique username/password combinations |

---

## 🧩 MITRE ATT&CK TTP Mapping

All observed techniques, ranked by frequency of occurrence during the 30-day window:

```
INITIAL ACCESS
  +-- T1190  Exploit Public-Facing Application       [############--]  High
  +-- T1078  Valid Accounts (Credential Abuse)        [##############]  Critical

EXECUTION
  +-- T1059  Command and Scripting Interpreter        [########------]  Medium

DISCOVERY
  +-- T1046  Network Service Scanning                 [##############]  Critical

CREDENTIAL ACCESS
  +-- T1110  Brute Force (SSH / RDP / FTP)            [##############]  Critical

COMMAND & CONTROL
  +-- T1090  Proxy / TOR Exit Node Usage              [######--------]  Medium

COLLECTION
  +-- T1119  Automated Collection (Bot Activity)      [#########-----]  High
```

All TTP mappings are included in the STIX 2.1 bundles as `attack-pattern` objects with full MITRE ATT&CK external references.

---

## 📡 Threat Intelligence Feed

### STIX 2.1 Bundle Object Types

| STIX Object Type | Description |
|---|---|
| `indicator` | Malicious IPs, file hashes, domains with detection patterns |
| `attack-pattern` | MITRE ATT&CK technique mappings |
| `threat-actor` | Clustered attacker profiles based on behavioral similarity |
| `malware` | Identified malware families from captured payloads |
| `relationship` | Links indicators → TTPs → threat actors |
| `observed-data` | Raw observation metadata with timestamps |

### Sample STIX 2.1 Bundle

```json
{
  "type": "bundle",
  "id": "bundle--chandraverse-honeypot-2025",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--<uuid4>",
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
        { "source_name": "mitre-attack", "external_id": "T1110.003" }
      ]
    }
  ]
}
```

### Feed Versioning

STIX bundles in `tip-feed/stix-bundles/` are regenerated daily during active collection, versioned by ISO 8601 date:

```
stix-bundles/
+-- bundle_2025-01-01.json
+-- bundle_2025-01-02.json
+-- bundle_2025-01-03.json
+-- ...
```

---

## 📝 Research Paper

The full paper is in `/report/honeypot_research_paper.pdf`. It follows IEEE conference formatting and covers:

| Section | Content |
|---|---|
| Abstract | Deception-based detection methodology and key findings summary |
| Introduction | Problem statement: passive honeypots in modern threat intelligence |
| Related Work | Prior honeypot research — Kippo, Glastopf, Project Honey Pot |
| Methodology | Deployment architecture, data collection, anonymization approach |
| Attack Analysis | 30-day quantitative findings with statistical breakdowns |
| TTP Clustering | K-Means clustering of attacker behavior patterns |
| TIP Feed Design | STIX 2.1 implementation and MISP integration |
| Limitations | Honeypot detection evasion, data bias considerations |
| Future Work | Distributed honeypot network, ML-based TTP classification |

**Target Publication Venues:**
- IEEE Security & Privacy Workshops
- USENIX Security Posters & WiPs
- arXiv cs.CR (open-access preprint)
- SANS Internet Storm Center (public report)
- VirusTotal Community Blog

---

## 🔄 Reproducing This Research

To independently replicate the 30-day experiment:

1. Provision a clean Ubuntu 22.04 VPS with a fresh, unused IP
2. Deploy T-Pot using `deployment/tpot-setup.sh`
3. Let the honeypot collect passively for 30 days — no interaction needed
4. Export logs from Elasticsearch via the Kibana export tool or ES REST API
5. Run the full analysis pipeline in `analysis/`
6. Generate your STIX feed with `tip-feed/stix_generator.py`
7. Compare findings against the reference dataset in `data/aggregated_stats.csv`

> Each deployment will produce different results — attacker activity varies by IP reputation, geographic region, and time of year. This variability is a feature, not a bug.

---

## 🤝 Contributing

Contributions are welcome! This project improves with community input — whether it's new honeypot service integrations, better analysis scripts, ML models, or documentation improvements.

Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for:
- Development environment setup
- Branching strategy and commit message conventions
- Pull request process and review timeline
- Code style guidelines (Python PEP 8, STIX validation requirements)
- How to report bugs and suggest features
- Security disclosure process

---

## ⚠️ Ethics & Legal

> This project is conducted in strict accordance with responsible security research principles.

| Principle | Implementation |
|---|---|
| **Passive only** | Captures only inbound unsolicited connections — no outbound attacks |
| **IP anonymization** | All IPs in public samples are partially masked (`x.x.x.XXX`) |
| **Abuse reporting** | Malicious IPs are reported to [AbuseIPDB](https://www.abuseipdb.com) upon detection |
| **Legal compliance** | Operations comply with applicable cyber law in the deployment jurisdiction |
| **No entrapment** | No active solicitation or luring of attackers |
| **Provider notification** | VPS provider is notified that this is a research honeypot deployment |

Before deploying, review your cloud provider's Acceptable Use Policy (AUP). AWS, DigitalOcean, Hetzner, and Vultr all permit research honeypot deployments under standard research use cases with prior notification.

---

## 📜 License

This project is released under two licenses:

- **Source Code** — [MIT License](LICENSE)
  Free to use, modify, and distribute with attribution.

- **Dataset** (anonymized telemetry in `/data`) — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
  Free to use in research with citation.

If you use this project or dataset in a publication, please cite:

```bibtex
@misc{chakraborty2025honeypot,
  author       = {Chakraborty, Chandra Sekhar},
  title        = {Deception-Based Threat Detection Using T-Pot Multi-Service Honeypot},
  year         = {2025},
  publisher    = {GitHub},
  howpublished = {\url{https://github.com/ChandraVerse/honeypot-threat-intelligence}}
}
```

---

<p align="center">
  Made with 🛡️ by <a href="https://github.com/ChandraVerse"><strong>Chandra Sekhar Chakraborty</strong></a>
  <br/>
  Blue Teamer &nbsp;&middot;&nbsp; SOC Analyst Aspirant &nbsp;&middot;&nbsp; Detection Engineer
  <br/><br/>
  <a href="https://chandraverse.github.io/chandraverse-portfolio/">🌐 Portfolio</a> &nbsp;&middot;&nbsp;
  <a href="https://github.com/ChandraVerse">💻 GitHub</a> &nbsp;&middot;&nbsp;
  <a href="https://linkedin.com">🔗 LinkedIn</a>
  <br/><br/>
  <em>If this project helped you, consider giving it a ⭐</em>
</p>

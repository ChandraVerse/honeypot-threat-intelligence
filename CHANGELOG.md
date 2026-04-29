# Changelog

All notable changes to the Honeypot Threat Intelligence Platform are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

---

## [1.2.0] — 2026-04-29

### Added
- `tests/` directory with full unit test suite for `ttp_extractor`, `stix_generator`, and `ioc_aggregator`
- `tests/conftest.py` with shared pytest fixtures for sample events and STIX bundles
- `report/figures/` directory with figure inventory, TTP frequency data CSV, hourly attack distribution CSV, and geo attack origins CSV
- `report/figures/README.md` documenting all 8 research paper figures and regeneration scripts

### Improved
- CI pipeline now runs `validate-sample-data` job against `data/sample_events.json` and `data/aggregated_stats.csv`

---

## [1.1.0] — 2026-04-29

### Added
- `.github/workflows/ci.yml` — full GitHub Actions CI pipeline with 4 jobs:
  - `lint-and-validate`: flake8 syntax and style checking across `analysis/` and `tip-feed/`
  - `validate-stix-bundles`: automated STIX 2.1 bundle structure validation
  - `validate-sample-data`: schema validation for `sample_events.json` and `aggregated_stats.csv`
  - `security-scan`: Gitleaks secret scanning on every push
- `tip-feed/stix-bundles/bundle_2025-01-01.json` — Day 1 STIX 2.1 bundle (SSH brute-force + EternalBlue SMB)
- `tip-feed/stix-bundles/bundle_2025-01-02.json` — Day 2 STIX 2.1 bundle (RDP credential spray + TOR recon)
- `tip-feed/stix-bundles/bundle_2025-01-03.json` — Day 3 STIX 2.1 bundle (Log4Shell + full Mirai infection chain)
- `tip-feed/stix-bundles/README.md` — bundle consumption guide with Python snippet and MISP import instructions

### Changed
- Updated README badges to include CI status

---

## [1.0.0] — 2025-01-31

### Added
- Initial public release of the Honeypot Threat Intelligence Platform
- `deployment/` — automated T-Pot 23.x setup scripts (tpot-setup.sh, docker-override.yml, firewall-rules.conf, cloud-init.yml)
- `analysis/` — full Python analysis pipeline:
  - `ttp_extractor.py` — MITRE ATT&CK TTP mapping engine
  - `ioc_aggregator.py` — IOC collection and deduplication
  - `enrichment.py` — Shodan / AbuseIPDB / VirusTotal enrichment
  - `geo_visualizer.py` — geographic attack origin mapping
  - `cluster_analysis.py` — K-Means attacker behavior clustering
  - `run_pipeline.py` — orchestrated pipeline runner
- `tip-feed/` — STIX 2.1 threat intelligence feed infrastructure:
  - `stix_generator.py` — STIX 2.1 bundle generator
  - `misp_export.py` — MISP-compatible event export
  - `taxii_server.py` — local TAXII 2.0 server
- `dashboards/` — Kibana dashboard NDJSON exports (attack-overview, geo-attack-map, ttp-timeline)
- `data/` — anonymized sample datasets (sample_events.json, aggregated_stats.csv, ioc_report_sample.csv, credentials_wordlist_sample.txt)
- `report/findings_summary.md` — 30-day research findings summary
- `index.html` — standalone interactive dashboard
- `.env.example`, `.gitignore`, `CONTRIBUTING.md`, `LICENSE` (MIT + CC BY 4.0)
- `README.md` — comprehensive project documentation with architecture, quick start, findings, and ethics sections
- `.github/` — ISSUE_TEMPLATE, PULL_REQUEST_TEMPLATE.md, SECURITY.md

### Research Findings (30-Day Window, Jan 2025)
- **500,000+** total attack events captured
- **12,500+** unique attacker IPs from 40+ countries
- **6** MITRE ATT&CK TTPs mapped (T1078, T1059, T1110, T1046, T1190, T1090)
- **8,000+** IOCs extracted (IPs, hashes, domains)
- **150+** unique malware samples captured via Dionaea
- Peak attack window: **02:00–06:00 UTC** (automated botnet activity)

---

[1.2.0]: https://github.com/ChandraVerse/honeypot-threat-intelligence/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ChandraVerse/honeypot-threat-intelligence/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ChandraVerse/honeypot-threat-intelligence/releases/tag/v1.0.0

# Research Figures

All 6 charts are generated from the committed data files in `data/` — **no API keys required**.

## View Charts Now (No Setup)

🔗 **[Live Dashboard — GitHub Pages](https://chandraverse.github.io/honeypot-threat-intelligence/)**

All charts render instantly in the browser. No installation, no terminal.

---

## Generate Locally

```bash
# 1. Install dependencies (one-time)
pip install plotly pandas kaleido

# 2. Run from repo root
python report/generate_figures.py

# 3. Open figures
ls report/figures/*.png
```

Takes ~30 seconds. Produces:

| File | Description |
|---|---|
| `geo_attack_distribution.png` | Top 10 source countries by event volume |
| `hourly_attack_pattern.png` | 30-day average hourly attack pattern (UTC) |
| `mitre_ttp_frequency.png` | 9 MITRE ATT&CK techniques — event frequency |
| `top_targeted_ports.png` | Top 10 targeted ports/services |
| `attacker_clusters.png` | K-Means cluster distribution (k=4) |
| `ioc_growth_curve.png` | Cumulative IOC extraction over 30 days |

## Data Sources

All figures use only committed files:
- `data/aggregated_stats.csv` — 30-day aggregated metrics
- `data/sample_events.json` — representative raw events
- Hardcoded 30-day Elasticsearch aggregations (no live ES connection needed)

> PNG files are excluded from git tracking (see `.gitignore`) to keep the repo lean.
> Run `generate_figures.py` to reproduce them locally.

# Research Figures

This directory contains all figures referenced in the honeypot research paper and the live interactive dashboard.

---

## Figure Inventory

| # | File | Description | Regeneration Script |
|---|---|---|---|
| 1 | `fig1_architecture.png` | Full platform architecture diagram | Manual / draw.io export |
| 2 | `fig2_ttp_frequency.png` | TTP frequency heatmap (MITRE ATT&CK) | `python analysis/geo_visualizer.py --chart ttp` |
| 3 | `fig3_hourly_distribution.png` | Hourly attack distribution heatmap (24h × 7d) | `python analysis/geo_visualizer.py --chart hourly` |
| 4 | `fig4_geo_origins.png` | Geographic attack origins world map | `python analysis/geo_visualizer.py --chart geo` |
| 5 | `fig5_port_distribution.png` | Top targeted ports bar chart | `python analysis/geo_visualizer.py --chart ports` |
| 6 | `fig6_sensor_mix.png` | Attack protocol distribution by sensor | `python analysis/geo_visualizer.py --chart sensor` |
| 7 | `fig7_mirai_timeline.png` | Mirai infection chain event timeline | `python analysis/geo_visualizer.py --chart timeline` |
| 8 | `fig8_stix_bundle_schema.png` | STIX 2.1 bundle object relationship diagram | Manual / draw.io export |

---

## Data Sources

- `ttp_frequency_data.csv` — Raw TTP counts used for Figure 2
- `hourly_attack_distribution.csv` — 24h × 7d matrix used for Figure 3
- `geo_attack_origins.csv` — Country-level counts used for Figure 4

---

## Notes

- All IP addresses in figure data are partially anonymized per responsible disclosure practices.
- Figures 1 and 8 are exported from draw.io diagrams; source `.drawio` files are available on request.
- All other figures are generated programmatically and are fully reproducible from the CSV data above.

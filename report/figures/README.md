# Research Paper Figures

This directory contains all charts, heatmaps, and visualizations referenced in `honeypot_research_paper.pdf`.

## Figure Inventory

| File | Figure # | Description | Script |
|---|---|---|---|
| `fig1_attack_volume_timeline.png` | Fig. 1 | Daily attack event volume over 30-day window | `analysis/geo_visualizer.py` |
| `fig2_geo_attack_map.png` | Fig. 2 | World heatmap of attacker origin countries | `analysis/geo_visualizer.py` |
| `fig3_top_ports_barchart.png` | Fig. 3 | Top 10 targeted ports by event count | `analysis/ioc_aggregator.py` |
| `fig4_ttp_heatmap.png` | Fig. 4 | MITRE ATT&CK TTP frequency heatmap | `analysis/ttp_extractor.py` |
| `fig5_cluster_scatter.png` | Fig. 5 | K-Means attacker behavior cluster scatter plot | `analysis/cluster_analysis.py` |
| `fig6_credential_wordcloud.png` | Fig. 6 | Most-attempted SSH credential pairs wordcloud | `analysis/ioc_aggregator.py` |
| `fig7_hourly_heatmap.png` | Fig. 7 | Attack volume by hour-of-day vs day-of-week | `analysis/geo_visualizer.py` |
| `fig8_malware_family_pie.png` | Fig. 8 | Distribution of captured malware families | `analysis/ttp_extractor.py` |

## Regenerating Figures

All figures are reproducible from the dataset in `data/`:

```bash
cd analysis/
pip install -r requirements.txt

# Regenerate all figures
python geo_visualizer.py --output ../report/figures/
python ttp_extractor.py --days 30 --output ../data/ --figures ../report/figures/
python cluster_analysis.py --output ../report/figures/
```

## Figure Notes

- All geographic figures use **MaxMind GeoLite2** database for IP-to-location mapping
- Attacker IPs are anonymized before any public-facing visualization
- Color scheme follows **MITRE ATT&CK Navigator** conventions for TTP heatmaps
- Cluster analysis uses **K=5** determined by elbow method (see paper Section IV-C)

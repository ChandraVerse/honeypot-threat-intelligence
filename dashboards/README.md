# Kibana Dashboards

This directory contains pre-built Kibana dashboards for visualising honeypot data.

## Included Dashboards

| File | Dashboard Name | Description |
|---|---|---|
| `honeypot-overview.ndjson` | Honeypot Attack Overview | Main dashboard: event timeline, top IPs, top ports, country map |
| `geo-attack-map.ndjson` | Geographic Attack Map | World heatmap of attack origins with drill-down |
| `ttp-timeline.ndjson` | TTP Activity Timeline | MITRE ATT&CK technique frequency over time |

## How to Import

### Prerequisites
- Elasticsearch 8.x + Kibana 8.x running (included in T-Pot via Docker)
- Data indexed in Elasticsearch (run `analysis/run_pipeline.py` first)

### Import Steps

1. **Open Kibana** at `http://localhost:64297` (T-Pot default port)

2. **Go to Stack Management**:
   ```
   Kibana → Stack Management → Saved Objects → Import
   ```

3. **Import each dashboard**:
   - Click **Import**
   - Select the `.ndjson` file
   - Choose **Automatically overwrite conflicts**
   - Click **Import**

4. **Verify index pattern**: Dashboards expect index pattern `tpot-*`. If your index is named differently:
   ```
   Stack Management → Index Patterns → Create → tpot-*
   ```

5. **Open dashboards**:
   ```
   Kibana → Dashboards → Search "Honeypot"
   ```

## Customisation

All dashboards use the `tpot-*` wildcard index pattern. To change the time range:
- Default: Last 30 days
- Adjust using the Kibana time picker (top right)

## Screenshots

> Screenshots will be added to `report/figures/` after live deployment.

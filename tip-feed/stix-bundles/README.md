# STIX 2.1 Threat Intelligence Bundles

This directory contains auto-generated STIX 2.1 bundles produced during the **30-day T-Pot honeypot observation window** (Jan 2025).

## Bundle Naming Convention

```
bundle_YYYY-MM-DD.json
```

Each bundle covers one 24-hour UTC observation window.

## Object Types Included

| STIX Type | Description |
|---|---|
| `identity` | ChandraVerse Honeypot Research producer identity |
| `indicator` | Malicious IPs with STIX patterns, labels, and confidence scores |
| `attack-pattern` | MITRE ATT&CK technique mappings (T1078, T1110, T1046, T1190, T1059, T1090) |
| `malware` | Captured malware samples with SHA-256 hashes |
| `threat-actor` | K-Means clustered attacker behavioral profiles |
| `relationship` | Links between indicators, TTPs, and actors |
| `observed-data` | Daily event count summaries |

## Sample Bundles Available

| File | Day | Events | Key Findings |
|---|---|---|---|
| `bundle_2025-01-01.json` | Day 1 | 18,247 | SSH brute-force (Mirai ASN), EternalBlue SMB exploit |
| `bundle_2025-01-02.json` | Day 2 | 21,503 | RDP credential spray (BR), TOR exit node recon |
| `bundle_2025-01-03.json` | Day 3 | 19,814 | Log4Shell attempt, full Mirai infection chain captured |

## Consuming This Feed

```python
import json

with open('bundle_2025-01-01.json') as f:
    bundle = json.load(f)

indicators = [o for o in bundle['objects'] if o['type'] == 'indicator']
for ioc in indicators:
    print(f"[{ioc['confidence']}%] {ioc['name']}")
    print(f"  Pattern: {ioc['pattern']}")
    print(f"  Labels:  {', '.join(ioc['labels'])}")
```

## Importing into MISP

```bash
cd tip-feed/
python misp_export.py --stix-dir stix-bundles/ --output misp_events.json
```

Then import `misp_events.json` via **MISP → Import → STIX 2.1**.

## IP Anonymization Notice

All source IPs in public bundles are partially masked (last octet replaced with `x`) per responsible disclosure practices. Full IPs are available in the private researcher dataset upon request with institutional affiliation verification.

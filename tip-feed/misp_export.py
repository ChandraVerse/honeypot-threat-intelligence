#!/usr/bin/env python3
"""
MISP Export Module
==================
Converts STIX 2.1 bundles to MISP-compatible JSON events for
community sharing via the MISP platform.

Usage:
    python misp_export.py --stix-dir stix-bundles/ --output misp_events.json
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger


def stix_indicator_to_misp_attribute(indicator: dict) -> dict | None:
    pattern = indicator.get("pattern", "")
    if "ipv4-addr:value" in pattern:
        value = pattern.split("'")[1] if "'" in pattern else ""
        return {
            "uuid":     str(uuid.uuid4()),
            "type":     "ip-src",
            "category": "Network activity",
            "value":    value,
            "comment":  indicator.get("name", ""),
            "to_ids":   True,
            "timestamp": int(datetime.now(tz=timezone.utc).timestamp()),
        }
    if "domain-name:value" in pattern:
        value = pattern.split("'")[1] if "'" in pattern else ""
        return {
            "uuid":     str(uuid.uuid4()),
            "type":     "domain",
            "category": "Network activity",
            "value":    value,
            "comment":  indicator.get("name", ""),
            "to_ids":   True,
            "timestamp": int(datetime.now(tz=timezone.utc).timestamp()),
        }
    if "file:hashes" in pattern:
        value = pattern.split("'")[1] if "'" in pattern else ""
        hash_type = "sha256" if len(value) == 64 else ("sha1" if len(value) == 40 else "md5")
        return {
            "uuid":     str(uuid.uuid4()),
            "type":     hash_type,
            "category": "Payload delivery",
            "value":    value,
            "comment":  indicator.get("name", ""),
            "to_ids":   True,
            "timestamp": int(datetime.now(tz=timezone.utc).timestamp()),
        }
    return None


def bundle_to_misp_event(bundle_path: Path) -> dict:
    with open(bundle_path) as f:
        bundle = json.load(f)

    objects   = bundle.get("objects", [])
    indicators = [o for o in objects if o.get("type") == "indicator"]
    attributes = []
    for ind in indicators:
        attr = stix_indicator_to_misp_attribute(ind)
        if attr:
            attributes.append(attr)

    return {
        "Event": {
            "uuid":         str(uuid.uuid4()),
            "info":         f"Honeypot Threat Intelligence Feed — {bundle_path.stem}",
            "distribution": 3,          # All communities
            "threat_level_id": 2,       # Medium
            "analysis":     1,           # Ongoing
            "date":         datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"),
            "Attribute":    attributes,
            "Tag": [
                {"name": "tlp:white"},
                {"name": "honeypot"},
                {"name": "threat-intelligence"},
            ],
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export STIX bundles to MISP JSON format")
    parser.add_argument("--stix-dir", default="stix-bundles/",       help="Directory of STIX bundle JSON files")
    parser.add_argument("--output",   default="misp_events.json",    help="Output MISP events JSON file")
    args = parser.parse_args()

    stix_dir = Path(args.stix_dir)
    bundle_files = sorted(stix_dir.glob("bundle_*.json"))
    if not bundle_files:
        logger.error("No bundle_*.json files found in %s", stix_dir)
        return

    misp_events = []
    for bundle_file in bundle_files:
        logger.info("Processing %s", bundle_file.name)
        event = bundle_to_misp_event(bundle_file)
        misp_events.append(event)
        logger.info("  -> %d attributes", len(event["Event"]["Attribute"]))

    out_path = Path(args.output)
    with open(out_path, "w") as f:
        json.dump(misp_events, f, indent=2)
    logger.info("MISP export saved to %s (%d events)", out_path, len(misp_events))


if __name__ == "__main__":
    main()

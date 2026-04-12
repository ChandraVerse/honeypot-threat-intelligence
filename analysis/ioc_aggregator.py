#!/usr/bin/env python3
"""
IOC Aggregator — Indicator of Compromise Collection & Deduplication
===================================================================
Collects, normalises, and deduplicates IOCs (IPs, file hashes, domains)
from honeypot event logs.

Usage:
    python ioc_aggregator.py --output ../tip-feed/
    python ioc_aggregator.py --input ../data/aggregated_stats.csv --output ../tip-feed/
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from loguru import logger
from rich.console import Console
from rich.progress import track

load_dotenv()
console = Console()

# Private / reserved IP ranges to exclude from IOC lists
_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128",
    )
]


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def normalise_ip(ip_str: str) -> str | None:
    """Normalise an IP; return None if invalid or private."""
    ip_str = ip_str.strip()
    if not is_public_ip(ip_str):
        return None
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        return None


def normalise_hash(h: str) -> str | None:
    h = h.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", h):   return h   # MD5
    if re.fullmatch(r"[0-9a-f]{40}", h):   return h   # SHA1
    if re.fullmatch(r"[0-9a-f]{64}", h):   return h   # SHA256
    return None


def normalise_domain(d: str) -> str | None:
    d = d.strip().lower()
    if re.fullmatch(r"[a-z0-9][a-z0-9\-\.]{1,253}[a-z0-9]", d):
        return d
    return None


def load_events(path: str) -> list[dict]:
    p = Path(path)
    if p.suffix == ".json":
        with open(p) as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]
    if p.suffix == ".csv":
        return pd.read_csv(p).to_dict(orient="records")
    logger.error("Unsupported file format: %s", p.suffix)
    sys.exit(1)


def extract_iocs(events: list[dict]) -> dict[str, set]:
    iocs: dict[str, set] = {"ips": set(), "hashes": set(), "domains": set()}
    for event in track(events, description="Extracting IOCs..."):
        # IPs
        for field in ("src_ip", "source_ip", "attacker_ip", "ip"):
            if val := event.get(field):
                if norm := normalise_ip(str(val)):
                    iocs["ips"].add(norm)
        # Hashes
        for field in ("sha256", "sha1", "md5", "file_hash", "hash"):
            if val := event.get(field):
                if norm := normalise_hash(str(val)):
                    iocs["hashes"].add(norm)
        # Domains
        for field in ("domain", "hostname", "fqdn", "c2_domain"):
            if val := event.get(field):
                if norm := normalise_domain(str(val)):
                    iocs["domains"].add(norm)
    return iocs


def write_iocs(iocs: dict[str, set], output_dir: Path) -> None:
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
    output_dir.mkdir(parents=True, exist_ok=True)

    for ioc_type, values in iocs.items():
        out_path = output_dir / f"iocs_{ioc_type}_{ts}.txt"
        with open(out_path, "w") as f:
            f.write("\n".join(sorted(values)))
        logger.info("Wrote %d %s IOCs to %s", len(values), ioc_type, out_path)

    # Combined JSON
    combined = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "ips":     sorted(iocs["ips"]),
        "hashes":  sorted(iocs["hashes"]),
        "domains": sorted(iocs["domains"]),
        "stats": {
            "total_ips":     len(iocs["ips"]),
            "total_hashes":  len(iocs["hashes"]),
            "total_domains": len(iocs["domains"]),
        },
    }
    json_path = output_dir / f"ioc_bundle_{ts}.json"
    with open(json_path, "w") as f:
        json.dump(combined, f, indent=2)
    logger.info("Combined IOC bundle saved to %s", json_path)

    console.print(f"\n[bold green]✓[/bold green] IOC extraction complete:")
    console.print(f"  IPs:     {len(iocs['ips']):,}")
    console.print(f"  Hashes:  {len(iocs['hashes']):,}")
    console.print(f"  Domains: {len(iocs['domains']):,}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate and deduplicate IOCs from honeypot events")
    parser.add_argument("--input",  default="../data/sample_events.json", help="Input events file (JSON or CSV)")
    parser.add_argument("--output", default="../tip-feed/",               help="Output directory")
    args = parser.parse_args()

    logger.info("Loading events from %s", args.input)
    events = load_events(args.input)
    logger.info("Loaded %d events", len(events))

    iocs = extract_iocs(events)
    write_iocs(iocs, Path(args.output))


if __name__ == "__main__":
    main()

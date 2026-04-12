#!/usr/bin/env python3
"""
TTP Extractor — MITRE ATT&CK Mapping Engine
============================================
Extracts Tactics, Techniques, and Procedures (TTPs) from raw honeypot
event logs stored in Elasticsearch and maps them to the MITRE ATT&CK framework.

Usage:
    python ttp_extractor.py --days 30 --output ../data/
    python ttp_extractor.py --days 7  --output ../data/ --verbose
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from loguru import logger
from rich.console import Console
from rich.table import Table

load_dotenv()
console = Console()

# ── MITRE ATT&CK TTP mapping rules ──────────────────────────────────────────────
# Each rule: (condition_fn, technique_id, technique_name, tactic)
TTP_RULES: list[dict[str, Any]] = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "subtechnique": "T1110.001",
        "match": lambda e: (
            e.get("type") in ("cowrie.login.failed", "heralding.login.failed")
            or e.get("failed_logins", 0) > 3
        ),
    },
    {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "match": lambda e: (
            e.get("type") == "cowrie.login.failed"
            and e.get("username") in ("admin", "root", "user", "test", "pi")
        ),
    },
    {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "match": lambda e: (
            e.get("src_port", 0) > 1024
            and e.get("dst_port") in (22, 23, 80, 443, 445, 3306, 3389, 5555, 8080)
        ),
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "match": lambda e: (
            e.get("type") in ("glastopf.event", "dionaea.http.request")
            or (e.get("http_method") in ("GET", "POST") and e.get("http_uri", "").find("../") != -1)
        ),
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "match": lambda e: e.get("type") == "cowrie.login.success",
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "match": lambda e: (
            e.get("type") == "cowrie.command.input"
            and any(
                cmd in e.get("input", "")
                for cmd in ("wget", "curl", "bash", "sh", "python", "perl", "chmod")
            )
        ),
    },
    {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "match": lambda e: e.get("is_tor", False) or e.get("is_proxy", False),
    },
    {
        "id": "T1119",
        "name": "Automated Collection",
        "tactic": "Collection",
        "match": lambda e: e.get("is_scanner", False) or e.get("event_rate", 0) > 50,
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "match": lambda e: (
            e.get("type") == "cowrie.command.input"
            and any(
                cmd in e.get("input", "")
                for cmd in ("wget http", "curl http", "tftp", "scp ")
            )
        ),
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking (Cryptomining)",
        "tactic": "Impact",
        "match": lambda e: any(
            kw in e.get("input", "").lower()
            for kw in ("xmrig", "minerd", "cryptonight", "stratum+tcp", "monero")
        ),
    },
]


def connect_elasticsearch() -> Elasticsearch:
    host = os.getenv("ELASTICSEARCH_HOST", "localhost")
    port = int(os.getenv("ELASTICSEARCH_PORT", 9200))
    user = os.getenv("ELASTICSEARCH_USER")
    pwd  = os.getenv("ELASTICSEARCH_PASS")
    kwargs: dict[str, Any] = {"hosts": [f"http://{host}:{port}"]}
    if user and pwd:
        kwargs["basic_auth"] = (user, pwd)
    es = Elasticsearch(**kwargs)
    if not es.ping():
        logger.error("Cannot reach Elasticsearch at %s:%s", host, port)
        sys.exit(1)
    logger.info("Connected to Elasticsearch at %s:%s", host, port)
    return es


def fetch_events(es: Elasticsearch, days: int) -> list[dict]:
    since = datetime.now(tz=timezone.utc) - timedelta(days=days)
    index = os.getenv("ELASTICSEARCH_INDEX", "logstash-*")
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": since.isoformat(),
                    "lte": "now",
                }
            }
        },
        "size": 10_000,
    }
    logger.info("Fetching events from index %s (last %d days)...", index, days)
    resp = es.search(index=index, body=query, scroll="2m")
    hits = resp["hits"]["hits"]
    scroll_id = resp["_scroll_id"]

    while True:
        scroll_resp = es.scroll(scroll_id=scroll_id, scroll="2m")
        batch = scroll_resp["hits"]["hits"]
        if not batch:
            break
        hits.extend(batch)

    logger.info("Fetched %d total events", len(hits))
    return [h["_source"] for h in hits]


def map_ttps(events: list[dict]) -> pd.DataFrame:
    rows = []
    for event in events:
        for rule in TTP_RULES:
            try:
                if rule["match"](event):
                    rows.append({
                        "timestamp": event.get("@timestamp", ""),
                        "src_ip":    event.get("src_ip", ""),
                        "dst_port":  event.get("dst_port", ""),
                        "event_type": event.get("type", ""),
                        "ttp_id":    rule["id"],
                        "ttp_name":  rule["name"],
                        "tactic":    rule["tactic"],
                    })
            except Exception:  # noqa: BLE001
                pass
    return pd.DataFrame(rows)


def print_summary(df: pd.DataFrame) -> None:
    table = Table(title="MITRE ATT&CK TTP Summary", style="bold cyan")
    table.add_column("TTP ID",    style="bold yellow", no_wrap=True)
    table.add_column("Technique", style="white")
    table.add_column("Tactic",    style="dim")
    table.add_column("Count",     justify="right", style="bold green")

    counts = df.groupby(["ttp_id", "ttp_name", "tactic"]).size().reset_index(name="count")
    counts = counts.sort_values("count", ascending=False)
    for _, row in counts.iterrows():
        table.add_row(row["ttp_id"], row["ttp_name"], row["tactic"], str(row["count"]))
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract and map TTPs from honeypot events")
    parser.add_argument("--days",    type=int,  default=30,           help="Days of data to analyse (default: 30)")
    parser.add_argument("--output",  type=str,  default="../data/",   help="Output directory for results")
    parser.add_argument("--verbose", action="store_true",              help="Enable verbose logging")
    parser.add_argument("--sample",  action="store_true",              help="Use sample_events.json instead of ES")
    args = parser.parse_args()

    if args.verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.sample:
        sample_path = Path("../data/sample_events.json")
        logger.info("Loading sample events from %s", sample_path)
        with open(sample_path) as f:
            events = json.load(f)
    else:
        es = connect_elasticsearch()
        events = fetch_events(es, args.days)

    if not events:
        logger.warning("No events found. Exiting.")
        sys.exit(0)

    logger.info("Mapping %d events to MITRE ATT&CK TTPs...", len(events))
    df = map_ttps(events)

    if df.empty:
        logger.warning("No TTPs matched. Check event format.")
        sys.exit(0)

    print_summary(df)

    out_file = output_dir / f"ttp_mappings_{datetime.now().strftime('%Y%m%d')}.csv"
    df.to_csv(out_file, index=False)
    logger.info("TTP mappings saved to %s", out_file)

    json_out = output_dir / f"ttp_mappings_{datetime.now().strftime('%Y%m%d')}.json"
    df.to_json(json_out, orient="records", indent=2)
    logger.info("JSON output saved to %s", json_out)


if __name__ == "__main__":
    main()

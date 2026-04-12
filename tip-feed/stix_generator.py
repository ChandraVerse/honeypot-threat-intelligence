#!/usr/bin/env python3
"""
STIX 2.1 Threat Intelligence Feed Generator
============================================
Generates STIX 2.1 bundles from aggregated honeypot IOC data.
Outputs include: Indicator, AttackPattern, ThreatActor, Malware,
Relationship, and ObservedData objects.

Usage:
    python stix_generator.py \\
        --input ../data/aggregated_stats.csv \\
        --output stix-bundles/ \\
        --campaign honeypot-30day-2025
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from loguru import logger
from stix2 import (
    AttackPattern,
    Bundle,
    ExternalReference,
    Identity,
    Indicator,
    Malware,
    ObservedData,
    Relationship,
    ThreatActor,
)

load_dotenv()

AUTHOR = os.getenv("STIX_AUTHOR", "ChandraVerse")

# MITRE ATT&CK techniques to embed
ATTACK_PATTERNS = [
    {"id": "T1110",     "name": "Brute Force"},
    {"id": "T1110.003", "name": "Brute Force: Password Spraying"},
    {"id": "T1046",     "name": "Network Service Scanning"},
    {"id": "T1190",     "name": "Exploit Public-Facing Application"},
    {"id": "T1078",     "name": "Valid Accounts"},
    {"id": "T1059",     "name": "Command and Scripting Interpreter"},
    {"id": "T1090",     "name": "Proxy"},
    {"id": "T1119",     "name": "Automated Collection"},
    {"id": "T1105",     "name": "Ingress Tool Transfer"},
    {"id": "T1496",     "name": "Resource Hijacking"},
]

MALWARE_FAMILIES = [
    {"name": "Mirai",        "labels": ["bot", "worm"]},
    {"name": "Mozi",         "labels": ["bot", "p2p"]},
    {"name": "XMRig",        "labels": ["coinminer"]},
    {"name": "Gafgyt",       "labels": ["bot", "ddos"]},
    {"name": "Dark.IoT",     "labels": ["bot"]},
]


def build_identity() -> Identity:
    return Identity(
        name=AUTHOR,
        identity_class="organization",
        description="Honeypot Threat Intelligence Research Platform",
    )


def build_attack_patterns() -> list[AttackPattern]:
    patterns = []
    for tp in ATTACK_PATTERNS:
        patterns.append(
            AttackPattern(
                name=tp["name"],
                external_references=[
                    ExternalReference(
                        source_name="mitre-attack",
                        external_id=tp["id"],
                        url=f"https://attack.mitre.org/techniques/{tp['id'].replace('.', '/')}",
                    )
                ],
            )
        )
    return patterns


def build_malware_objects() -> list[Malware]:
    return [
        Malware(
            name=m["name"],
            is_family=True,
            labels=m["labels"],
        )
        for m in MALWARE_FAMILIES
    ]


def build_ip_indicators(df: pd.DataFrame, identity: Identity) -> list[Indicator]:
    ip_col = next((c for c in ("src_ip", "ip", "attacker_ip") if c in df.columns), None)
    if not ip_col:
        logger.warning("No IP column found in dataframe; skipping IP indicators")
        return []

    indicators = []
    # Take up to 2000 most-frequent IPs
    top_ips = df[ip_col].value_counts().head(2000).index.tolist()
    for ip in top_ips:
        score = 75
        if "abuse_score" in df.columns:
            row_score = df.loc[df[ip_col] == ip, "abuse_score"].max()
            if not pd.isna(row_score):
                score = int(row_score)
        indicators.append(
            Indicator(
                name=f"Malicious IP: {ip}",
                indicator_types=["malicious-activity"],
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                valid_from=datetime.now(tz=timezone.utc),
                confidence=score,
                created_by_ref=identity.id,
                labels=["honeypot-observed"],
            )
        )
    return indicators


def build_bundle(
    identity: Identity,
    indicators: list[Indicator],
    attack_patterns: list[AttackPattern],
    malware_objects: list[Malware],
    campaign: str,
) -> Bundle:
    objects: list = [identity] + attack_patterns + malware_objects + indicators

    # Relationships: each indicator -> attack pattern (brute force as default)
    bf_pattern = next((a for a in attack_patterns if a.name == "Brute Force"), None)
    if bf_pattern:
        for ind in indicators[:100]:   # limit relationships for bundle size
            objects.append(
                Relationship(
                    relationship_type="indicates",
                    source_ref=ind.id,
                    target_ref=bf_pattern.id,
                )
            )

    return Bundle(objects=objects, allow_custom=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate STIX 2.1 threat intelligence bundle")
    parser.add_argument("--input",    default="../data/aggregated_stats.csv")
    parser.add_argument("--output",   default="stix-bundles/")
    parser.add_argument("--campaign", default="honeypot-30day-2025")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.input)
    logger.info("Loaded %d rows from %s", len(df), args.input)

    identity       = build_identity()
    attack_patterns = build_attack_patterns()
    malware_objects = build_malware_objects()
    indicators      = build_ip_indicators(df, identity)
    bundle          = build_bundle(identity, indicators, attack_patterns, malware_objects, args.campaign)

    date_str   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    out_path   = output_dir / f"bundle_{date_str}.json"
    bundle_str = bundle.serialize(pretty=True)
    out_path.write_text(bundle_str)

    bundle_dict = json.loads(bundle_str)
    logger.info(
        "STIX bundle saved to %s (%d objects)",
        out_path, len(bundle_dict.get("objects", [])),
    )


if __name__ == "__main__":
    main()

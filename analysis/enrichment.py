#!/usr/bin/env python3
"""
Threat Enrichment Engine
========================
Enriches extracted IOCs (IPs) with threat intelligence data from:
  - Shodan: port scan history, open services, vulnerability tags
  - AbuseIPDB: abuse confidence score, usage type, ISP
  - VirusTotal: detection ratio, community votes
  - MaxMind GeoLite2: country, city, ASN

Usage:
    python enrichment.py --input ../data/aggregated_stats.csv
    python enrichment.py --input ../tip-feed/iocs_ips_20250101.txt --rate-limit 1.0
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any

import geoip2.database
import pandas as pd
import requests
import shodan
from dotenv import load_dotenv
from loguru import logger
from rich.progress import track

load_dotenv()

SHODAN_KEY  = os.getenv("SHODAN_API_KEY",  "")
ABUSE_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
VT_KEY      = os.getenv("VT_API_KEY",       "")
GEO_DB_PATH = os.getenv("GEO_DB_PATH",     "./data/GeoLite2-City.mmdb")


def geo_lookup(ip: str, reader: geoip2.database.Reader) -> dict[str, str]:
    try:
        r = reader.city(ip)
        return {
            "country_code":  r.country.iso_code or "",
            "country_name":  r.country.name or "",
            "city":          r.city.name or "",
            "latitude":      str(r.location.latitude or ""),
            "longitude":     str(r.location.longitude or ""),
            "asn":           str(r.traits.autonomous_system_number or ""),
            "org":           r.traits.organization or "",
        }
    except Exception:
        return {"country_code": "XX", "country_name": "Unknown", "city": "",
                "latitude": "", "longitude": "", "asn": "", "org": ""}


def shodan_lookup(ip: str, api: shodan.Shodan) -> dict[str, Any]:
    try:
        host = api.host(ip)
        return {
            "shodan_ports":   ",".join(str(p) for p in host.get("ports", [])),
            "shodan_vulns":   ",".join(host.get("vulns", {}).keys()),
            "shodan_tags":    ",".join(host.get("tags", [])),
            "shodan_org":     host.get("org", ""),
            "shodan_os":      host.get("os", ""),
        }
    except shodan.exception.APIError:
        return {"shodan_ports": "", "shodan_vulns": "", "shodan_tags": "",
                "shodan_org": "", "shodan_os": ""}


def abuseipdb_lookup(ip: str) -> dict[str, Any]:
    if not ABUSE_KEY:
        return {}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "abuse_score":        d.get("abuseConfidenceScore", 0),
            "abuse_total_reports":d.get("totalReports", 0),
            "abuse_usage_type":   d.get("usageType", ""),
            "abuse_isp":          d.get("isp", ""),
            "abuse_is_tor":       d.get("isTor", False),
        }
    except requests.RequestException as exc:
        logger.warning("AbuseIPDB error for %s: %s", ip, exc)
        return {}


def virustotal_lookup(ip: str) -> dict[str, Any]:
    if not VT_KEY:
        return {}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 404:
            return {"vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 0}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "vt_malicious":  stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless":   stats.get("harmless", 0),
        }
    except requests.RequestException as exc:
        logger.warning("VirusTotal error for %s: %s", ip, exc)
        return {}


def enrich_ips(ips: list[str], rate_limit: float) -> pd.DataFrame:
    shodan_api = shodan.Shodan(SHODAN_KEY) if SHODAN_KEY else None
    geo_reader = None
    if Path(GEO_DB_PATH).exists():
        geo_reader = geoip2.database.Reader(GEO_DB_PATH)
    else:
        logger.warning("GeoLite2 DB not found at %s — geo fields will be empty", GEO_DB_PATH)

    rows = []
    for ip in track(ips, description="Enriching IPs..."):
        row: dict[str, Any] = {"ip": ip}
        if geo_reader:
            row.update(geo_lookup(ip, geo_reader))
        if shodan_api:
            row.update(shodan_lookup(ip, shodan_api))
        row.update(abuseipdb_lookup(ip))
        row.update(virustotal_lookup(ip))
        rows.append(row)
        time.sleep(rate_limit)

    if geo_reader:
        geo_reader.close()
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich IOC IPs with threat intelligence")
    parser.add_argument("--input",      default="../data/aggregated_stats.csv",
                        help="Input file: CSV with 'src_ip' column or plain IP list (.txt)")
    parser.add_argument("--output",     default="../data/enriched_ips.csv",
                        help="Output enriched CSV")
    parser.add_argument("--rate-limit", type=float, default=1.0,
                        help="Seconds to wait between API calls (default: 1.0)")
    parser.add_argument("--limit",      type=int,   default=500,
                        help="Max IPs to enrich (default: 500)")
    args = parser.parse_args()

    p = Path(args.input)
    if p.suffix == ".txt":
        ips = [line.strip() for line in p.read_text().splitlines() if line.strip()]
    else:
        df_in = pd.read_csv(p)
        ip_col = next((c for c in ("src_ip", "ip", "attacker_ip") if c in df_in.columns), None)
        if not ip_col:
            logger.error("No IP column found in %s", args.input)
            sys.exit(1)
        ips = df_in[ip_col].dropna().unique().tolist()

    ips = ips[: args.limit]
    logger.info("Enriching %d unique IPs...", len(ips))

    df_out = enrich_ips(ips, args.rate_limit)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(out_path, index=False)
    logger.info("Enriched data saved to %s (%d rows)", out_path, len(df_out))


if __name__ == "__main__":
    main()

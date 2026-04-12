#!/usr/bin/env python3
"""
run_pipeline.py — Master Orchestrator
======================================
Runs the full Honeypot TIP analysis pipeline end-to-end:

  Step 1: Extract TTPs from Elasticsearch logs
  Step 2: Aggregate and deduplicate IOCs
  Step 3: Enrich IOCs with Shodan / AbuseIPDB / VirusTotal / GeoIP
  Step 4: Generate geographic visualizations
  Step 5: Run K-Means cluster analysis on attacker behaviour
  Step 6: Generate STIX 2.1 bundle
  Step 7: Export MISP-compatible JSON

Usage:
    python analysis/run_pipeline.py [--days 30] [--skip-enrich] [--dry-run]

Requires:
    .env file with all API keys configured (see .env.example)
"""

import argparse
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

# --- Logging Setup -----------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"pipeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
    ],
)
log = logging.getLogger("pipeline")

# --- Environment -------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    log.warning("python-dotenv not installed — relying on system environment variables")

import os

REQUIRED_ENV = ["ELASTICSEARCH_HOST", "ELASTICSEARCH_PORT"]
for key in REQUIRED_ENV:
    if not os.getenv(key):
        log.error(f"Missing required environment variable: {key}")
        log.error("Copy .env.example to .env and fill in your values.")
        sys.exit(1)

# --- Step Runner -------------------------------------------------------------

STEPS = [
    ("TTP Extraction",          "ttp_extractor",    "run"),
    ("IOC Aggregation",         "ioc_aggregator",   "run"),
    ("IOC Enrichment",          "enrichment",       "run"),
    ("Geographic Visualization","geo_visualizer",   "run"),
    ("Cluster Analysis",        "cluster_analysis", "run"),
]


def run_step(step_name: str, module_name: str, func_name: str, args: argparse.Namespace) -> bool:
    """Import and execute a pipeline step module."""
    log.info(f"{'='*60}")
    log.info(f"  STEP: {step_name}")
    log.info(f"{'='*60}")
    start = time.time()
    try:
        import importlib
        module = importlib.import_module(f"analysis.{module_name}")
        func = getattr(module, func_name)
        func(days=args.days, dry_run=args.dry_run)
        elapsed = time.time() - start
        log.info(f"  ✓ {step_name} completed in {elapsed:.1f}s")
        return True
    except Exception as exc:
        log.error(f"  ✗ {step_name} failed: {exc}", exc_info=True)
        return False


def run_stix_generation(args: argparse.Namespace) -> bool:
    """Generate STIX 2.1 bundle from enriched IOC data."""
    log.info(f"{'='*60}")
    log.info("  STEP: STIX 2.1 Bundle Generation")
    log.info(f"{'='*60}")
    start = time.time()
    try:
        import importlib
        module = importlib.import_module("tip-feed.stix_generator")
        module.generate_bundle(dry_run=args.dry_run)
        elapsed = time.time() - start
        log.info(f"  ✓ STIX bundle generated in {elapsed:.1f}s")
        return True
    except Exception as exc:
        log.error(f"  ✗ STIX generation failed: {exc}", exc_info=True)
        return False


def run_misp_export(args: argparse.Namespace) -> bool:
    """Export MISP-compatible events from STIX bundle."""
    log.info(f"{'='*60}")
    log.info("  STEP: MISP Export")
    log.info(f"{'='*60}")
    start = time.time()
    try:
        import importlib
        module = importlib.import_module("tip-feed.misp_export")
        module.export(dry_run=args.dry_run)
        elapsed = time.time() - start
        log.info(f"  ✓ MISP export completed in {elapsed:.1f}s")
        return True
    except Exception as exc:
        log.error(f"  ✗ MISP export failed: {exc}", exc_info=True)
        return False


def print_summary(results: dict, total_time: float):
    """Print pipeline execution summary."""
    passed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    print("\n" + "="*60)
    print("  PIPELINE SUMMARY")
    print("="*60)
    for step, ok in results.items():
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  [{status}] {step}")
    print("-"*60)
    print(f"  Passed: {passed}/{len(results)}   Failed: {failed}   Time: {total_time:.1f}s")
    print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Honeypot TIP — Full Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analysis/run_pipeline.py                    # Full 30-day run
  python analysis/run_pipeline.py --days 7           # Last 7 days only
  python analysis/run_pipeline.py --skip-enrich      # Skip API enrichment (no keys needed)
  python analysis/run_pipeline.py --dry-run          # Validate config without executing
"""
    )
    parser.add_argument("--days", type=int, default=30, help="Number of days to analyse (default: 30)")
    parser.add_argument("--skip-enrich", action="store_true", help="Skip Shodan/AbuseIPDB/VT enrichment")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and exit without running")
    parser.add_argument("--steps", nargs="+", help="Run specific steps only (e.g. --steps ttp ioc)")
    args = parser.parse_args()

    log.info("Honeypot TIP Analysis Pipeline")
    log.info(f"  Analysis window : {args.days} days")
    log.info(f"  Enrichment      : {'DISABLED' if args.skip_enrich else 'ENABLED'}")
    log.info(f"  Dry run         : {args.dry_run}")

    if args.dry_run:
        log.info("Dry run — configuration valid. Exiting.")
        sys.exit(0)

    pipeline_start = time.time()
    results = {}

    # Analysis steps
    for step_name, module_name, func_name in STEPS:
        if module_name == "enrichment" and args.skip_enrich:
            log.info(f"Skipping {step_name} (--skip-enrich)")
            results[step_name] = True
            continue
        ok = run_step(step_name, module_name, func_name, args)
        results[step_name] = ok
        if not ok:
            log.warning(f"Step '{step_name}' failed — continuing pipeline")

    # TIP feed generation
    results["STIX 2.1 Bundle"] = run_stix_generation(args)
    results["MISP Export"] = run_misp_export(args)

    total_time = time.time() - pipeline_start
    print_summary(results, total_time)

    # Exit 1 if any step failed
    if any(not v for v in results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()

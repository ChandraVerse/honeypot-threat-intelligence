#!/usr/bin/env python3
"""
Local TAXII 2.0 Server
======================
Serves STIX 2.1 bundles via a minimal TAXII 2.0-compatible REST API.
Optional — enables consumers (e.g., OpenCTI, MISP) to pull the feed
automatically using the TAXII protocol.

Usage:
    python taxii_server.py
    python taxii_server.py --host 0.0.0.0 --port 6000 --stix-dir stix-bundles/
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

load_dotenv()

STIX_DIR = Path(os.getenv("STIX_OUTPUT_DIR", "./stix-bundles/"))
COLLECTION_ID = os.getenv("TAXII_COLLECTION_ID", "honeypot-ioc-feed")

app = FastAPI(
    title="Honeypot TAXII 2.0 Server",
    description="TAXII 2.0 feed of honeypot-derived STIX 2.1 threat intelligence",
    version="1.0.0",
)

TAXII_CONTENT_TYPE = "application/vnd.oasis.taxii+json;version=2.0"
STIX_CONTENT_TYPE  = "application/vnd.oasis.stix+json;version=2.1"


@app.get("/taxii/")
async def taxii_discovery():
    return JSONResponse(
        content={
            "title":       "Honeypot Threat Intelligence TAXII Server",
            "description": "Live IOC feed from T-Pot honeypot deployment",
            "contact":     "https://github.com/ChandraVerse/honeypot-threat-intelligence",
            "default":     "/taxii/api-root/",
            "api_roots":   ["/taxii/api-root/"],
        },
        media_type=TAXII_CONTENT_TYPE,
    )


@app.get("/taxii/api-root/")
async def api_root():
    return JSONResponse(
        content={
            "title":               "Honeypot IOC Feed — API Root",
            "versions":            ["taxii-2.0"],
            "max_content_length":  104_857_600,
        },
        media_type=TAXII_CONTENT_TYPE,
    )


@app.get("/taxii/api-root/collections/")
async def list_collections():
    return JSONResponse(
        content={
            "collections": [
                {
                    "id":          COLLECTION_ID,
                    "title":       "Honeypot IOC Feed",
                    "description": "Malicious IPs, file hashes, and domains observed by T-Pot honeypot",
                    "can_read":    True,
                    "can_write":   False,
                    "media_types": [STIX_CONTENT_TYPE],
                }
            ]
        },
        media_type=TAXII_CONTENT_TYPE,
    )


@app.get("/taxii/api-root/collections/{collection_id}/objects/")
async def get_objects(collection_id: str, added_after: str | None = None):
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Collection not found")

    bundle_files = sorted(STIX_DIR.glob("bundle_*.json"), reverse=True)
    if not bundle_files:
        raise HTTPException(status_code=404, detail="No STIX bundles found")

    if added_after:
        try:
            cutoff = datetime.fromisoformat(added_after.replace("Z", "+00:00"))
            bundle_files = [
                f for f in bundle_files
                if datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc) > cutoff
            ]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid added_after format")

    all_objects: list = []
    for bf in bundle_files:
        with open(bf) as f:
            bundle = json.load(f)
        all_objects.extend(bundle.get("objects", []))

    return JSONResponse(
        content={
            "type":    "bundle",
            "id":      f"bundle--{COLLECTION_ID}",
            "spec_version": "2.1",
            "objects": all_objects,
        },
        media_type=STIX_CONTENT_TYPE,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Start TAXII 2.0 server")
    parser.add_argument("--host",     default=os.getenv("TAXII_HOST", "127.0.0.1"))
    parser.add_argument("--port",     type=int, default=int(os.getenv("TAXII_PORT", 6000)))
    parser.add_argument("--stix-dir", default=str(STIX_DIR))
    parser.add_argument("--reload",   action="store_true", help="Enable hot-reload (dev mode)")
    args = parser.parse_args()

    global STIX_DIR
    STIX_DIR = Path(args.stix_dir)

    uvicorn.run(
        "taxii_server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()

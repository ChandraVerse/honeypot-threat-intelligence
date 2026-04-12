"""Honeypot Threat Intelligence Analysis Package.

Modules:
    ttp_extractor    - MITRE ATT&CK TTP mapping from Elasticsearch logs
    ioc_aggregator   - IOC extraction and deduplication
    enrichment       - Shodan / AbuseIPDB / VirusTotal / GeoIP enrichment
    geo_visualizer   - Geographic attack visualizations
    cluster_analysis - K-Means attacker behaviour clustering
    run_pipeline     - Master pipeline orchestrator
"""

__version__ = "1.0.0"
__author__ = "Chandra Sekhar Chakraborty"
__email__ = "contact@chandraverse.dev"

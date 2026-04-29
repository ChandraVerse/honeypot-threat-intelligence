"""pytest configuration and shared fixtures for honeypot-threat-intelligence tests."""
import pytest
import json
import os


@pytest.fixture(scope="session")
def sample_events():
    """Load sample_events.json for use across test modules."""
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'sample_events.json')
    with open(data_path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def stix_bundle_day1():
    """Load Day 1 STIX bundle for validation tests."""
    bundle_path = os.path.join(
        os.path.dirname(__file__), '..', 'tip-feed', 'stix-bundles', 'bundle_2025-01-01.json'
    )
    with open(bundle_path) as f:
        return json.load(f)


@pytest.fixture
def sample_ioc_list():
    """Return a fresh list of sample IOCs for each test."""
    return [
        {"type": "ipv4", "value": "1.2.3.x", "confidence": 92, "source": "cowrie"},
        {"type": "ipv4", "value": "5.6.7.x", "confidence": 97, "source": "dionaea"},
        {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "confidence": 99, "source": "dionaea"},
        {"type": "domain", "value": "malicious-c2.example.com", "confidence": 88, "source": "cowrie"},
    ]


@pytest.fixture
def sample_event():
    """Return a single valid honeypot event dict."""
    return {
        "timestamp": "2025-01-01T02:14:00.000Z",
        "src_ip": "1.2.3.x",
        "src_port": 54321,
        "dst_port": 22,
        "honeypot_service": "cowrie",
        "event_type": "ssh.login",
        "username": "root",
        "password": "admin",
        "success": False,
        "country": "CN",
        "asn": "AS12345"
    }

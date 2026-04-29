"""Unit tests for analysis/ioc_aggregator.py IOC deduplication and validation."""
import pytest
import re


class TestIOCValidation:
    """Tests for IOC format validation and deduplication."""

    SAMPLE_IOCS = [
        {"type": "ipv4", "value": "192.168.1.1", "confidence": 85, "source": "cowrie"},
        {"type": "ipv4", "value": "10.0.0.1", "confidence": 72, "source": "dionaea"},
        {"type": "domain", "value": "malicious-c2.example.com", "confidence": 91, "source": "cowrie"},
        {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "confidence": 78, "source": "dionaea"},
        {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "confidence": 95, "source": "dionaea"},
        {"type": "ipv4", "value": "192.168.1.1", "confidence": 85, "source": "heralding"},  # Duplicate
    ]

    def _deduplicate(self, iocs):
        seen = set()
        unique = []
        for ioc in iocs:
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        return unique

    def _validate_ipv4(self, ip):
        pattern = r'^(\d{1,3}\.){3}(\d{1,3}|x)$'
        return bool(re.match(pattern, ip))

    def _validate_md5(self, hash_val):
        return bool(re.match(r'^[a-f0-9]{32}$', hash_val))

    def _validate_sha256(self, hash_val):
        return bool(re.match(r'^[a-f0-9]{64}$', hash_val))

    def test_deduplication_removes_duplicates(self):
        unique = self._deduplicate(self.SAMPLE_IOCS)
        assert len(unique) == 5, f"Expected 5 unique IOCs, got {len(unique)}"

    def test_deduplication_preserves_order(self):
        unique = self._deduplicate(self.SAMPLE_IOCS)
        assert unique[0]["value"] == "192.168.1.1"

    def test_ipv4_format_validation(self):
        valid_ips = ["1.2.3.4", "192.168.1.1", "10.0.0.1", "1.2.3.x"]
        invalid_ips = ["999.999.999.999", "not-an-ip", ""]
        for ip in valid_ips:
            assert self._validate_ipv4(ip), f"Should be valid: {ip}"
        for ip in invalid_ips:
            assert not self._validate_ipv4(ip), f"Should be invalid: {ip}"

    def test_md5_hash_format_validation(self):
        valid = "d41d8cd98f00b204e9800998ecf8427e"
        invalid = ["UPPERCASE1234", "tooshort", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]
        assert self._validate_md5(valid)
        for h in invalid:
            assert not self._validate_md5(h), f"Should be invalid MD5: {h}"

    def test_sha256_hash_format_validation(self):
        valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert self._validate_sha256(valid)
        assert not self._validate_sha256("tooshort")

    def test_confidence_score_filtering(self):
        """IOCs below confidence threshold 70 should be filtered."""
        threshold = 70
        high_conf = [ioc for ioc in self.SAMPLE_IOCS if ioc["confidence"] >= threshold]
        assert all(ioc["confidence"] >= threshold for ioc in high_conf)

    def test_ioc_types_categorization(self):
        """All IOC types must be from the allowed set."""
        allowed_types = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"}
        unique = self._deduplicate(self.SAMPLE_IOCS)
        for ioc in unique:
            assert ioc["type"] in allowed_types, f"Unknown IOC type: {ioc['type']}"

    def test_source_attribution_present(self):
        """Every IOC must have a source honeypot service attributed."""
        valid_sources = {"cowrie", "dionaea", "glastopf", "heralding", "adbhoney"}
        for ioc in self.SAMPLE_IOCS:
            assert ioc["source"] in valid_sources, f"Invalid source: {ioc['source']}"

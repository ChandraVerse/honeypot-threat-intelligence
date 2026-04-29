"""Unit tests for tip-feed/stix_generator.py STIX 2.1 output validation."""
import pytest
import json
import os


class TestSTIXBundleStructure:
    """Validate structure of generated STIX 2.1 bundles."""

    BUNDLE_DIR = os.path.join(os.path.dirname(__file__), '..', 'tip-feed', 'stix-bundles')

    def _load_bundle(self, filename):
        path = os.path.join(self.BUNDLE_DIR, filename)
        with open(path) as f:
            return json.load(f)

    def _get_bundle_files(self):
        if not os.path.exists(self.BUNDLE_DIR):
            return []
        return [f for f in os.listdir(self.BUNDLE_DIR) if f.endswith('.json')]

    def test_bundles_exist(self):
        """At least one STIX bundle must exist in stix-bundles/."""
        bundles = self._get_bundle_files()
        assert len(bundles) >= 1, "No STIX bundles found in tip-feed/stix-bundles/"

    def test_bundle_type_is_bundle(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            assert bundle.get("type") == "bundle", f"{fname}: type must be 'bundle'"

    def test_bundle_spec_version_is_21(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            assert bundle.get("spec_version") == "2.1", f"{fname}: spec_version must be '2.1'"

    def test_bundle_has_objects_array(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            assert "objects" in bundle, f"{fname}: missing 'objects' array"
            assert isinstance(bundle["objects"], list), f"{fname}: 'objects' must be a list"
            assert len(bundle["objects"]) > 0, f"{fname}: 'objects' array is empty"

    def test_bundle_has_identity_object(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            identities = [o for o in bundle["objects"] if o["type"] == "identity"]
            assert len(identities) >= 1, f"{fname}: bundle must contain at least one identity object"

    def test_bundle_has_at_least_one_indicator(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
            assert len(indicators) >= 1, f"{fname}: bundle must contain at least one indicator"

    def test_all_indicators_have_required_fields(self):
        required = ["id", "name", "pattern", "pattern_type", "valid_from", "confidence"]
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            for obj in bundle["objects"]:
                if obj["type"] == "indicator":
                    for field in required:
                        assert field in obj, f"{fname} indicator '{obj.get('name','?')}': missing '{field}'"

    def test_indicator_confidence_in_valid_range(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            for obj in bundle["objects"]:
                if obj["type"] == "indicator":
                    conf = obj.get("confidence", -1)
                    assert 0 <= conf <= 100, f"{fname}: confidence {conf} out of range [0,100]"

    def test_all_attack_patterns_have_mitre_reference(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            for obj in bundle["objects"]:
                if obj["type"] == "attack-pattern":
                    refs = obj.get("external_references", [])
                    mitre_refs = [r for r in refs if r.get("source_name") == "mitre-attack"]
                    assert len(mitre_refs) >= 1, (
                        f"{fname}: attack-pattern '{obj.get('name')}' missing MITRE ATT&CK reference"
                    )

    def test_relationships_reference_existing_objects(self):
        for fname in self._get_bundle_files():
            bundle = self._load_bundle(fname)
            all_ids = {o["id"] for o in bundle["objects"]}
            for obj in bundle["objects"]:
                if obj["type"] == "relationship":
                    src = obj.get("source_ref", "")
                    tgt = obj.get("target_ref", "")
                    assert src in all_ids, f"{fname}: relationship source_ref '{src}' not in bundle"
                    assert tgt in all_ids, f"{fname}: relationship target_ref '{tgt}' not in bundle"

"""Synthetic cases and contract validation of live local binary output."""
import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("validate_inventory", ROOT / "scripts/validate_inventory.py")
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = validation.validator()
        cls.synthetic = json.loads((ROOT / "tests/fixtures/synthetic-inventory.json").read_text())

    def invalid(self, report):
        self.assertTrue(list(self.validator.iter_errors(report)))

    def test_synthetic_fixture_is_labeled_and_valid(self):
        self.assertEqual(self.synthetic["origin"], "synthetic")
        self.validator.validate(self.synthetic)

    def test_live_binary_matches_contract(self):
        binary = os.environ.get("LGI_AGENT_BIN", str(ROOT / "target/debug/lgi-agent"))
        report = json.loads(subprocess.check_output([binary], timeout=10))
        self.validator.validate(report)
        self.assertEqual(report["origin"], "live")

    def test_cannot_claim_acceptance_or_verification(self):
        for field in ["result", *self.synthetic["evidence"]]:
            with self.subTest(field=field):
                report = copy.deepcopy(self.synthetic)
                if field == "result":
                    report[field] = "ACCEPTED"
                else:
                    report["evidence"][field] = True
                self.invalid(report)

    def test_extra_fields_are_rejected_at_each_object_level(self):
        for path in [(), ("platform",), ("platform", "secureBoot"), ("evidence",), ("platform", "tpm")]:
            report = copy.deepcopy(self.synthetic)
            node = report
            for key in path:
                node = node[key]
            node["quoteVerified"] = True
            self.invalid(report)

    def test_required_field_version_and_types(self):
        for key in self.synthetic:
            report = copy.deepcopy(self.synthetic)
            del report[key]
            self.invalid(report)
        for value in [2, "1", None, True]:
            report = copy.deepcopy(self.synthetic)
            report["schemaVersion"] = value
            self.invalid(report)

    def test_unknown_cannot_be_represented_as_false_or_known_value(self):
        report = copy.deepcopy(self.synthetic)
        observation = report["platform"]["secureBoot"]
        observation.update(status="unavailable", value="disabled", error="not_found")
        self.invalid(report)
        observation.update(value=None)
        self.validator.validate(report)
        observation.update(status="observed", error=None)
        self.invalid(report)

    def test_unavailable_and_permission_denied_are_distinct(self):
        report = copy.deepcopy(self.synthetic)
        observation = report["platform"]["secureBoot"]
        observation.update(status="error", value=None, error="permission_denied")
        self.validator.validate(report)
        observation["status"] = "unavailable"
        self.invalid(report)

    def test_limits(self):
        report = copy.deepcopy(self.synthetic)
        report["platform"]["kernelRelease"]["value"] = "x" * 257
        self.invalid(report)
        report = copy.deepcopy(self.synthetic)
        module = {"name":"synthetic", "sizeBytes":0, "referenceCount":0, "state":"Live"}
        report["platform"]["loadedModules"]["value"] = [module] * 4097
        self.invalid(report)

    def test_duplicate_keys_invalid_json_and_byte_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic.json"
            for payload in [b'{"schemaVersion":1,"schemaVersion":1}', b'not-json', b' ' * (validation.MAX_REPORT_BYTES + 1)]:
                path.write_bytes(payload)
                with self.assertRaises(ValueError):
                    validation.read_report(path)


if __name__ == "__main__":
    unittest.main()

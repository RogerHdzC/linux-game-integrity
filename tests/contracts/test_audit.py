"""Synthetic tests of OSV response handling."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("audit", ROOT / "scripts/audit_dependencies.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.requests = [{"package": {"name": "synthetic"}, "version": "0.0.0"}]

    def test_empty_findings(self):
        self.assertEqual(audit.evaluate(self.requests, {"results": [{}]}), [])

    def test_advisory_is_reported(self):
        result = audit.evaluate(self.requests, {"results": [{"vulns": [{"id": "SYNTHETIC-TEST"}]}]})
        self.assertEqual(result, [("synthetic", "0.0.0", "SYNTHETIC-TEST")])

    def test_incomplete_or_paginated_response_fails(self):
        for response in [{}, {"results": []}, {"results": [{"next_page_token": "synthetic"}]}, {"results": [{"error": "failure"}]}, {"results": [{"vulns": None}]}]:
            with self.assertRaises(ValueError):
                audit.evaluate(self.requests, response)

    def test_all_pinned_dependencies_are_queried(self):
        requests = audit.queries()
        self.assertTrue(any(p["package"]["ecosystem"] == "crates.io" for p in requests))
        self.assertTrue(any(p["package"]["ecosystem"] == "PyPI" for p in requests))

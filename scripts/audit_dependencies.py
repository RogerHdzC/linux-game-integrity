#!/usr/bin/env python3
"""Query OSV with dependency names/versions; never send inventory data."""
import json
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def queries():
    packages = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    result = [
        {"package": {"name": p["name"], "ecosystem": "crates.io"}, "version": p["version"]}
        for p in packages if p.get("source", "").startswith("registry+")
    ]
    for line in (ROOT / "tests/requirements.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, version = line.split("==")
        result.append({"package": {"name": name, "ecosystem": "PyPI"}, "version": version})
    return result


def evaluate(requests, response):
    results = response.get("results")
    if not isinstance(results, list) or len(results) != len(requests):
        raise ValueError("Incomplete OSV response")
    found = []
    for package, result in zip(requests, results):
        if not isinstance(result, dict) or result.get("next_page_token") or result.get("error"):
            raise ValueError("Incomplete or paginated OSV response; review required")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("Invalid OSV response")
        for vulnerability in vulnerabilities:
            found.append((package["package"]["name"], package["version"], vulnerability["id"]))
    return found


def main():
    try:
        packages = queries()
        request = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=json.dumps({"queries": packages}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            findings = evaluate(packages, json.load(response))
        for name, version, advisory in findings:
            print(f"{name} {version}: {advisory}")
        if findings:
            return 1
        print(f"OSV: {len(packages)} versions queried, no known advisories returned by this query.")
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print("Dependency audit incomplete; this is not a passing result.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

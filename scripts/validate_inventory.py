#!/usr/bin/env python3
"""Validate format and limits; does NOT verify integrity or authenticity."""
import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "packages/attestation-contracts/inventory-v1.schema.json"
MAX_REPORT_BYTES = 8 * 1024 * 1024


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_report(path):
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_REPORT_BYTES + 1)
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds 8 MiB")
    return json.loads(payload, object_pairs_hook=reject_duplicates)


def validator():
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        report = read_report(args.report)
        errors = list(validator().iter_errors(report))
        if errors:
            for error in errors[:10]:
                print(f"Invalid contract at: {error.json_path}", file=sys.stderr)
            return 1
    except (OSError, ValueError, RecursionError):
        print("Could not read a valid JSON report within the limits.", file=sys.stderr)
        return 1
    print("Valid v1 contract; unverified data, INDETERMINATE result.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

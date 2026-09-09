"""
TraceMail AI — Team Reports: Reports Engine
File   : team_reports/reports/schemas/report_schema.py
Purpose: Exports the JSON Schema (Draft-07) for the forensic report.
         Generated from Pydantic models to guarantee schema stays in sync
         with the code.

Usage:
    # Export static JSON schema file (run once, commit to repo)
    python -m team_reports.reports.schemas.report_schema

    # Use in tests
    from team_reports.reports.schemas.report_schema import get_report_schema, validate_report_dict

Integration:
    - Contract tests import validate_report_dict() to assert every API
      response conforms to this schema.
    - CI generates report_schema.json and checks for drift.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from team_reports.reports.json.json_report import JSONReport

# ── Path where the static JSON schema file is written ───────────────────────
_SCHEMA_FILE = Path(__file__).parent / "report_schema.json"


def get_report_schema() -> dict[str, Any]:
    """
    Return the JSON Schema (Draft-07) for JSONReport, generated from
    the Pydantic model.

    The schema is augmented with:
    - $schema declaration
    - title / description
    - additionalProperties: false (strict validation)

    Returns:
        dict: Full JSON Schema dictionary.
    """
    raw_schema = JSONReport.model_json_schema()

    # Pydantic generates Draft-2020-12; we annotate as Draft-07 for
    # compatibility with jsonschema and schemathesis.
    schema: dict[str, Any] = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        **raw_schema,
        "title": "TraceMail AI Forensic Report",
        "description": (
            "Machine-readable JSON forensic report produced by the "
            "TraceMail AI Reports Engine (SIH26106 Team Reports). "
            "Covers all 10 investigation sections."
        ),
    }
    return schema


def write_schema_file(path: Path = _SCHEMA_FILE) -> None:
    """
    Write the JSON schema to a static .json file.
    Called during CI to detect schema drift.

    Args:
        path: Destination path for the JSON schema file.
    """
    schema = get_report_schema()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2, ensure_ascii=False)
    print(f"Schema written to: {path}")


def load_schema_file(path: Path = _SCHEMA_FILE) -> dict[str, Any]:
    """
    Load the static JSON schema from disk.

    Args:
        path: Path to the JSON schema file.

    Returns:
        dict: Loaded JSON Schema.

    Raises:
        FileNotFoundError: If schema file does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Schema file not found: {path}. "
            "Run: python -m team_reports.reports.schemas.report_schema"
        )
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def validate_report_dict(data: dict[str, Any]) -> list[str]:
    """
    Validate a raw dict (e.g. parsed API response) against the report schema.

    Args:
        data: Dictionary to validate.

    Returns:
        list[str]: List of validation error messages.
                   Empty list means the data is valid.
    """
    schema = get_report_schema()
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: str(e.path))
    return [f"{'.'.join(str(p) for p in e.path) or 'root'}: {e.message}" for e in errors]


def assert_valid_report(data: dict[str, Any]) -> None:
    """
    Assert that data conforms to the report schema.
    Raises AssertionError with a formatted message if invalid.
    Use this in pytest tests for clear failure messages.

    Args:
        data: Dictionary to validate.

    Raises:
        AssertionError: With list of all schema violations.
    """
    errors = validate_report_dict(data)
    if errors:
        error_list = "\n  • ".join(errors)
        raise AssertionError(
            f"Report schema validation failed ({len(errors)} error(s)):\n  • {error_list}"
        )


def check_schema_drift(path: Path = _SCHEMA_FILE) -> bool:
    """
    Compare the schema currently generated from code against the committed
    static file. Returns True if they match (no drift).

    Args:
        path: Path to the committed JSON schema file.

    Returns:
        bool: True = no drift, False = schema has changed.
    """
    current = get_report_schema()

    if not path.exists():
        print(f"[DRIFT] Schema file missing: {path}", file=sys.stderr)
        return False

    committed = load_schema_file(path)

    if current != committed:
        print(
            "[DRIFT] Schema has changed. Run: python -m team_reports.reports.schemas.report_schema",
            file=sys.stderr,
        )
        return False

    print("[OK] Schema is up-to-date.")
    return True


# ── CLI: python -m team_reports.reports.schemas.report_schema ────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TraceMail AI Report Schema CLI")
    parser.add_argument(
        "--check-drift",
        action="store_true",
        help="Check if generated schema matches committed file (exit 1 on drift)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_SCHEMA_FILE,
        help=f"Output path (default: {_SCHEMA_FILE})",
    )
    args = parser.parse_args()

    if args.check_drift:
        ok = check_schema_drift(args.output)
        sys.exit(0 if ok else 1)
    else:
        write_schema_file(args.output)

"""
TraceMail AI — Team Reports
File   : team_reports/tests/unit/test_report_schema.py
Purpose: Unit tests for JSON Schema generator, validator, and drift detection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from team_reports.reports.schemas.report_schema import (
    _SCHEMA_FILE,
    assert_valid_report,
    check_schema_drift,
    get_report_schema,
    load_schema_file,
    validate_report_dict,
    write_schema_file,
)


def test_get_report_schema() -> None:
    schema = get_report_schema()
    assert isinstance(schema, dict)
    assert schema.get("$schema") == "http://json-schema.org/draft-07/schema#"
    assert "TraceMail AI Forensic Report" in schema.get("title", "")
    assert "properties" in schema


def test_load_schema_file() -> None:
    schema = load_schema_file(_SCHEMA_FILE)
    assert isinstance(schema, dict)
    assert "$schema" in schema


def test_load_schema_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "non_existent_schema.json"
    with pytest.raises(FileNotFoundError, match="Schema file not found"):
        load_schema_file(missing)


def test_validate_report_dict_valid(json_report) -> None:
    data = json.loads(json_report.model_dump_json())
    errors = validate_report_dict(data)
    assert errors == []


def test_validate_report_dict_invalid() -> None:
    bad_data = {"report_id": 123}  # invalid type and missing required fields
    errors = validate_report_dict(bad_data)
    assert len(errors) > 0


def test_assert_valid_report_success(json_report) -> None:
    data = json.loads(json_report.model_dump_json())
    assert_valid_report(data)  # Should not raise


def test_assert_valid_report_failure() -> None:
    bad_data = {"invalid": "data"}
    with pytest.raises(AssertionError, match="Report schema validation failed"):
        assert_valid_report(bad_data)


def test_check_schema_drift_true() -> None:
    assert check_schema_drift(_SCHEMA_FILE) is True


def test_check_schema_drift_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    assert check_schema_drift(missing) is False


def test_check_schema_drift_mismatch(tmp_path: Path) -> None:
    mismatched = tmp_path / "mismatched.json"
    mismatched.write_text('{"different": true}', encoding="utf-8")
    assert check_schema_drift(mismatched) is False


def test_write_schema_file(tmp_path: Path) -> None:
    out_file = tmp_path / "sub" / "output_schema.json"
    write_schema_file(out_file)
    assert out_file.exists()
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded.get("$schema") == "http://json-schema.org/draft-07/schema#"

"""정규화 CLI의 입력 검증·결과 일관성·기존 파일 보호."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing

import pytest

from gentrace_forensics import cli
from gentrace_forensics.normalization.pipeline import normalize_entries


def test_empty_input_produces_empty_valid_outputs(tmp_path):
    entries = tmp_path / "classified.jsonl"
    entries.write_bytes(b"\n \n")
    out = tmp_path / "normalized"
    assert normalize_entries(entries, out) == 0
    assert (out / "normalized.jsonl").read_bytes() == b""
    with closing(sqlite3.connect(out / "normalized.db")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 0
    report = json.loads((out / "normalization.json").read_text())
    assert report["classified_sha256"] == hashlib.sha256(entries.read_bytes()).hexdigest()


def test_invalid_record_reports_line_and_removes_new_output(tmp_path, classified_entry, capsys):
    entries = tmp_path / "classified.jsonl"
    entries.write_text(classified_entry.model_dump_json() + '\n{"not_an_entry": true}\n')
    out = tmp_path / "normalized"
    assert cli.main(["normalize", "--entries", str(entries), "--out", str(out)]) == 1
    error = capsys.readouterr().err
    assert f"{entries}:2" in error
    assert "not_an_entry" not in error
    assert not out.exists() and entries.is_file()


def test_duplicates_do_not_silently_reduce_sqlite_rows(tmp_path, classified_entry):
    entries = tmp_path / "classified.jsonl"
    entries.write_text((classified_entry.model_dump_json() + "\n") * 2)
    out = tmp_path / "normalized"
    with pytest.raises(ValueError, match="duplicate normalized source_id"):
        normalize_entries(entries, out)
    assert not out.exists()


def test_existing_output_is_preserved(tmp_path, classified_entry):
    entries = tmp_path / "classified.jsonl"
    entries.write_text(classified_entry.model_dump_json() + "\n")
    out = tmp_path / "normalized"
    out.mkdir()
    marker = out / "normalized.db"
    marker.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        normalize_entries(entries, out)
    assert marker.read_bytes() == b"keep"


def test_store_failure_cleans_new_outputs(tmp_path, classified_entry, monkeypatch):
    entries = tmp_path / "classified.jsonl"
    entries.write_text(classified_entry.model_dump_json() + "\n")

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr("gentrace_forensics.normalization.pipeline.write_sqlite", fail)
    out = tmp_path / "normalized"
    with pytest.raises(OSError, match="disk full"):
        normalize_entries(entries, out)
    assert not out.exists()


def test_sqlite_error_is_reported_without_traceback(
    tmp_path, classified_entry, monkeypatch, capsys
):
    entries = tmp_path / "classified.jsonl"
    entries.write_text(classified_entry.model_dump_json() + "\n")

    def fail(*args):
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr("gentrace_forensics.normalization.pipeline.write_sqlite", fail)
    out = tmp_path / "normalized"
    assert cli.main(["normalize", "--entries", str(entries), "--out", str(out)]) == 1
    assert "gentrace: unable to open database file" in capsys.readouterr().err
    assert not out.exists()

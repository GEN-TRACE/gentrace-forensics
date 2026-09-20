"""JSONL·SQLite 왕복, 프로필 구분, 저장 실패 시 기존 결과 보존."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gentrace_forensics.normalization.store import write_jsonl, write_sqlite
from gentrace_forensics.normalization.transform import transform
from gentrace_forensics.schemas.classification import ClassifiedEntry
from gentrace_forensics.schemas.normalization import NormalizedArtifact


def test_jsonl_and_sqlite_roundtrip(classified_entry: ClassifiedEntry, tmp_path: Path):
    records = [transform(classified_entry)]
    other = classified_entry.model_copy(deep=True)
    other.source_cache.chrome_profile = "Profile 1"
    records.append(transform(other))
    jsonl_path = tmp_path / "records.jsonl"
    db_path = tmp_path / "records.db"

    assert write_jsonl(records, jsonl_path) == 2
    assert write_sqlite(records, db_path) == 2
    assert [
        NormalizedArtifact.model_validate_json(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
    ] == records
    connection = sqlite3.connect(db_path)
    try:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM artifacts ORDER BY source_id").fetchall()
        loaded = [NormalizedArtifact.model_validate(dict(row)) for row in rows]
    finally:
        connection.close()
    assert loaded == sorted(records, key=lambda record: record.source_id)


def test_jsonl_failure_preserves_existing_file(classified_entry: ClassifiedEntry, tmp_path: Path):
    path = tmp_path / "records.jsonl"
    path.write_text("previous\n", encoding="utf-8")

    def records():
        yield transform(classified_entry)
        raise ValueError("conversion failed")

    with pytest.raises(ValueError, match="conversion failed"):
        write_jsonl(records(), path)
    assert path.read_text(encoding="utf-8") == "previous\n"
    assert sorted(item.name for item in tmp_path.iterdir()) == ["records.jsonl"]


def test_sqlite_rolls_back_incomplete_batch(classified_entry: ClassifiedEntry, tmp_path: Path):
    path = tmp_path / "records.db"
    original = transform(classified_entry)
    write_sqlite([original], path)

    def records():
        yield original.model_copy(update={"filename": "changed"})
        yield original.model_copy(update={"source_id": "new-source"})
        raise ValueError("conversion failed")

    with pytest.raises(ValueError, match="conversion failed"):
        write_sqlite(records(), path)
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute("SELECT source_id, filename FROM artifacts").fetchall()
    finally:
        connection.close()
    assert rows == [(original.source_id, original.filename)]

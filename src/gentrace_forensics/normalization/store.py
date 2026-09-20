"""NormalizedArtifact 저장 — SQLite / JSONL (필요 시 Parquet).

- SQLite: 타임라인·상관분석 쿼리용. 인덱스: timestamp, service, artifact_kind, domain.
- JSONL: 교환·감사용 평문.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from collections.abc import Iterable
from pathlib import Path

from gentrace_forensics.normalization.time import to_iso8601
from gentrace_forensics.schemas.normalization import NormalizedArtifact

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS artifacts (
    source_id       TEXT PRIMARY KEY,
    timestamp       TEXT,
    service         TEXT,
    user_id         TEXT,
    session_id      TEXT,
    event_type      TEXT,
    actor            TEXT,
    content          TEXT,
    content_type     TEXT,
    artifact_source TEXT,
    artifact_kind   TEXT,
    filename         TEXT,
    url              TEXT,
    domain           TEXT,
    sha256           TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_ts      ON artifacts(timestamp);
CREATE INDEX IF NOT EXISTS idx_artifacts_service ON artifacts(service);
CREATE INDEX IF NOT EXISTS idx_artifacts_kind    ON artifacts(artifact_kind);
CREATE INDEX IF NOT EXISTS idx_artifacts_domain  ON artifacts(domain);
"""

_INSERT_SQL = """
INSERT OR REPLACE INTO artifacts (
    source_id, timestamp, service, user_id, session_id, event_type, actor, content,
    content_type, artifact_source, artifact_kind, filename, url, domain, sha256
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _row(record: NormalizedArtifact) -> tuple[str | None, ...]:
    return (
        record.source_id,
        to_iso8601(record.timestamp),
        record.service,
        record.user_id,
        record.session_id,
        record.event_type,
        record.actor,
        record.content,
        record.content_type,
        record.artifact_source,
        record.artifact_kind,
        record.filename,
        record.url,
        record.domain,
        record.sha256,
    )


def write_sqlite(records: Iterable[NormalizedArtifact], db_path: Path) -> int:
    """레코드를 SQLite로 저장하고 처리한 레코드 수를 반환한다."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open_db(db_path) as conn:
        for record in records:
            conn.execute(_INSERT_SQL, _row(record))
            count += 1
    return count


def write_jsonl(records: Iterable[NormalizedArtifact], jsonl_path: Path) -> int:
    """UTF-8 JSONL로 원자적(atomic) 저장하고 기록 수를 반환한다."""
    jsonl_path = Path(jsonl_path)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=jsonl_path.parent,
            prefix=f".{jsonl_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            for record in records:
                payload = record.model_dump(mode="json")
                handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
                handle.write("\n")
                count += 1
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_name, jsonl_path)
        temp_name = None
        return count
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def open_db(db_path: Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    return conn

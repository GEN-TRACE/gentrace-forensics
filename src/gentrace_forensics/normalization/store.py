"""NormalizedArtifact 저장 — SQLite / JSONL (필요 시 Parquet).

- SQLite: 타임라인·상관분석 쿼리용. 인덱스: timestamp, service, artifact_kind, domain.
- JSONL: 교환·감사용 평문.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

from gentrace_forensics.schemas.normalization import NormalizedArtifact

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS artifacts (
    source_id       TEXT PRIMARY KEY,
    timestamp       TEXT,
    service         TEXT,
    user_id         TEXT,
    session_id      TEXT,
    event_type      TEXT,
    actor           TEXT,
    content         TEXT,
    content_type    TEXT,
    artifact_source TEXT,
    artifact_kind   TEXT,
    filename        TEXT,
    url             TEXT,
    domain          TEXT,
    sha256          TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_ts      ON artifacts(timestamp);
CREATE INDEX IF NOT EXISTS idx_artifacts_service ON artifacts(service);
CREATE INDEX IF NOT EXISTS idx_artifacts_kind    ON artifacts(artifact_kind);
CREATE INDEX IF NOT EXISTS idx_artifacts_domain  ON artifacts(domain);
"""


def write_sqlite(records: Iterable[NormalizedArtifact], db_path: Path) -> int:
    """레코드를 SQLite 로 저장하고 기록 수 반환."""
    raise NotImplementedError


def write_jsonl(records: Iterable[NormalizedArtifact], jsonl_path: Path) -> int:
    raise NotImplementedError


def open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    return conn

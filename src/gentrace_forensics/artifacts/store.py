"""Persist artifact evidence, relationships and validation results."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from gentrace_forensics.artifacts.models import Artifact, NetworkRecord, Relationship
from gentrace_forensics.reporting import write_report


def write_outputs(
    out: Path,
    artifacts: list[Artifact],
    relationships: list[Relationship],
    network: list[NetworkRecord],
    summary: dict[str, Any],
) -> None:
    for filename in (
        "artifacts.jsonl",
        "artifacts.sqlite3",
        "network_records.jsonl",
        "validation_summary.json",
    ):
        if (out / filename).exists():
            raise FileExistsError(f"artifact output already exists: {out / filename}")
    with (out / "artifacts.jsonl").open("x", encoding="utf-8") as output:
        for artifact in artifacts:
            output.write(artifact.model_dump_json() + "\n")
    with (out / "network_records.jsonl").open("x", encoding="utf-8") as output:
        for record in network:
            output.write(record.model_dump_json() + "\n")
    with closing(sqlite3.connect(out / "artifacts.sqlite3")) as db:
        db.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE artifacts (artifact_id TEXT PRIMARY KEY, service TEXT, role TEXT,
                attribution TEXT, recovery_status TEXT, record_json TEXT NOT NULL);
            CREATE TABLE sources (source_id TEXT PRIMARY KEY, record_json TEXT NOT NULL);
            CREATE TABLE artifact_sources (artifact_id TEXT REFERENCES artifacts, source_id TEXT REFERENCES sources,
                PRIMARY KEY (artifact_id, source_id));
            CREATE TABLE relationships (artifact_id TEXT REFERENCES artifacts, subject_id TEXT,
                relation TEXT, source_id TEXT REFERENCES sources, record_json TEXT NOT NULL);
            CREATE TABLE network_records (record_id TEXT PRIMARY KEY, service TEXT, record_json TEXT NOT NULL);
            CREATE INDEX artifacts_service_role ON artifacts(service, role);
        """)
        with db:
            for artifact in artifacts:
                db.execute(
                    "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        artifact.artifact_id,
                        artifact.service,
                        artifact.role,
                        artifact.attribution,
                        artifact.recovery_status,
                        artifact.model_dump_json(),
                    ),
                )
                for source in artifact.source_refs:
                    db.execute(
                        "INSERT OR IGNORE INTO sources VALUES (?, ?)",
                        (source.source_id, source.model_dump_json()),
                    )
                    db.execute(
                        "INSERT OR IGNORE INTO artifact_sources VALUES (?, ?)",
                        (artifact.artifact_id, source.source_id),
                    )
            for relation in relationships:
                db.execute(
                    "INSERT INTO relationships VALUES (?, ?, ?, ?, ?)",
                    (
                        relation.artifact_id,
                        relation.subject_id,
                        relation.relation,
                        relation.source_id,
                        relation.model_dump_json(),
                    ),
                )
            for record in network:
                db.execute(
                    "INSERT INTO network_records VALUES (?, ?, ?)",
                    (record.record_id, record.service, record.model_dump_json()),
                )
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("artifact database integrity check failed")
        summary["sqlite_artifact_count"] = db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[
            0
        ]
        if summary["sqlite_artifact_count"] != len(artifacts):
            raise ValueError("artifact JSONL and database counts differ")
    write_report(out / "validation_summary.json", summary)

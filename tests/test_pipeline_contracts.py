"""네이티브 E01·바이너리 파서를 대체한 단계 간 경로·데이터 계약 테스트.

획득의 파일 추출·매니페스트 작성, 분류·출력, 정규화·저장은 실제 함수를 사용한다.
실제 E01과 Blockfile 바이너리 포맷 검증을 대신하는 테스트는 아니다.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from gentrace_forensics.acquisition.extract import extract_cache, manifest_path
from gentrace_forensics.acquisition.filesystem import ProfileLocation
from gentrace_forensics.classification.blockfile.parser import HttpResponseInfo, ParsedCacheEntry
from gentrace_forensics.classification.output import classify_manifests
from gentrace_forensics.normalization.store import write_jsonl, write_sqlite
from gentrace_forensics.normalization.transform import transform_many
from gentrace_forensics.schemas.classification import ClassifiedEntry
from gentrace_forensics.schemas.normalization import NormalizedArtifact


class _FixtureFs:
    def __init__(self, cache_path: str, body: bytes):
        self.cache_path = cache_path
        self.files = {
            name: b"fixture" for name in ("index", "data_0", "data_1", "data_2", "data_3")
        }
        self.files["f_000001"] = body

    def open_dir(self, *, path: str):
        assert path == self.cache_path
        return [
            SimpleNamespace(info=SimpleNamespace(name=SimpleNamespace(name=name)))
            for name in self.files
        ]

    def open(self, *, path: str):
        data = self.files[Path(path).name]
        return SimpleNamespace(
            info=SimpleNamespace(meta=SimpleNamespace(size=len(data), addr=42)),
            read_random=lambda offset, size: data[offset : offset + size],
        )


def test_acquired_profiles_retain_evidence_through_normalized_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    acquired_dir = tmp_path / "acquired"
    manifests = []
    for number, name in enumerate(("Default", "Profile 1"), 1):
        source = f"/Users/alice/AppData/Local/Google/Chrome/User Data/{name}/Cache/Cache_Data"
        profile = ProfileLocation("alice", name, source, 1_048_576)
        fs = _FixtureFs(source, f"profile {number}".encode())
        extract_cache(
            object(),
            fs,
            profile,
            acquired_dir,
            image_path="synthetic.E01",
            image_sha256="a" * 64,
        )
        manifests.append(manifest_path(acquired_dir, profile))

    def parse(cache_dir: Path):
        # 이미 추출된 실제 파일을 읽되, 이 테스트에서는 binary parser 경계만 대체한다.
        body = (cache_dir / "f_000001").read_bytes()
        return [
            ParsedCacheEntry(
                cache_key="1/0/https://claude.ai/api/chat-1/files/file-1",
                url="https://claude.ai/api/chat-1/files/file-1",
                response=HttpResponseInfo(200, {"content-type": "image/webp"}),
                body=body,
                body_sha256=hashlib.sha256(body).hexdigest(),
                stored_body_size=len(body),
                content_encoding=None,
                source_file="f_000001",
                source_offset=0,
                entry_hash=1,
                entry_state="normal",
                cache_timestamps={
                    "creation_time_us": 13_344_473_600_000_000,
                    "response_time_us": 13_344_473_602_000_000,
                },
                warnings=["fixture provenance warning"],
            )
        ]

    monkeypatch.setattr("gentrace_forensics.classification.classify.parse_cache_dir", parse)
    out = tmp_path / "results"
    assert classify_manifests(manifests, out) == 2
    classified = [
        ClassifiedEntry.model_validate_json(line)
        for line in (out / "classified.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    records = transform_many(classified)
    assert write_jsonl(records, out / "normalized.jsonl") == 2
    assert write_sqlite(records, out / "normalized.db") == 2

    saved = [
        NormalizedArtifact.model_validate_json(line)
        for line in (out / "normalized.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    by_source = {(item.entry_id, item.source_cache.source_path): item for item in classified}
    for record in saved:
        provenance = json.loads(record.source_id)
        original = by_source[(provenance["entry_id"], provenance["cache_source_path"])]
        assert original.evidence["parse_warnings"] == ["fixture provenance warning"]
        assert original.body_path and original.body_path.is_file()
        body_hash = hashlib.sha256(original.body_path.read_bytes()).hexdigest()
        assert record.sha256 == body_hash == provenance["source_file_sha256"]
        assert provenance["image_sha256"] == "a" * 64
        assert provenance["partition_offset"] == 1_048_576
        assert record.timestamp == datetime(2023, 11, 14, 22, 13, 22, tzinfo=UTC)
        assert record.session_id == "chat-1"
        assert record.artifact_kind == "file_upload"
        assert record.content_type == "image"
    connection = sqlite3.connect(out / "normalized.db")
    try:
        assert connection.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 2
    finally:
        connection.close()

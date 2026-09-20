"""로컬 E01을 사용하는 선택적 네이티브 전체 실행 검증.

GENTRACE_E01_FIXTURE에 첫 .E01 경로를 지정한다. 기본 출력은 pytest 임시 폴더이며,
GENTRACE_E01_OUTPUT을 지정하면 그 새 폴더에 검증 결과를 보관한다.
실제 증거 데이터와 결과물은 저장소에 추가하지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from itertools import zip_longest
from pathlib import Path

import pytest

from gentrace_forensics import cli
from gentrace_forensics.schemas.acquisition import AcquiredCache
from gentrace_forensics.schemas.classification import ClassifiedEntry
from gentrace_forensics.schemas.normalization import NormalizedArtifact


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_native_e01_pipeline(tmp_path: Path) -> None:
    fixture = os.environ.get("GENTRACE_E01_FIXTURE")
    if not fixture:
        pytest.skip("GENTRACE_E01_FIXTURE에 로컬 E01 경로를 지정해야 함")
    pytest.importorskip("pyewf")
    pytest.importorskip("pytsk3")
    image_path = Path(fixture).expanduser().resolve()
    assert image_path.is_file(), "지정한 E01 파일이 존재하지 않음"
    out = Path(os.environ.get("GENTRACE_E01_OUTPUT", str(tmp_path / "run"))).expanduser().resolve()
    assert cli.main(["run", "--image", str(image_path), "--out", str(out)]) == 0

    report = json.loads((out / "run.json").read_text(encoding="utf-8"))
    assert report["status"] == "complete"
    assert report["profile_count"] > 0
    assert report["classified_count"] == report["normalized_count"] > 0
    acquisition = json.loads((out / "acquired" / "acquisition.json").read_text(encoding="utf-8"))
    file_hashes: dict[tuple[str, int, str], dict[str, str]] = {}
    for path in report["manifests"]:
        cache = AcquiredCache.model_validate_json(Path(path).read_bytes())
        assert cache.image_path == str(image_path)
        assert cache.image_sha256 == acquisition["image_sha256"]
        hashes = {}
        for file in cache.files:
            assert file.local_path.stat().st_size == file.size
            assert _sha256(file.local_path) == file.sha256
            hashes[file.relative_path] = file.sha256
        file_hashes[(cache.image_path, cache.partition_offset, cache.source_path)] = hashes

    classified_path = Path(report["classified_entries"])
    checked = 0
    with (
        classified_path.open("rb") as entries,
        Path(report["normalized_jsonl"]).open("rb") as normalized,
        closing(sqlite3.connect(report["normalized_sqlite"])) as connection,
    ):
        connection.row_factory = sqlite3.Row
        for entry_line, record_line in zip_longest(entries, normalized):
            assert entry_line is not None and record_line is not None
            entry = ClassifiedEntry.model_validate_json(entry_line)
            record = NormalizedArtifact.model_validate_json(record_line)
            if entry.body_path is not None:
                assert entry.body_path.stat().st_size == entry.size
                assert _sha256(entry.body_path) == entry.body_sha256
            assert record.sha256 == entry.body_sha256
            provenance = json.loads(record.source_id)
            key = (
                entry.source_cache.image_path,
                entry.source_cache.partition_offset,
                entry.source_cache.source_path,
            )
            assert provenance["source_file_sha256"] == file_hashes[key][entry.source_file]
            assert provenance["entry_id"] == entry.entry_id
            assert provenance["source_offset"] == entry.source_offset
            row = connection.execute(
                "SELECT * FROM artifacts WHERE source_id = ?", (record.source_id,)
            ).fetchone()
            assert row is not None and NormalizedArtifact.model_validate(dict(row)) == record
            checked += 1
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == checked
    assert checked == report["classified_count"]
    summary = json.loads((out / "normalized" / "normalization.json").read_text(encoding="utf-8"))
    assert summary["classified_sha256"] == _sha256(classified_path)

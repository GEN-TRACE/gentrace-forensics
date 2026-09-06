"""classify.py 라우터 테스트.

유닛(합성 엔트리)은 CI 에서 돌고, `classify_cache_dir` 통합 테스트는
로컬 캐시 픽스처가 있을 때만 돈다.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from gentrace_forensics.classification.blockfile.parser import HttpResponseInfo, ParsedCacheEntry
from gentrace_forensics.classification.classify import (
    _local_acquired_cache,
    classify_cache_dir,
    classify_entries,
)
from gentrace_forensics.schemas.acquisition import AcquiredCache
from gentrace_forensics.schemas.classification import ClassifiedEntry


def make_entry(
    url: str,
    *,
    body: bytes = b"data",
    content_type: str | None = "application/octet-stream",
    status: int | None = 200,
    source_file: str = "f_000001",
    entry_hash: int = 0xABCDEF01,
    cache_key: str | None = None,
) -> ParsedCacheEntry:
    headers = {"content-type": content_type} if content_type else {}
    return ParsedCacheEntry(
        cache_key=cache_key or url,
        url=url,
        response=HttpResponseInfo(status=status, headers=headers),
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        stored_body_size=len(body),
        content_encoding=None,
        source_file=source_file,
        source_offset=0,
        entry_hash=entry_hash,
        entry_state="normal",
        cache_timestamps={"creation_time_us": 13_400_000_000_000_000},
    )


@pytest.fixture
def source_cache() -> AcquiredCache:
    return _local_acquired_cache(Path("/tmp/Chrome/Default/Cache/Cache_Data"))


def test_unknown_when_no_classifier_matches(source_cache: AcquiredCache) -> None:
    entries = [make_entry("https://example.com/a"), make_entry("https://foo.bar/b")]
    out = classify_entries(entries, source_cache=source_cache)
    assert len(out) == 2
    assert all(isinstance(c, ClassifiedEntry) for c in out)
    assert {c.service for c in out} == {"unknown"}
    assert {c.artifact_kind for c in out} == {"other"}


def test_provenance_and_evidence_carried(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://x.com/img.png", body=b"PNGDATA", entry_hash=0x1234, source_file="f_00002a"
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert c.cache_key == "https://x.com/img.png"
    assert c.source_file == "f_00002a"
    assert c.body_sha256 == hashlib.sha256(b"PNGDATA").hexdigest()
    assert c.size == len(b"PNGDATA")
    assert c.evidence["entry_hash"] == "00001234"
    assert c.evidence["http_status"] == 200
    assert c.cache_timestamps["creation_time_us"] == 13_400_000_000_000_000
    assert c.filename == "img.png"


def test_entry_id_stable_and_unique(source_cache: AcquiredCache) -> None:
    entries = [make_entry(f"https://x.com/{i}") for i in range(5)]
    out = classify_entries(entries, source_cache=source_cache)
    ids = [c.entry_id for c in out]
    assert len(set(ids)) == 5
    again = classify_entries([entries[0]], source_cache=source_cache)
    assert again[0].entry_id == ids[0]


def test_body_written_to_disk(source_cache: AcquiredCache, tmp_path: Path) -> None:
    entry = make_entry("https://x.com/report.bin", body=b"\x00\x01\x02payload")
    (c,) = classify_entries([entry], source_cache=source_cache, body_dir=tmp_path)
    assert c.body_path is not None
    assert c.body_path.read_bytes() == b"\x00\x01\x02payload"
    assert c.body_path.parent == tmp_path


def test_empty_body_not_written(source_cache: AcquiredCache, tmp_path: Path) -> None:
    (c,) = classify_entries(
        [make_entry("https://x.com/e", body=b"")], source_cache=source_cache, body_dir=tmp_path
    )
    assert c.body_path is None


# --- 통합 (로컬 캐시 픽스처) ---


def test_classify_local_cache_dir(cache_fixture_dir: Path) -> None:
    out = classify_cache_dir(cache_fixture_dir)
    assert len(out) > 100
    for c in out:
        assert isinstance(c, ClassifiedEntry)
        assert c.entry_id
        assert c.source_cache.source_path
    # PR 4~6 전이므로 아직 전부 unknown
    assert {c.service for c in out} <= {"unknown"}

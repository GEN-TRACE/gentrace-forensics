"""스키마 스모크 테스트 — 계약 모델이 임포트·인스턴스화 되는지만 확인."""

from __future__ import annotations

from gentrace_forensics.schemas import (
    AcquiredCache,
    AcquiredFile,
    ClassifiedEntry,
    NormalizedArtifact,
)


def test_acquired_cache_minimal() -> None:
    cache = AcquiredCache(
        image_path="disk.E01",
        partition_offset=0,
        windows_user="user",
        chrome_profile="Default",
        source_path="/Users/user/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data",
    )
    assert cache.files == []


def test_classified_entry_minimal() -> None:
    cache = AcquiredCache(
        image_path="disk.E01",
        partition_offset=0,
        windows_user="user",
        chrome_profile="Default",
        source_path="x",
    )
    entry = ClassifiedEntry(
        entry_id="abc",
        cache_key="1/0/https://chatgpt.com/",
        url="https://chatgpt.com/",
        filename="index.html",
        size=0,
        source_file="data_1",
        source_cache=cache,
    )
    assert entry.service == "unknown"
    assert entry.artifact_kind == "other"


def test_normalized_artifact_minimal() -> None:
    art = NormalizedArtifact(
        service="chatgpt",
        event_type="upload",
        content_type="image",
        artifact_source="cache",
        artifact_kind="file_upload",
        url="https://chatgpt.com/",
        domain="chatgpt.com",
        source_id="abc",
    )
    assert art.timestamp is None


def test_acquired_file_roundtrip() -> None:
    f = AcquiredFile(relative_path="index", local_path="/tmp/index", size=1, sha256="0" * 64)
    assert f.model_dump()["relative_path"] == "index"

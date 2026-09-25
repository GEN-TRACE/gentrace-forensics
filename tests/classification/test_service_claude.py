"""Claude 분류기 테스트.

실데이터가 전혀 없어 CONTRIBUTING.md 3.2.2 스펙 기반 합성 엔트리로만 검증한다.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

import pytest

from gentrace_forensics.classification.classify import (
    _local_acquired_cache,
    classify_entries,
)
from gentrace_forensics.classification.services.claude import ClaudeClassifier
from gentrace_forensics.schemas.acquisition import AcquiredCache

from .test_classify import make_entry


@pytest.fixture
def source_cache() -> AcquiredCache:
    return _local_acquired_cache(Path("/tmp/no-claude-fixture"))


def test_file_preview_is_candidate(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://claude.ai/api/conv-123/files/file-456",
        body=b"webp-bytes",
        content_type="image/webp",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("claude", "other")
    assert c.evidence["scope_id"] == "conv-123"
    assert c.evidence["file_id"] == "file-456"


def test_generated_output_path_is_candidate(source_cache: AcquiredCache) -> None:
    encoded_path = quote("/mnt/user-data/outputs/report.pdf", safe="")
    entry = make_entry(
        f"https://claude.ai/api/conv-123/download?path={encoded_path}",
        body=b"pdf-bytes",
        content_type="application/octet-stream",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("claude", "other")
    assert c.filename == "report.pdf"
    assert "/mnt/user-data/outputs/report.pdf" in c.evidence["decoded_url"]


def test_generated_output_requires_octet_stream_content_type(source_cache: AcquiredCache) -> None:
    encoded_path = quote("/mnt/user-data/outputs/report.pdf", safe="")
    entry = make_entry(
        f"https://claude.ai/api/conv-123/download?path={encoded_path}",
        content_type="application/json",  # 스펙과 다른 content-type이면 매치 안 함
    )
    clf = ClaudeClassifier()
    assert not clf.matches(entry)


def test_matches_scope() -> None:
    clf = ClaudeClassifier()
    assert clf.matches(
        make_entry("https://claude.ai/api/conv-1/files/file-1", content_type="image/webp")
    )
    encoded_path = quote("/mnt/user-data/outputs/x.png", safe="")
    assert clf.matches(
        make_entry(
            f"https://claude.ai/api/conv-1/x?path={encoded_path}",
            content_type="application/octet-stream",
        )
    )
    assert not clf.matches(make_entry("https://claude.ai/new"))
    assert not clf.matches(make_entry("https://assets-proxy.anthropic.com/claude-ai/v2/a.js"))

"""ChatGPT 분류기 테스트.

대화 목록(`backend-api/conversations`)은 로컬 캐시 픽스처로 검증한다.
`estuary/content` 업로드·개별 대화 상세(생성본) 는 이 시나리오 캐시에 실데이터가
없어 CONTRIBUTING.md 스펙 기반 합성 엔트리로만 검증한다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gentrace_forensics.classification.classify import (
    _local_acquired_cache,
    classify_cache_dir,
    classify_entries,
)
from gentrace_forensics.classification.services.chatgpt import ChatGPTClassifier
from gentrace_forensics.schemas.acquisition import AcquiredCache

from .test_classify import make_entry

_CONVERSATIONS_LIST_BODY = json.dumps(
    {
        "items": [
            {
                "id": "conv-1",
                "title": "Generate WiFi Poster PNG",
                "create_time": "2026-08-25T13:57:58Z",
                "update_time": "2026-08-25T13:58:59Z",
            },
            {"id": "conv-2", "title": "Revise WiFi Poster"},
        ],
        "total": 2,
    }
).encode()

_CONVERSATION_DETAIL_WITH_FILE_BODY = json.dumps(
    {
        "conversation_id": "conv-1",
        "mapping": {
            "node-1": {
                "message": {
                    "content": {
                        "parts": [
                            {
                                "asset_pointer": "file-service://abc",
                                "download_url": "https://files.oaiusercontent.com/abc?sig=1",
                                "file_name": "wifi_poster.png",
                                "file_size_bytes": 204800,
                            }
                        ]
                    }
                }
            }
        },
    }
).encode()

_CONVERSATION_DETAIL_NO_FILE_BODY = json.dumps(
    {
        "conversation_id": "conv-2",
        "mapping": {"node-1": {"message": {"content": {"parts": ["hi"]}}}},
    }
).encode()

_ESTUARY_DENIED_BODY = json.dumps(
    {"file_name": "screenshot.png", "file_size_bytes": 51200}
).encode()


@pytest.fixture
def source_cache() -> AcquiredCache:
    return _local_acquired_cache(Path("/tmp/01_Cache_Data"))


def test_conversations_list_is_conversation(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://chatgpt.com/backend-api/conversations?offset=0&limit=28",
        body=_CONVERSATIONS_LIST_BODY,
        content_type="application/json",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("chatgpt", "conversation")
    assert c.evidence["role"] == "conversation_list"
    assert c.evidence["conversation_count"] == 2
    assert c.evidence["conversations"][0]["title"] == "Generate WiFi Poster PNG"


def test_conversation_detail_with_download_url_is_metadata(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://chatgpt.com/backend-api/conversation/conv-1",
        body=_CONVERSATION_DETAIL_WITH_FILE_BODY,
        content_type="application/json",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("chatgpt", "conversation")
    assert c.evidence["conversation_id"] == "conv-1"
    assert c.evidence["download_urls"] == ["https://files.oaiusercontent.com/abc?sig=1"]
    assert c.evidence["file_names"] == ["wifi_poster.png"]
    assert c.evidence["file_size_bytes"] == [204800]


def test_conversation_detail_without_download_url_is_conversation(
    source_cache: AcquiredCache,
) -> None:
    entry = make_entry(
        "https://chatgpt.com/backend-api/conversation/conv-2",
        body=_CONVERSATION_DETAIL_NO_FILE_BODY,
        content_type="application/json",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("chatgpt", "conversation")
    assert c.evidence["role"] == "conversation_detail"


def test_estuary_content_is_candidate_when_access_denied(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://chatgpt.com/backend-api/estuary/content?id=file-abc123",
        body=b"File stream access denied",  # 실제 관측된 응답 본문 형태
        content_type="text/plain",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("chatgpt", "other")
    assert c.evidence["file_id"] == "file-abc123"
    assert c.evidence["access_denied"] is True


def test_estuary_content_extracts_plaintext_metadata(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://chatgpt.com/backend-api/estuary/content?id=file-xyz",
        body=_ESTUARY_DENIED_BODY,
        content_type="application/json",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert c.evidence["file_name"] == "screenshot.png"
    assert c.evidence["file_size_bytes"] == 51200


def test_matches_scope() -> None:
    clf = ChatGPTClassifier()
    assert clf.matches(make_entry("https://chatgpt.com/backend-api/estuary/content?id=x"))
    assert clf.matches(make_entry("https://chatgpt.com/backend-api/conversation/abc"))
    assert clf.matches(make_entry("https://chatgpt.com/backend-api/conversations?offset=0"))
    assert not clf.matches(make_entry("https://chatgpt.com/backend-api/me"))
    assert not clf.matches(make_entry("https://chatgpt.com/cdn/assets/app.js"))


# --- 통합 (로컬 캐시 픽스처) ---


def test_chatgpt_conversation_list_on_local_fixture(chatgpt_cache_fixture_dir: Path) -> None:
    out = classify_cache_dir(chatgpt_cache_fixture_dir)
    cg = [c for c in out if c.service == "chatgpt"]
    assert cg, "01_Cache_Data 픽스처에 chatgpt.com 엔트리가 있어야 함"
    lists = [c for c in cg if c.evidence.get("role") == "conversation_list"]
    assert lists
    assert lists[0].evidence["conversation_count"] > 0

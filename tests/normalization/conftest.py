"""정규화 계약 검증용 합성 분류 결과."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from gentrace_forensics.schemas.acquisition import AcquiredCache, AcquiredFile
from gentrace_forensics.schemas.classification import ClassifiedEntry


@pytest.fixture
def classified_entry(tmp_path: Path) -> ClassifiedEntry:
    return ClassifiedEntry(
        entry_id="entry-1",
        cache_key="1/0/https://chatgpt.com/backend-api/conversation/chat-1",
        url="https://chatgpt.com/backend-api/conversation/chat-1",
        filename="결과.json",
        content_type="application/json; charset=utf-8",
        size=2,
        body_sha256=hashlib.sha256(b"{}").hexdigest(),
        source_file="f_000001",
        source_offset=0,
        service="chatgpt",
        artifact_kind="generated_file",
        cache_timestamps={"response_time_us": 13_344_473_600_123_456},
        evidence={"conversation_id": "chat-1", "user_id": "user-1"},
        source_cache=AcquiredCache(
            image_path="disk.E01",
            image_sha256="a" * 64,
            partition_offset=1_048_576,
            windows_user="alice",
            chrome_profile="Default",
            source_path="/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data",
            files=[
                AcquiredFile(
                    relative_path="f_000001",
                    local_path=tmp_path / "f_000001",
                    size=2,
                    sha256="b" * 64,
                )
            ],
        ),
    )

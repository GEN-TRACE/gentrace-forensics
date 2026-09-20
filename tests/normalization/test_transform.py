"""분류 JSONL → 공통 스키마 변환과 출처 연결 계약."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from gentrace_forensics.normalization.transform import build_source_id, transform, transform_many
from gentrace_forensics.schemas.classification import ClassifiedEntry


def test_classified_json_roundtrip_preserves_normalized_fields(classified_entry: ClassifiedEntry):
    entry = ClassifiedEntry.model_validate_json(classified_entry.model_dump_json())
    record = transform(entry)

    assert record.timestamp == datetime(2023, 11, 14, 22, 13, 20, 123456, tzinfo=UTC)
    assert record.service == "chatgpt"
    assert record.session_id == "chat-1"
    assert record.user_id == "user-1"
    assert record.event_type == "generate"
    assert record.actor == "service"
    assert record.content_type == "json"
    assert record.filename == "결과.json"
    assert record.sha256 == entry.body_sha256
    assert record.content == record.url == entry.url
    provenance = json.loads(record.source_id)
    assert provenance["source_file_sha256"] == "b" * 64
    assert provenance["image_sha256"] == "a" * 64
    assert provenance["partition_offset"] == 1_048_576
    assert provenance["source_file"] == entry.source_file
    assert provenance["source_offset"] == entry.source_offset
    assert provenance["entry_id"] == entry.entry_id


@pytest.mark.parametrize(
    ("timestamps", "expected_second"),
    [
        ({"creation_time_us": 13_344_473_600_000_000}, 20),
        (
            {"creation_time_us": 13_344_473_600_000_000, "request_time_us": 13_344_473_601_000_000},
            21,
        ),
        (
            {
                "creation_time_us": 13_344_473_600_000_000,
                "request_time_us": 13_344_473_601_000_000,
                "response_time_us": 13_344_473_602_000_000,
            },
            22,
        ),
    ],
)
def test_timestamp_priority(
    classified_entry: ClassifiedEntry, timestamps: dict[str, int], expected_second: int
):
    entry = classified_entry.model_copy(update={"cache_timestamps": timestamps})
    assert transform(entry).timestamp == datetime(2023, 11, 14, 22, 13, expected_second, tzinfo=UTC)


def test_service_timestamp_is_used_only_without_cache_time(classified_entry: ClassifiedEntry):
    entry = classified_entry.model_copy(update={"evidence": {"created_timestamp_ms": 1000}})
    assert transform(entry).timestamp == transform(classified_entry).timestamp
    entry.cache_timestamps = {}
    assert transform(entry).timestamp == datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC)


def test_unknown_values_remain_unset(classified_entry: ClassifiedEntry):
    entry = classified_entry.model_copy(
        update={
            "cache_timestamps": {},
            "evidence": {},
            "artifact_kind": "other",
            "service": "unknown",
        }
    )
    record = transform(entry)
    assert record.timestamp is None
    assert record.user_id is None
    assert record.session_id is None
    assert record.actor is None
    assert record.service == "unknown"


def test_profiles_with_same_entry_id_have_distinct_sources(classified_entry: ClassifiedEntry):
    other = classified_entry.model_copy(
        update={
            "source_cache": classified_entry.source_cache.model_copy(
                update={"chrome_profile": "Profile 1"}
            )
        }
    )
    records = transform_many([classified_entry, other])
    assert len({record.source_id for record in records}) == 2
    assert build_source_id(classified_entry) == records[0].source_id


def test_missing_acquired_file_hash_is_not_invented(classified_entry: ClassifiedEntry):
    classified_entry.source_cache.files = []
    assert json.loads(transform(classified_entry).source_id)["source_file_sha256"] is None


def test_claude_url_supplies_session_only_when_evidence_has_none(classified_entry: ClassifiedEntry):
    entry = classified_entry.model_copy(
        update={
            "service": "claude",
            "url": "https://claude.ai/api/chat-2/files/file-2",
            "evidence": {},
        }
    )
    assert transform(entry).session_id == "chat-2"
    entry.evidence = {"conversation_id": "explicit-chat"}
    assert transform(entry).session_id == "explicit-chat"

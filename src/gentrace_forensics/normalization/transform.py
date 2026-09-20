"""ClassifiedEntry → NormalizedArtifact.

- timestamp: cache_timestamps 중 가장 신뢰도 높은 값 → UTC
- service: mapping.normalize_service
- event_type: mapping.event_type_for(artifact_kind)
- source_id: entry_id + 이미지/프로필/오프셋을 되짚을 수 있는 문자열
- 모르는 값은 None. 추측 금지.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from gentrace_forensics.normalization.mapping import (
    content_type_group,
    event_type_for,
    normalize_service,
)
from gentrace_forensics.normalization.time import from_unix, from_webkit
from gentrace_forensics.normalization.url import domain_of
from gentrace_forensics.schemas.classification import ClassifiedEntry
from gentrace_forensics.schemas.normalization import NormalizedArtifact

_CLAUDE_CONVERSATION = re.compile(r"^/api/([^/]+)/files(?:/|$)")


def _scalar_text(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _first_evidence_value(evidence: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _scalar_text(evidence.get(key))
        if value is not None:
            return value
    return None


def _source_file_sha256(entry: ClassifiedEntry) -> str | None:
    """AcquiredCache.files에서 현재 source_file의 SHA-256을 찾는다."""
    exact = [item for item in entry.source_cache.files if item.relative_path == entry.source_file]
    if len(exact) == 1:
        return exact[0].sha256

    source_name = PurePath(entry.source_file).name
    by_name = [
        item
        for item in entry.source_cache.files
        if PurePath(item.relative_path).name == source_name
    ]
    return by_name[0].sha256 if len(by_name) == 1 else None


def build_source_id(entry: ClassifiedEntry) -> str:
    """원본 E01 → Cache_Data 파일 → 엔트리 오프셋까지 역추적 가능한 식별자.

    사람이/도구가 다시 분해할 수 있도록 해시 하나로 뭉개지 않고 canonical JSON으로 만든다.
    """
    cache = entry.source_cache
    provenance = {
        "cache_source_path": cache.source_path,
        "chrome_profile": cache.chrome_profile,
        "entry_id": entry.entry_id,
        "image_path": cache.image_path,
        "image_sha256": cache.image_sha256,
        "partition_offset": cache.partition_offset,
        "source_file": entry.source_file,
        "source_file_sha256": _source_file_sha256(entry),
        "source_offset": entry.source_offset,
        "windows_user": cache.windows_user,
    }
    return json.dumps(provenance, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _timestamp(entry: ClassifiedEntry) -> datetime | None:
    # 현재 분류 계약(parser.py)이 보장하는 Chrome/WebKit epoch microseconds.
    for key in ("response_time_us", "request_time_us", "creation_time_us"):
        raw = entry.cache_timestamps.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            dt = from_webkit(int(raw))
            if dt is not None:
                return dt

    # 향후 분류기가 aware datetime을 직접 넘기는 경우를 보수적으로 지원.
    for key in ("response_time", "request_time", "creation_time"):
        raw = entry.cache_timestamps.get(key)
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                continue
            return raw.astimezone(UTC)

    # 캐시 시간이 없을 때만 분류 근거에 명시된 서비스 원시 시간을 사용한다.
    evidence = entry.evidence
    for key in ("created_timestamp_ms", "timestamp_ms"):
        raw = evidence.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            dt = from_unix(float(raw), unit="ms")
            if dt is not None:
                return dt

    for key in ("date_unix", "timestamp_unix"):
        raw = evidence.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            dt = from_unix(float(raw), unit="s")
            if dt is not None:
                return dt

    return None


def _ids(entry: ClassifiedEntry, service: str) -> tuple[str | None, str | None]:
    evidence = entry.evidence
    user_id = _first_evidence_value(
        evidence,
        ("user_id", "userId", "account_id", "accountId", "owner_id", "ownerId"),
    )
    session_id = _first_evidence_value(
        evidence,
        ("session_id", "sessionId", "conversation_id", "conversationId", "chat_id", "chatId"),
    )

    # Claude upload URL은 계약상 /api/[conversation_id]/files/[file_id] 구조다.
    if session_id is None and service == "claude":
        from gentrace_forensics.normalization.url import decode_path

        match = _CLAUDE_CONVERSATION.match(decode_path(entry.url))
        if match:
            session_id = match.group(1)

    return user_id, session_id


def _actor(entry: ClassifiedEntry) -> str | None:
    explicit = _first_evidence_value(entry.evidence, ("actor",))
    if explicit is not None:
        return explicit
    if entry.artifact_kind == "file_upload":
        return "user"
    if entry.artifact_kind == "generated_file":
        return "service"
    return None


def transform(entry: ClassifiedEntry) -> NormalizedArtifact:
    """분류 결과 한 건을 Common Schema로 변환하고 Pydantic 검증을 수행한다."""
    service = normalize_service(entry.service) or "unknown"
    content_type = content_type_group(entry.content_type) or "unknown"
    user_id, session_id = _ids(entry, service)

    return NormalizedArtifact(
        timestamp=_timestamp(entry),
        service=service,
        user_id=user_id,
        session_id=session_id,
        event_type=event_type_for(entry.artifact_kind),
        actor=_actor(entry),
        # body_path를 임의로 다시 읽지 않는다. ClassifiedEntry가 보장하는 원문 URL을 보존한다.
        content=entry.url or None,
        content_type=content_type,
        artifact_source="cache",
        artifact_kind=entry.artifact_kind,
        filename=entry.filename or None,
        url=entry.url,
        domain=domain_of(entry.url),
        source_id=build_source_id(entry),
        sha256=entry.body_sha256,
    )


def transform_many(entries: list[ClassifiedEntry]) -> list[NormalizedArtifact]:
    return [transform(entry) for entry in entries]

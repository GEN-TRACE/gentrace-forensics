"""서비스 라우팅 + artifact_kind 결정.

흐름:
  Cache_Data 디렉터리 → `blockfile.parser.parse_cache_dir` 로 ParsedCacheEntry 목록
  → 각 엔트리를 `ServiceClassifier` 로 라우팅 (첫 매치)
  → (선택) 압축 해제된 본문을 디스크에 저장 + SHA-256
  → schemas.ClassifiedEntry 산출

`source_cache` 는 예은 획득 단계의 AcquiredCache. 아직 없을 때(분류만 개발)는
`_local_acquired_cache()` 로 최소 정보만 채운 placeholder 를 만든다.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Sequence
from pathlib import Path

from gentrace_forensics.classification.blockfile.parser import (
    ParsedCacheEntry,
    parse_cache_dir,
)
from gentrace_forensics.classification.services import ALL_CLASSIFIERS
from gentrace_forensics.classification.services.base import Classification, ServiceClassifier
from gentrace_forensics.schemas.acquisition import AcquiredCache
from gentrace_forensics.schemas.classification import ClassifiedEntry


def _entry_id(entry: ParsedCacheEntry) -> str:
    digest = hashlib.sha256(entry.cache_key.encode("utf-8", "replace")).hexdigest()
    return digest[:16]


def _local_acquired_cache(cache_dir: Path) -> AcquiredCache:
    """예은 AcquiredCache 가 없을 때 쓰는 placeholder (Phase 1 / 분류만 개발용)."""
    resolved = cache_dir.resolve()
    return AcquiredCache(
        image_path="(local)",
        partition_offset=0,
        windows_user="(unknown)",
        chrome_profile=resolved.parent.name or "(unknown)",
        source_path=str(resolved),
    )


def _write_body(entry: ParsedCacheEntry, body_dir: Path, entry_id: str) -> Path | None:
    if not entry.body:
        return None
    body_dir.mkdir(parents=True, exist_ok=True)
    dest = body_dir / f"{entry_id}_{entry.filename}"
    dest.write_bytes(entry.body)
    return dest


def _route(
    classifiers: Sequence[ServiceClassifier],
    entry: ParsedCacheEntry,
    entries: Sequence[ParsedCacheEntry],
) -> tuple[str, Classification]:
    for clf in classifiers:
        if clf.matches(entry):
            result = clf.classify(entry, entries=entries)
            return (result.service or clf.service), result
    return "unknown", Classification("other")


def classify_entries(
    entries: Sequence[ParsedCacheEntry],
    *,
    source_cache: AcquiredCache,
    body_dir: Path | None = None,
) -> list[ClassifiedEntry]:
    """이미 파싱된 엔트리 목록을 분류한다."""
    classifiers: list[ServiceClassifier] = [cls() for cls in ALL_CLASSIFIERS]
    out: list[ClassifiedEntry] = []
    for entry in entries:
        entry_id = _entry_id(entry)
        service, result = _route(classifiers, entry, entries)
        evidence = dict(result.evidence)
        evidence.setdefault("entry_hash", f"{entry.entry_hash & 0xFFFFFFFF:08x}")
        evidence.setdefault("http_status", entry.response.status)
        evidence.setdefault("entry_state", entry.entry_state)
        if entry.warnings:
            evidence.setdefault("parse_warnings", list(entry.warnings))

        body_path = _write_body(entry, body_dir, entry_id) if body_dir else None

        out.append(
            ClassifiedEntry(
                entry_id=entry_id,
                cache_key=entry.cache_key,
                url=entry.url,
                content_type=entry.content_type,
                content_encoding=entry.content_encoding,
                content_disposition=entry.response.get("content-disposition"),
                filename=result.filename or entry.filename,
                size=len(entry.body),
                body_path=body_path,
                body_sha256=entry.body_sha256,
                service=service,  # type: ignore[arg-type]
                artifact_kind=result.artifact_kind,
                evidence=evidence,
                source_file=entry.source_file,
                source_offset=entry.source_offset,
                cache_timestamps=dict(entry.cache_timestamps),
                source_cache=source_cache,
            )
        )
    return out


def classify_cache_dir(
    cache_dir: str | Path,
    *,
    source_cache: AcquiredCache | None = None,
    body_dir: str | Path | None = None,
) -> list[ClassifiedEntry]:
    """Cache_Data 디렉터리 하나를 파싱 + 분류한다."""
    cache_dir = Path(cache_dir)
    entries = parse_cache_dir(cache_dir)
    if source_cache is None:
        source_cache = _local_acquired_cache(cache_dir)
    return classify_entries(
        entries,
        source_cache=source_cache,
        body_dir=Path(body_dir) if body_dir is not None else None,
    )


def classify_cache(
    cache: AcquiredCache,
    cache_dir: str | Path,
    *,
    body_dir: str | Path | None = None,
) -> list[ClassifiedEntry]:
    """예은 AcquiredCache + 추출된 Cache_Data 경로로 분류한다."""
    return classify_cache_dir(cache_dir, source_cache=cache, body_dir=body_dir)


def iter_classified(
    cache: AcquiredCache, cache_dir: str | Path, *, body_dir: str | Path | None = None
) -> Iterator[ClassifiedEntry]:
    yield from classify_cache(cache, cache_dir, body_dir=body_dir)

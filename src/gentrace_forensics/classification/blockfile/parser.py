"""chrome_blockfile_parser 통합 — 분류 단계의 입력 경계.

`parse_cache_dir(path) -> list[ParsedCacheEntry]` 가 이 프로젝트에서 캐시를 읽는
유일한 공개 API 다. 엔진은 `_self_backend`(자체 구현 `structs`/`addr`/`index`/
`entry`, Phase 2) — `_ccl_backend`(ccl_chromium_reader)는 삭제하지 않고 교차검증
(tests/classification/test_blockfile_entry.py)용으로 남겨둔다.

검증: 두 백엔드가 같은 픽스처에서 URL·상태코드·헤더·본문 SHA-256 전수 일치함을
확인했다 (Phase 2 전환 시점의 회귀 테스트로도 계속 쓴다). 외부 툴(ChromeCacheView
/ Hindsight) 대조는 아직 진행 전.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from gentrace_forensics.classification import http
from gentrace_forensics.classification.blockfile import _self_backend
from gentrace_forensics.classification.blockfile.entry import HttpResponseInfo

__all__ = ["BlockfileCache", "HttpResponseInfo", "ParsedCacheEntry", "parse_cache_dir"]


@dataclass
class ParsedCacheEntry:
    """서비스 분류 이전의 원시 캐시 엔트리 (압축은 해제된 상태)."""

    cache_key: str
    url: str
    response: HttpResponseInfo
    body: bytes  # stream 1, 압축 해제 완료
    body_sha256: str  # 압축 해제된 body 의 SHA-256
    stored_body_size: int  # 디스크에 저장된 크기 (압축 해제 전)
    content_encoding: str | None
    source_file: str  # 'f_00024a.gz' 또는 'data_1'
    source_offset: int
    entry_hash: int
    entry_state: str  # 'normal' | 'evicted' | 'doomed'
    cache_timestamps: dict[str, int | None] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    response_location: dict[str, int | str] = field(default_factory=dict)
    entry_flags: int = 0
    sparse_data: bytes = b""
    entry_location: dict[str, int | str] = field(default_factory=dict)
    sparse_location: dict[str, int | str] = field(default_factory=dict)

    @property
    def content_type(self) -> str | None:
        return self.response.content_type

    @property
    def filename(self) -> str:
        return http.decide_filename(
            url=self.url,
            content_type=self.content_type,
            content_disposition=self.response.get("content-disposition"),
            entry_hash=self.entry_hash,
        )


def _to_parsed(raw: _self_backend.RawCacheEntry) -> ParsedCacheEntry:
    body, decode_warnings = http.decompress_with_warnings(raw.stored_body, raw.content_encoding)
    return ParsedCacheEntry(
        response_location=raw.response_location,
        entry_flags=raw.entry_flags,
        sparse_data=raw.sparse_data,
        entry_location=raw.entry_location,
        sparse_location=raw.sparse_location,
        cache_key=raw.cache_key,
        url=raw.url,
        response=HttpResponseInfo(
            status=raw.http_status,
            headers=dict(raw.headers),
            request_time_us=raw.request_time_us,
            response_time_us=raw.response_time_us,
        ),
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        stored_body_size=raw.stored_body_size,
        content_encoding=raw.content_encoding,
        source_file=raw.source_file,
        source_offset=raw.source_offset,
        entry_hash=raw.entry_hash,
        entry_state=raw.entry_state,
        cache_timestamps={
            "creation_time_us": raw.creation_time_us,
            "request_time_us": raw.request_time_us,
            "response_time_us": raw.response_time_us,
        },
        warnings=[*raw.warnings, *decode_warnings],
    )


class BlockfileCache:
    """캐시 디렉터리 하나."""

    def __init__(self, cache_dir: str | Path) -> None:
        self.cache_dir = Path(cache_dir)

    def iter_entries(self) -> Iterator[ParsedCacheEntry]:
        for raw in _self_backend.iter_raw_entries(self.cache_dir):
            yield _to_parsed(raw)

    def entries(self) -> list[ParsedCacheEntry]:
        return list(self.iter_entries())


def parse_cache_dir(cache_dir: str | Path) -> list[ParsedCacheEntry]:
    return BlockfileCache(cache_dir).entries()

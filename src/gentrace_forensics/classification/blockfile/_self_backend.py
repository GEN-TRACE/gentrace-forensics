"""자체 구현(`structs`/`addr`/`index`/`entry`) 기반 blockfile 캐시 백엔드 (Phase 2).

`_ccl_backend.py`(ccl_chromium_reader, 참조·검증용)와 동일한 `RawCacheEntry`
계약을 만든다. `parser.py` 가 실제로 쓰는 엔진은 이 모듈이다 — `_ccl_backend`
는 삭제하지 않고 `tests/classification/test_blockfile_entry.py`의 교차검증
(URL·상태코드·헤더·본문 SHA-256 전수 대조)에 계속 남겨둔다.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from gentrace_forensics.classification.blockfile import entry as _entry
from gentrace_forensics.classification.blockfile._ccl_backend import (
    RawCacheEntry,
    looks_like_blockfile_cache,
)
from gentrace_forensics.classification.blockfile.addr import FileType
from gentrace_forensics.classification.blockfile.structs import (
    BLOCK_HEADER_SIZE,
    ENTRY_DOOMED,
    ENTRY_EVICTED,
    ENTRY_NORMAL,
)

__all__ = ["RawCacheEntry", "iter_raw_entries", "looks_like_blockfile_cache"]

_STATE_NAMES = {ENTRY_NORMAL: "normal", ENTRY_EVICTED: "evicted", ENTRY_DOOMED: "doomed"}


def _source_location(entry: _entry.CacheEntry) -> tuple[str, int]:
    """Stream 1(본문)이 실제로 저장된 파일명과 오프셋."""
    addr = entry.stream_addrs[1]
    if not addr.is_initialized:
        return "?", 0
    if addr.file_type == FileType.EXTERNAL:
        return f"f_{addr.external_file_number:06x}", 0
    return f"data_{addr.block_file_number}", addr.file_offset(BLOCK_HEADER_SIZE)


def iter_raw_entries(cache_dir: str | Path) -> Iterator[RawCacheEntry]:
    """blockfile 캐시 디렉터리 하나를 RawCacheEntry 로 순회한다 (자체 파서 엔진)."""
    src = Path(cache_dir)
    if not looks_like_blockfile_cache(src):
        raise ValueError(f"blockfile 캐시가 아님 (index/data_0..3 없음): {src}")

    for cache_entry in _entry.iter_entries(src):
        info = cache_entry.response_info(src)
        warnings: list[str] = []
        try:
            body = cache_entry.body_bytes(src)
        except (OSError, ValueError) as exc:
            body = b""
            warnings.append(f"body read failed: {exc}")

        source_file, source_offset = _source_location(cache_entry)
        creation_time_us = cache_entry.store.creation_time or None

        yield RawCacheEntry(
            cache_key=cache_entry.key.raw,
            url=cache_entry.key.url,
            http_status=info.status,
            headers=dict(info.headers),
            stored_body=body,
            stored_body_size=len(body),
            content_encoding=info.get("content-encoding"),
            source_file=source_file,
            source_offset=source_offset,
            entry_hash=cache_entry.store.hash,
            entry_state=_STATE_NAMES.get(cache_entry.store.state, "normal"),
            creation_time_us=creation_time_us,
            warnings=warnings,
        )

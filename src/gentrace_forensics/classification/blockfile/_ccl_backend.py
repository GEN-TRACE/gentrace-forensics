"""ccl_chromium_reader 를 감싼 blockfile 캐시 백엔드 (Phase 1).

이 모듈이 유일하게 ccl 에 의존한다. Phase 2 에서 자체 파서(structs/addr/index/entry)가
완성되면 이 파일만 교체하고 `parser.py` 는 그대로 둔다.

`iter_raw_entries()` 가 반환하는 `RawCacheEntry` 가 그 경계다.
"""

from __future__ import annotations

import importlib.util
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# ccl_chromium_reader 는 `reference` extra (GitHub 설치). 모듈 로드 시점이 아니라
# 실제 파싱할 때만 import 한다 → ccl 없이도 parser.py 를 import 할 수 있다.

_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_BLOCKFILE_MARKERS = ("index", "data_0", "data_1", "data_2", "data_3")
_EXTERNAL_NAME = re.compile(r"^f_[0-9a-f]{6}$")
# _dk_ / Range_ 키를 정리한 뒤에도 남는 sparse/range 식별자 접미사 `:deadbeef:0`
_SPARSE_SUFFIX = re.compile(r":[0-9a-f]{6,}:\d+$")
_STATUS_LINE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})")


@dataclass
class RawCacheEntry:
    """서비스 분류 이전, ccl 이 읽어준 캐시 엔트리 하나."""

    cache_key: str
    url: str
    http_status: int | None
    headers: dict[str, str]  # 소문자 이름 → 값 (중복 시 마지막)
    stored_body: bytes  # stream 1, 압축 해제 전
    stored_body_size: int
    content_encoding: str | None
    source_file: str  # 'f_00024a.gz' / 'data_1' (실제 디스크상 이름)
    source_offset: int
    entry_hash: int
    entry_state: str  # 'normal' | 'evicted' | 'doomed'
    creation_time_us: int | None  # Chrome epoch microseconds (raw)
    request_time_us: int | None = None
    response_time_us: int | None = None
    warnings: list[str] = field(default_factory=list)


def ccl_available() -> bool:
    return importlib.util.find_spec("ccl_chromium_reader") is not None


def looks_like_blockfile_cache(path: Path) -> bool:
    return path.is_dir() and all((path / m).is_file() for m in _BLOCKFILE_MARKERS)


def _dt_to_us(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return round((dt - _CHROME_EPOCH).total_seconds() * 1_000_000)


@contextmanager
def _canonical_cache_dir(src: Path) -> Iterator[tuple[Path, dict[str, str]]]:
    """외부 파일이 `f_00024a.gz` 처럼 확장자가 붙어 있으면 정규 이름(`f_00024a`)으로
    심볼릭 링크한 임시 디렉터리를 만든다. 확장자가 없으면 원본을 그대로 쓴다.

    반환: (ccl 에 넘길 경로, {정규이름: 실제파일명})
    """
    real_names: dict[str, str] = {}
    needs_norm = False
    for child in src.iterdir():
        if not child.is_file():
            continue
        stem = child.name.split(".", 1)[0]
        if _EXTERNAL_NAME.match(stem):
            real_names[stem] = child.name
            if child.name != stem:
                needs_norm = True

    if not needs_norm:
        yield src, real_names
        return

    with tempfile.TemporaryDirectory(prefix="gentrace-cache-") as tmp:
        tmp_path = Path(tmp)
        for child in src.iterdir():
            if not child.is_file():
                continue
            stem = child.name.split(".", 1)[0]
            link_name = stem if _EXTERNAL_NAME.match(stem) else child.name
            (tmp_path / link_name).symlink_to(child.resolve())
        yield tmp_path, real_names


def _clean_url(cache_key_cls: type, raw_key: str) -> str:
    key = raw_key.removeprefix("Range_")
    url = cache_key_cls(key).url
    return _SPARSE_SUFFIX.sub("", str(url))


def _status_from_declarations(declarations: list[str]) -> int | None:
    for line in declarations:
        m = _STATUS_LINE.match(line)
        if m:
            return int(m.group(1))
    return None


def iter_raw_entries(cache_dir: str | Path) -> Iterator[RawCacheEntry]:
    """blockfile 캐시 디렉터리 하나를 RawCacheEntry 로 순회한다."""
    src = Path(cache_dir)
    if not looks_like_blockfile_cache(src):
        raise ValueError(f"blockfile 캐시가 아님 (index/data_0..3 없음): {src}")
    if not ccl_available():
        raise ModuleNotFoundError(
            'ccl_chromium_reader 필요 — `pip install -e ".[reference]"` (Phase 1 엔진)'
        )

    from ccl_chromium_reader.ccl_chromium_cache import CacheKey, ChromiumBlockFileCache

    with _canonical_cache_dir(src) as (ccl_dir, real_names):
        cache = ChromiumBlockFileCache(ccl_dir)
        for raw_key, entry in cache.items():
            warnings: list[str] = []
            url = _clean_url(CacheKey, raw_key)

            metas = cache.get_metadata(entry)
            meta = next((m for m in metas if m is not None), None)
            headers: dict[str, str] = {}
            status = None
            req_us = resp_us = None
            if meta is not None:
                for name, value in meta.http_header_attributes:
                    headers[name.lower()] = value
                status = _status_from_declarations(list(meta.http_header_declarations))
                req_us = _dt_to_us(meta.request_time)
                resp_us = _dt_to_us(meta.response_time)

            body = b""
            try:
                buffers = cache.get_cachefile(entry)
                body = next((b for b in buffers if b), b"") or b""
            except (ValueError, OSError) as exc:  # 잘린 스트림 등
                warnings.append(f"body read failed: {exc}")

            try:
                location = cache.get_location_for_cachefile(raw_key)[0]
                canonical = location.file_name
                source_file = real_names.get(canonical, canonical)
                source_offset = location.offset
            except (ValueError, KeyError, IndexError):
                source_file = "?"
                source_offset = 0

            yield RawCacheEntry(
                cache_key=raw_key,
                url=url,
                http_status=status,
                headers=headers,
                stored_body=body,
                stored_body_size=len(body),
                content_encoding=headers.get("content-encoding"),
                source_file=source_file,
                source_offset=source_offset,
                entry_hash=entry.entry_hash,
                entry_state=entry.state.name.lower(),
                creation_time_us=_dt_to_us(entry.creation_time),
                request_time_us=req_us,
                response_time_us=resp_us,
                warnings=warnings,
            )

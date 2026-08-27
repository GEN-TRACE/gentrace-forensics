"""chrome_blockfile_parser 통합.

index → 주소 수집 → 엔트리 순회 → Stream 0/1 → 압축 해제까지 묶어
캐시 폴더 하나를 raw 엔트리 목록으로 반환한다.
검증: ChromeCacheView / Hindsight 와 대조 (엔트리 수, URL, Content-Type, 크기).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from gentrace_forensics.classification.blockfile.entry import HttpResponseInfo


@dataclass
class ParsedCacheEntry:
    """서비스 분류 이전의 원시 캐시 엔트리."""

    cache_key: str
    url: str
    response: HttpResponseInfo
    body: bytes  # 압축 해제 완료
    body_was_compressed: bool
    source_file: str  # data_N 또는 f_XXXXXX
    source_offset: int | None
    creation_time_raw: int | None
    rankings_times_raw: dict[str, int] = field(default_factory=dict)
    entry_hash: int = 0


class BlockfileCache:
    """캐시 디렉터리 하나."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = Path(cache_dir)

    def iter_entries(self) -> Iterator[ParsedCacheEntry]:
        raise NotImplementedError

    def entries(self) -> list[ParsedCacheEntry]:
        return list(self.iter_entries())


def parse_cache_dir(cache_dir: Path) -> list[ParsedCacheEntry]:
    return BlockfileCache(cache_dir).entries()

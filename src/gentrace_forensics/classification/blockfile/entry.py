"""EntryStore + Stream 0/1 읽기.

- CacheAddr → data_N 오프셋에서 EntryStore 읽기 (키, 스트림 주소)
- Stream 0 : HTTP 응답 헤더 (pickle 형태) → status line, 헤더 딕셔너리
- Stream 1 : 응답 본문. 작은 본문은 블록 내부, 큰 본문은 f_XXXXXX.
- 캐시 키 접두어(`1/0/https://...`) 처리는 CacheKey 에서.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from gentrace_forensics.classification.blockfile.addr import CacheAddr
from gentrace_forensics.classification.blockfile.structs import EntryStore


@dataclass
class CacheKey:
    """캐시 키 문자열에서 실제 요청 URL 을 뽑는다.

    ccl_chromium_reader 의 CacheKey 방식 참고. 접두어 예:
      `1/0/https://example.com/...`  (isolation key + 기타)
      `_dk_https://... https://... https://...`
    """

    raw: str

    @property
    def url(self) -> str:
        raise NotImplementedError


@dataclass
class HttpResponseInfo:
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class CacheEntry:
    addr: CacheAddr
    store: EntryStore
    key: CacheKey
    stream_addrs: list[CacheAddr]

    def response_info(self, cache_dir: Path) -> HttpResponseInfo:
        """Stream 0 파싱."""
        raise NotImplementedError

    def body_bytes(self, cache_dir: Path) -> bytes:
        """Stream 1 raw 바이트 (압축 해제 전)."""
        raise NotImplementedError


def read_entry(cache_dir: Path, addr: CacheAddr) -> CacheEntry:
    raise NotImplementedError


def read_block_data(cache_dir: Path, addr: CacheAddr) -> bytes:
    """BLOCK 파일(data_N) 또는 EXTERNAL 파일(f_*)에서 addr 가 가리키는 raw 바이트."""
    raise NotImplementedError

"""index 파일 파싱.

헤더 + 해시테이블을 읽어 유효한 CacheAddr(엔트리 주소) 전체를 수집한다.
new-style 캐시라면 별도 index 파일(예: `the-real-index`)이 있을 수 있으므로
버전 확인 후 분기. 우선은 blockfile old-style index 를 대상으로 한다.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from gentrace_forensics.classification.blockfile.addr import CacheAddr
from gentrace_forensics.classification.blockfile.structs import (
    INDEX_HEADER_TOTAL_SIZE,
    IndexHeader,
)

_CACHE_ADDR_FORMAT = "<I"
_CACHE_ADDR_SIZE = struct.calcsize(_CACHE_ADDR_FORMAT)


def read_index_header(index_path: Path) -> IndexHeader:
    with Path(index_path).open("rb") as f:
        buf = f.read(INDEX_HEADER_TOTAL_SIZE)
    return IndexHeader.parse(buf)


def iter_entry_addresses(index_path: Path) -> Iterator[CacheAddr]:
    """해시테이블 슬롯을 순회하며 초기화된 엔트리 CacheAddr 를 yield.

    각 슬롯은 충돌 체인의 head 이며, EntryStore.next 를 따라가야 완전하지만
    그 순회는 entry.py 에서 처리한다. 여기서는 테이블에 직접 들어있는 주소만.
    """
    index_path = Path(index_path)
    header = read_index_header(index_path)
    table_byte_len = header.table_size * _CACHE_ADDR_SIZE
    with index_path.open("rb") as f:
        f.seek(INDEX_HEADER_TOTAL_SIZE)
        table_bytes = f.read(table_byte_len)
    for (value,) in struct.iter_unpack(_CACHE_ADDR_FORMAT, table_bytes):
        if value == 0:
            continue
        addr = CacheAddr(value)
        if addr.is_initialized:
            yield addr

"""disk_format.h 대응 구조체.

Chromium `net/disk_cache/blockfile/disk_format.h` / `disk_format_base.h` 의
바이너리 레이아웃을 파이썬으로 옮긴다. VM Chrome 정확한 버전을 docs/blockfile_format.md 에 기록.

주요 구조체:
  - IndexHeader   : index 파일 헤더 (magic 0xC103CAC3, version, num_entries, table_len ...)
  - BlockFileHeader: data_N 파일 헤더 (magic 0xC104CAC3, block_size, max_entries ...)
  - EntryStore    : 캐시 엔트리 (hash, next, rankings_node, key_len, key/long_key,
                    data_size[4], data_addr[4], flags, creation_time ...)
  - RankingsNode  : LRU 랭킹 노드 (last_used, last_modified ...)
"""

from __future__ import annotations

from dataclasses import dataclass

INDEX_MAGIC = 0xC103CAC3
BLOCKFILE_MAGIC = 0xC104CAC3

# TODO: 실제 캐시 파일 헤더 첫 수십 바이트를 헥스로 확인해 아래 포맷 문자열 확정.
INDEX_HEADER_FORMAT = "<"  # TODO
BLOCKFILE_HEADER_FORMAT = "<"  # TODO
ENTRY_STORE_FORMAT = "<"  # TODO


@dataclass
class IndexHeader:
    magic: int
    version: int
    num_entries: int
    num_bytes: int
    last_file: int
    table_len: int

    @classmethod
    def parse(cls, buf: bytes) -> IndexHeader:
        raise NotImplementedError


@dataclass
class BlockFileHeader:
    magic: int
    version: int
    this_file: int
    next_file: int
    entry_size: int
    num_entries: int
    max_entries: int

    @classmethod
    def parse(cls, buf: bytes) -> BlockFileHeader:
        raise NotImplementedError


@dataclass
class EntryStore:
    hash: int
    next: int
    rankings_node: int
    reuse_count: int
    refetch_count: int
    state: int
    creation_time: int  # Chrome/WebKit time
    key_len: int
    long_key: int  # CacheAddr, key_len 이 크면 사용
    data_size: tuple[int, int, int, int]
    data_addr: tuple[int, int, int, int]  # CacheAddr[4] : stream 0..3
    flags: int
    key: bytes | None  # inline key (long_key 미사용 시)

    @classmethod
    def parse(cls, buf: bytes) -> EntryStore:
        raise NotImplementedError

"""disk_format.h / disk_format_base.h 대응 구조체.

Chromium `net/disk_cache/blockfile/disk_format.h`,
`net/disk_cache/blockfile/disk_format_base.h` (2025-09 기준 main 브랜치 소스)의
바이너리 레이아웃을 파이썬으로 옮긴다.

버전 확인: 로컬 캐시 픽스처(`01_Cache_Data`, `02_Cache_Data`)의 `index` 헤더를
직접 파싱해 `magic == kIndexMagic`, `version == kVersion3_0` 을 확인했고
(`create_time`을 WebKit epoch로 환산한 값이 실제 파일 mtime과 일치), `data_N`
헤더의 `magic == kBlockMagic`, `entry_size`(36/256/1024/4096)로 파일별 블록
타입도 대조했다. docs/blockfile_format.md 에 헥스 대조 기록.

주요 구조체:
  - IndexHeader    : index 파일 헤더
  - BlockFileHeader: data_N 파일 헤더
  - EntryStore     : 캐시 엔트리 (256바이트 고정)
  - RankingsNode   : LRU 랭킹 노드 (36바이트 고정, data_0)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# --- index 파일 ---
INDEX_MAGIC = 0xC103CAC3  # kIndexMagic
INDEX_TABLE_SIZE = 0x10000  # kIndexTablesize (table_len == 0 일 때 기본값)
VERSION_2_0 = 0x20000
VERSION_2_1 = 0x20001
VERSION_3_0 = 0x30000
CURRENT_VERSION = VERSION_3_0

# --- data_N (block) 파일 ---
BLOCK_MAGIC = 0xC104CAC3  # kBlockMagic
BLOCK_VERSION_2 = 0x20000  # kBlockVersion2
BLOCK_HEADER_SIZE = 8192  # kBlockHeaderSize (두 페이지)
MAX_BLOCKS = (BLOCK_HEADER_SIZE - 80) * 8  # kMaxBlocks
ALLOC_BITMAP_WORDS = MAX_BLOCKS // 32

ENTRY_STORE_SIZE = 256  # sizeof(EntryStore), disk_format.h static_assert
RANKINGS_NODE_SIZE = 36  # sizeof(RankingsNode), disk_format.h static_assert

# EntryStore.state (enum EntryState)
ENTRY_NORMAL = 0
ENTRY_EVICTED = 1
ENTRY_DOOMED = 2

# EntryStore.flags (enum EntryFlags)
PARENT_ENTRY = 1
CHILD_ENTRY = 1 << 1

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def webkit_time_to_datetime(value: int) -> datetime | None:
    """WebKit/Chrome 시간(1601-01-01 UTC 기준 마이크로초) -> UTC datetime.

    값이 없거나(0) 음수면 기록되지 않은 것으로 보고 None.
    """
    if value <= 0:
        return None
    return _WEBKIT_EPOCH + timedelta(microseconds=value)


# uint32 magic; uint32 version; int32 num_entries; int32 old_v2_num_bytes;
# int32 last_file; int32 this_id; CacheAddr stats; int32 table_len;
# int32 crash; int32 experiment; uint64 create_time; int64 num_bytes;
# int32 corruption_detected;  (+ int32 pad[49]; LruData lru; 는 파싱하지 않음)
_INDEX_HEADER_FORMAT = "<IIiiiiIiiiQqi"
INDEX_HEADER_FIXED_SIZE = struct.calcsize(_INDEX_HEADER_FORMAT)

# IndexHeader 뒤에 따라오는 int32 pad[49] + LruData(구성원 합산 112바이트) 는
# 지금 분류 파이프라인에 불필요해 구조체로는 만들지 않지만, 해시테이블이
# 시작하는 오프셋을 구하려면 전체 온디스크 크기가 필요하다.
# 실제 픽스처의 index 파일 크기가 `INDEX_HEADER_TOTAL_SIZE + table_size * 4` 와
# 정확히 일치함을 확인해 검증했다 (예: 01_Cache_Data/index = 368 + 131072*4).
_INDEX_HEADER_PAD_SIZE = 49 * 4  # int32 pad[49]
_LRU_DATA_SIZE = (
    112  # pad1[2]+filled+sizes[5]+heads[5]+tails[5]+transaction+operation+operation_list+pad2[7]
)
INDEX_HEADER_TOTAL_SIZE = INDEX_HEADER_FIXED_SIZE + _INDEX_HEADER_PAD_SIZE + _LRU_DATA_SIZE


@dataclass(frozen=True)
class IndexHeader:
    """index 파일 맨 앞 고정 크기 헤더 (해시테이블 앞부분)."""

    magic: int
    version: int
    num_entries: int
    old_v2_num_bytes: int  # 예전(v2) 필드, v3 캐시에서는 관측상 0
    last_file: int
    this_id: int
    stats: int  # CacheAddr
    table_len: int
    crash: int
    experiment: int
    create_time: int  # raw WebKit time (us)
    num_bytes: int
    corruption_detected: int

    @property
    def is_valid_magic(self) -> bool:
        return self.magic == INDEX_MAGIC

    @property
    def version_major(self) -> int:
        return self.version >> 16

    @property
    def version_minor(self) -> int:
        return self.version & 0xFFFF

    @property
    def table_size(self) -> int:
        """실제 해시테이블 슬롯 수 (table_len==0 이면 기본 kIndexTablesize)."""
        return self.table_len or INDEX_TABLE_SIZE

    @property
    def created(self) -> datetime | None:
        return webkit_time_to_datetime(self.create_time)

    @classmethod
    def parse(cls, buf: bytes) -> IndexHeader:
        if len(buf) < INDEX_HEADER_FIXED_SIZE:
            raise ValueError(
                f"index header too short: {len(buf)} bytes (need >= {INDEX_HEADER_FIXED_SIZE})"
            )
        fields = struct.unpack(_INDEX_HEADER_FORMAT, buf[:INDEX_HEADER_FIXED_SIZE])
        return cls(*fields)


# uint32 magic; uint32 version; int16 this_file; int16 next_file;
# int32 entry_size; int32 num_entries; int32 max_entries;
# (+ empty[4]; hints[4]; updating; user[5]; allocation_map[2028] 는 파싱하지 않음)
_BLOCK_FILE_HEADER_FORMAT = "<IIhhiii"
BLOCK_FILE_HEADER_FIXED_SIZE = struct.calcsize(_BLOCK_FILE_HEADER_FORMAT)


@dataclass(frozen=True)
class BlockFileHeader:
    """data_N 파일 맨 앞 고정 크기 헤더 (뒤에 8192바이트까지 할당 비트맵)."""

    magic: int
    version: int
    this_file: int
    next_file: int
    entry_size: int
    num_entries: int
    max_entries: int

    @property
    def is_valid_magic(self) -> bool:
        return self.magic == BLOCK_MAGIC

    @classmethod
    def parse(cls, buf: bytes) -> BlockFileHeader:
        if len(buf) < BLOCK_FILE_HEADER_FIXED_SIZE:
            raise ValueError(
                f"block file header too short: {len(buf)} bytes "
                f"(need >= {BLOCK_FILE_HEADER_FIXED_SIZE})"
            )
        fields = struct.unpack(_BLOCK_FILE_HEADER_FORMAT, buf[:BLOCK_FILE_HEADER_FIXED_SIZE])
        return cls(*fields)


# uint32 hash; CacheAddr next; CacheAddr rankings_node; int32 reuse_count;
# int32 refetch_count; int32 state; uint64 creation_time; int32 key_len;
# CacheAddr long_key; int32 data_size[4]; CacheAddr data_addr[4];
# uint32 flags; int32 pad[4]; uint32 self_hash; char key[160]
_ENTRY_STORE_FORMAT = "<IIIiiiQiI4i4II4iI160s"
if struct.calcsize(_ENTRY_STORE_FORMAT) != ENTRY_STORE_SIZE:
    raise AssertionError("bad EntryStore format")


@dataclass(frozen=True)
class EntryStore:
    """캐시 엔트리 하나 (data_1, 256바이트 고정)."""

    hash: int
    next: int  # CacheAddr, 해시 충돌 체인의 다음 엔트리
    rankings_node: int  # CacheAddr, data_0 의 RankingsNode
    reuse_count: int
    refetch_count: int
    state: int
    creation_time: int  # raw WebKit time (us)
    key_len: int
    long_key: int  # CacheAddr, key_len 이 inline key 보다 크면 사용
    data_size: tuple[int, int, int, int]
    data_addr: tuple[int, int, int, int]  # CacheAddr[4], stream 0..3
    flags: int
    self_hash: int
    key: bytes  # inline key (null 로 채워짐), long_key 사용 시 무의미

    @property
    def created(self) -> datetime | None:
        return webkit_time_to_datetime(self.creation_time)

    @property
    def inline_key(self) -> str:
        """long_key 미사용(key_len <= len(key 버퍼)) 시의 캐시 키 문자열."""
        return self.key.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    @classmethod
    def parse(cls, buf: bytes) -> EntryStore:
        if len(buf) < ENTRY_STORE_SIZE:
            raise ValueError(f"entry store too short: {len(buf)} bytes (need {ENTRY_STORE_SIZE})")
        (
            hash_,
            next_,
            rankings_node,
            reuse_count,
            refetch_count,
            state,
            creation_time,
            key_len,
            long_key,
            d0,
            d1,
            d2,
            d3,
            a0,
            a1,
            a2,
            a3,
            flags,
            _pad0,
            _pad1,
            _pad2,
            _pad3,
            self_hash,
            key,
        ) = struct.unpack(_ENTRY_STORE_FORMAT, buf[:ENTRY_STORE_SIZE])
        return cls(
            hash=hash_,
            next=next_,
            rankings_node=rankings_node,
            reuse_count=reuse_count,
            refetch_count=refetch_count,
            state=state,
            creation_time=creation_time,
            key_len=key_len,
            long_key=long_key,
            data_size=(d0, d1, d2, d3),
            data_addr=(a0, a1, a2, a3),
            flags=flags,
            self_hash=self_hash,
            key=key,
        )


# uint64 last_used; uint64 no_longer_used_last_modified; CacheAddr next;
# CacheAddr prev; CacheAddr contents; int32 dirty; uint32 self_hash
_RANKINGS_NODE_FORMAT = "<QQIIIiI"
if struct.calcsize(_RANKINGS_NODE_FORMAT) != RANKINGS_NODE_SIZE:
    raise AssertionError("bad RankingsNode format")


@dataclass(frozen=True)
class RankingsNode:
    """LRU 랭킹 노드 (data_0, 36바이트 고정)."""

    last_used: int  # raw WebKit time (us)
    no_longer_used_last_modified: int  # raw WebKit time (us)
    next: int  # CacheAddr
    prev: int  # CacheAddr
    contents: int  # CacheAddr, 대응하는 EntryStore
    dirty: int
    self_hash: int

    @classmethod
    def parse(cls, buf: bytes) -> RankingsNode:
        if len(buf) < RANKINGS_NODE_SIZE:
            raise ValueError(
                f"rankings node too short: {len(buf)} bytes (need {RANKINGS_NODE_SIZE})"
            )
        fields = struct.unpack(_RANKINGS_NODE_FORMAT, buf[:RANKINGS_NODE_SIZE])
        return cls(*fields)

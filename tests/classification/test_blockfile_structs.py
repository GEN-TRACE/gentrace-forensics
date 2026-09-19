"""structs.py / addr.py / index.py 테스트.

CacheAddr 비트 해석은 합성 값으로, IndexHeader/BlockFileHeader/EntryStore
레이아웃은 로컬 캐시 픽스처의 실제 바이트로 검증한다 (ccl_chromium_reader 와
무관하게 자체 구현만으로 대조 가능한 선에서: magic, on-disk 크기, entry_size 등).
"""

from __future__ import annotations

import struct
from pathlib import Path

from gentrace_forensics.classification.blockfile.addr import (
    BLOCK_SIZE_FOR_TYPE,
    CacheAddr,
    FileType,
)
from gentrace_forensics.classification.blockfile.index import (
    iter_entry_addresses,
    read_index_header,
)
from gentrace_forensics.classification.blockfile.structs import (
    BLOCK_MAGIC,
    ENTRY_STORE_SIZE,
    INDEX_HEADER_TOTAL_SIZE,
    INDEX_MAGIC,
    RANKINGS_NODE_SIZE,
    VERSION_3_0,
    BlockFileHeader,
)

# --- addr.py: 실제 픽스처의 IndexHeader.stats 필드에서 관측된 값
# (초기화됨, BLOCK_256, data_1, 블록 2개, 시작 블록 0) ---
_SAMPLE_BLOCK_ADDR = 0xA1010000


def test_block_addr_decodes_known_value() -> None:
    addr = CacheAddr(_SAMPLE_BLOCK_ADDR)
    assert addr.is_initialized
    assert not addr.is_external
    assert addr.file_type == FileType.BLOCK_256
    assert addr.block_file_number == 1
    assert addr.num_blocks == 2
    assert addr.block_number == 0
    assert addr.block_size == 256
    assert addr.file_offset(8192) == 8192


def test_external_addr_decodes_file_number() -> None:
    # is_initialized(bit31) + EXTERNAL(file_type=0, bits30-28) + f_00002a
    addr = CacheAddr(0x8000002A)
    assert addr.is_initialized
    assert addr.is_external
    assert addr.file_type == FileType.EXTERNAL
    assert addr.external_file_number == 0x2A


def test_uninitialized_addr() -> None:
    assert not CacheAddr(0).is_initialized


def test_block_size_table_matches_struct_constants() -> None:
    assert BLOCK_SIZE_FOR_TYPE[FileType.RANKINGS] == RANKINGS_NODE_SIZE
    assert BLOCK_SIZE_FOR_TYPE[FileType.BLOCK_256] == ENTRY_STORE_SIZE


# --- structs.py / index.py: 실제 캐시 픽스처와 대조 ---


def test_index_header_matches_real_fixture(cache_fixture_dir: Path) -> None:
    header = read_index_header(cache_fixture_dir / "index")
    assert header.is_valid_magic
    assert header.magic == INDEX_MAGIC
    assert header.version == VERSION_3_0
    assert header.num_entries > 0

    # IndexHeader(368바이트, pad+LruData 포함) + 해시테이블(각 슬롯 4바이트)이
    # index 파일 전체를 정확히 채워야 한다 - 오프셋 계산이 맞다는 가장 강한 증거.
    actual_size = (cache_fixture_dir / "index").stat().st_size
    assert actual_size == INDEX_HEADER_TOTAL_SIZE + header.table_size * 4


def test_iter_entry_addresses_are_all_initialized(cache_fixture_dir: Path) -> None:
    header = read_index_header(cache_fixture_dir / "index")
    addrs = list(iter_entry_addresses(cache_fixture_dir / "index"))

    assert addrs, "해시테이블에 초기화된 엔트리 주소가 하나도 없음"
    # 여기서는 해시 충돌 체인을 안 따라가므로(테이블 슬롯당 head 하나) 실제
    # num_entries 보다 적거나 같아야 한다.
    assert len(addrs) <= header.num_entries
    for addr in addrs:
        assert addr.is_initialized


def test_block_file_headers_match_real_fixture(cache_fixture_dir: Path) -> None:
    # data_0 = RANKINGS(36바이트), data_1 = BLOCK_256(EntryStore, 256바이트)
    expected_entry_size = {
        "data_0": RANKINGS_NODE_SIZE,
        "data_1": ENTRY_STORE_SIZE,
    }
    for name, entry_size in expected_entry_size.items():
        path = cache_fixture_dir / name
        with path.open("rb") as f:
            buf = f.read(32)
        header = BlockFileHeader.parse(buf)
        assert header.is_valid_magic
        assert header.magic == BLOCK_MAGIC
        assert header.entry_size == entry_size
        assert header.this_file >= 0
        assert 0 <= header.num_entries <= header.max_entries


def test_cache_addr_struct_size_is_four_bytes() -> None:
    assert struct.calcsize("<I") == 4

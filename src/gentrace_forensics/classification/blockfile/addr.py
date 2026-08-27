"""CacheAddr 해석.

명세: Chromium `net/disk_cache/blockfile/addr.h`.
32비트 값 하나가 "데이터가 어디 있는지"를 인코딩한다.

  bit 31      : is_initialized
  bit 28-30   : file_type (0=EXTERNAL(f_*), 1=RANKINGS, 2..5=BLOCK_256/1K/4K/...)
  EXTERNAL 인 경우 하위 28비트 = f_<hex> 파일 번호
  BLOCK 인 경우:
    bit 24-25 : num_blocks - 1
    bit 16-23 : file_number  (data_<n>)
    bit 0-15  : block_number (파일 내 블록 인덱스)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class FileType(IntEnum):
    EXTERNAL = 0
    RANKINGS = 1
    BLOCK_256 = 2
    BLOCK_1K = 3
    BLOCK_4K = 4
    BLOCK_FILES = 5
    BLOCK_ENTRIES = 6
    BLOCK_EVICTED = 7


BLOCK_SIZE_FOR_TYPE = {
    FileType.RANKINGS: 36,
    FileType.BLOCK_256: 256,
    FileType.BLOCK_1K: 1024,
    FileType.BLOCK_4K: 4096,
}


@dataclass(frozen=True)
class CacheAddr:
    raw: int

    @property
    def is_initialized(self) -> bool:
        return bool(self.raw & 0x80000000)

    @property
    def file_type(self) -> FileType:
        return FileType((self.raw & 0x70000000) >> 28)

    @property
    def is_external(self) -> bool:
        return self.file_type == FileType.EXTERNAL

    @property
    def external_file_number(self) -> int:
        """f_<hex> 파일 번호 (EXTERNAL 전용)."""
        raise NotImplementedError

    @property
    def block_file_number(self) -> int:
        """data_<n> 파일 번호 (BLOCK 전용)."""
        raise NotImplementedError

    @property
    def block_number(self) -> int:
        raise NotImplementedError

    @property
    def num_blocks(self) -> int:
        raise NotImplementedError

    def file_offset(self, header_size: int) -> int:
        """BLOCK 파일 내 바이트 오프셋 = header_size + block_number * block_size."""
        raise NotImplementedError

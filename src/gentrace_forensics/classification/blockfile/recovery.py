"""Recover checksum-verified EntryStores omitted from the persisted index.

This is a cache block scan, not filesystem carving. Allocation is recorded rather
than inferred from a stale index. Indexed keys take precedence over old remnants.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from gentrace_forensics.classification.blockfile.addr import CacheAddr
from gentrace_forensics.classification.blockfile.entry import CacheEntry, read_entry
from gentrace_forensics.classification.blockfile.structs import (
    BLOCK_HEADER_SIZE,
    BlockFileHeader,
    EntryStore,
)


def persistent_hash(data: bytes) -> int:
    """Chromium's 32-bit persistent hash (SuperFastHash algorithm)."""
    mask = 0xFFFFFFFF
    value = len(data)
    if not data:
        return 0
    end = len(data) - len(data) % 4
    for low, high in struct.iter_unpack("<HH", data[:end]):
        value = (value + low) & mask
        value = ((value << 16) ^ (high << 11) ^ value) & mask
        value = (value + (value >> 11)) & mask
    tail = data[end:]
    if len(tail) >= 2:
        value = (value + int.from_bytes(tail[:2], "little")) & mask
        shift = 16 if len(tail) == 3 else 11
        value = (value ^ (value << shift)) & mask
        if len(tail) == 3:
            value ^= (int.from_bytes(tail[2:], "little", signed=True) << 18) & mask
        value = (value + (value >> (11 if len(tail) == 3 else 17))) & mask
    elif tail:
        value = (value + int.from_bytes(tail, "little", signed=True)) & mask
        value = (value ^ (value << 10)) & mask
        value = (value + (value >> 1)) & mask
    for left, right in ((3, 5), (4, 17), (25, 6)):
        value = (value ^ (value << left)) & mask
        value = (value + (value >> right)) & mask
    return value


def scan_unindexed(
    cache_dir: Path, occupied: set[tuple[int, int]], known_keys: set[str]
) -> Iterator[CacheEntry]:
    for path in sorted(cache_dir.glob("data_*")):
        if not path.name[5:].isdigit():
            continue
        file_number = int(path.name[5:])
        if file_number > 255:
            continue
        with path.open("rb") as source:
            header_bytes = source.read(BLOCK_HEADER_SIZE)
            if len(header_bytes) != BLOCK_HEADER_SIZE:
                continue
            header = BlockFileHeader.parse(header_bytes)
            if not header.is_valid_magic or header.entry_size != 256:
                continue
            count = min((path.stat().st_size - BLOCK_HEADER_SIZE) // 256, 64896)
            for block in range(count):
                if (file_number, block) in occupied:
                    continue
                source.seek(BLOCK_HEADER_SIZE + block * 256)
                raw = source.read(256)
                store = EntryStore.parse(raw)
                if (
                    store.state not in (0, 1, 2)
                    or not 0 < store.key_len <= 65536
                    or store.reuse_count < 0
                    or store.refetch_count < 0
                    or store.self_hash == 0
                    or persistent_hash(raw[:92]) != store.self_hash
                    or any(size < 0 for size in store.data_size)
                ):
                    continue
                blocks = 1 if store.long_key else (96 + store.key_len + 1 + 255) // 256
                if not 1 <= blocks <= 4 or block + blocks > count:
                    continue
                if any((file_number, block + i) in occupied for i in range(blocks)):
                    continue
                addr = CacheAddr(0xA0000000 | ((blocks - 1) << 24) | (file_number << 16) | block)
                try:
                    entry = read_entry(cache_dir, addr)
                    key = entry.key.raw.encode("utf-8")
                    if len(key) != store.key_len or persistent_hash(key) != store.hash:
                        continue
                    url = urlsplit(entry.key.url)
                    if url.scheme not in ("http", "https") or not url.hostname:
                        continue
                    if entry.key.raw in known_keys:
                        continue
                    if entry.response_info(cache_dir).status is None:
                        continue
                except (OSError, ValueError):
                    continue
                allocated = all(
                    header_bytes[80 + (block + i) // 8] & (1 << ((block + i) % 8))
                    for i in range(blocks)
                )
                entry.discovery = "block_scan"
                entry.allocation = "allocated" if allocated else "unallocated"
                known_keys.add(entry.key.raw)
                occupied.update((file_number, block + i) for i in range(blocks))
                yield entry

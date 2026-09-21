"""Unindexed cache records remain recoverable without accepting corrupt blocks."""

import struct

import pytest

from gentrace_forensics.classification.blockfile.entry import iter_entries
from gentrace_forensics.classification.blockfile.recovery import persistent_hash
from gentrace_forensics.classification.blockfile.structs import INDEX_HEADER_TOTAL_SIZE


def cache_with_unindexed_entry(path, *, allocated=False):
    key = b"1/0/https://chatgpt.com/backend-api/estuary/content?id=file-example"
    header_blob = b"HTTP/1.1 200 OK\0Content-Type: image/png\0\0"
    payload = struct.pack("<IqqI", 0, 0, 0, len(header_blob)) + header_blob
    payload += b"\0" * (-len(payload) % 4)
    response = struct.pack("<I", len(payload)) + payload
    (path / "f_000001").write_bytes(response)
    index = bytearray(INDEX_HEADER_TOTAL_SIZE + 4)
    struct.pack_into("<II", index, 0, 0xC103CAC3, 0x30000)
    struct.pack_into("<i", index, 28, 1)
    (path / "index").write_bytes(index)
    block = bytearray(8192 + 512)
    struct.pack_into("<IIhhiii", block, 0, 0xC104CAC3, 0x20000, 1, 0, 256, 1, 2)
    block[80] = int(allocated)
    record = bytearray(256)
    struct.pack_into("<I", record, 0, persistent_hash(key))
    struct.pack_into("<i", record, 32, len(key))
    struct.pack_into("<i", record, 40, len(response))
    struct.pack_into("<I", record, 56, 0x80000001)
    struct.pack_into("<I", record, 92, persistent_hash(record[:92]))
    record[96 : 96 + len(key)] = key
    block[8192:8448] = record
    (path / "data_1").write_bytes(block)
    return block


@pytest.mark.parametrize("allocated", [True, False])
def test_unindexed_entry_is_recovered_with_allocation_provenance(tmp_path, allocated):
    cache_with_unindexed_entry(tmp_path, allocated=allocated)
    assert list(iter_entries(tmp_path, include_unindexed=False)) == []
    [record] = list(iter_entries(tmp_path))
    assert record.discovery == "block_scan"
    assert record.allocation == ("allocated" if allocated else "unallocated")
    assert record.key.url.endswith("id=file-example")
    assert record.response_info(tmp_path).status == 200


@pytest.mark.parametrize("offset", [0, 40, 92, 110])
def test_corrupt_header_or_key_is_not_recovered(tmp_path, offset):
    block = cache_with_unindexed_entry(tmp_path)
    block[8192 + offset] ^= 1
    (tmp_path / "data_1").write_bytes(block)
    assert list(iter_entries(tmp_path)) == []


def test_missing_response_is_not_claimed_as_recovered_entry(tmp_path):
    cache_with_unindexed_entry(tmp_path)
    (tmp_path / "f_000001").write_bytes(b"")
    assert list(iter_entries(tmp_path)) == []

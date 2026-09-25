"""Chromium blockfile sparse allocation recovery, with no hole filling.

Layout source: net/disk_cache/blockfile/{disk_format_base.h,sparse_control.cc}.
Only the exact parent key, generation signature and allocated child blocks join.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry

CHILD_SIZE = 1 << 20
BLOCK_SIZE = 1024
MAGIC = 0xC103CAC3
CHILD_KEY = re.compile(r"^Range_(.*):([0-9a-fA-F]+):([0-9a-fA-F]+)$")
CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+)")


@dataclass
class Span:
    start: int
    data: bytes
    entry_key: str
    source_offset: int

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass
class SparseResult:
    parent_key: str
    spans: list[Span] = field(default_factory=list)
    expected_size: int | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    body: bytes | None = None
    coverage: list[tuple[int, int]] = field(default_factory=list)


def _header(data: bytes, *, child: bool) -> tuple[int, int, int, int, bytes]:
    if len(data) < 68 or len(data) % 4:
        raise ValueError("missing or truncated sparse index")
    signature, magic, key_len, last_block, last_len = struct.unpack_from("<qIiii", data)
    if magic != MAGIC or key_len < 1:
        raise ValueError("invalid sparse header")
    bitmap = data[64:]
    if child and len(bitmap) != 128 or not child and len(bitmap) > 8192:
        raise ValueError("invalid sparse bitmap size")
    if child and not (-1 <= last_block < 1024 and 0 <= last_len < 1024):
        raise ValueError("invalid sparse last block")
    return signature, key_len, last_block, last_len, bitmap


def _allocated(bitmap: bytes, index: int) -> bool:
    return 0 <= index < len(bitmap) * 8 and bool(bitmap[index // 8] & (1 << (index % 8)))


def assemble(
    spans: list[Span], expected_size: int | None, *, max_size: int = 256 * 1024 * 1024
) -> tuple[bytes | None, list[tuple[int, int]], list[str]]:
    """Check overlaps and coverage before allocating a whole output buffer."""
    ordered = sorted(spans, key=lambda item: (item.start, item.end))
    coverage: list[tuple[int, int]] = []
    errors: list[str] = []
    active: list[Span] = []
    for span in ordered:
        if span.start < 0 or expected_size is not None and span.end > expected_size:
            errors.append("range outside expected resource size")
        active = [old for old in active if old.end > span.start]
        for old in active:
            stop = min(old.end, span.end)
            if (
                old.data[span.start - old.start : stop - old.start]
                != span.data[: stop - span.start]
            ):
                errors.append("conflicting overlapping bytes")
        active.append(span)
        if not coverage or coverage[-1][1] < span.start:
            coverage.append((span.start, span.end))
        else:
            coverage[-1] = (coverage[-1][0], max(coverage[-1][1], span.end))
    if errors or expected_size is None or coverage != [(0, expected_size)]:
        return None, coverage, sorted(set(errors))
    if expected_size > max_size:
        return None, coverage, ["resource exceeds assembly size limit"]
    output = bytearray(expected_size)
    for span in ordered:
        output[span.start : span.end] = span.data
    return bytes(output), coverage, []


def recover_sparse(entries: list[ParsedCacheEntry]) -> dict[str, SparseResult]:
    parents = {entry.cache_key: entry for entry in entries if entry.entry_flags & 1}
    children: dict[str, list[tuple[int, int, ParsedCacheEntry]]] = {}
    for entry in entries:
        match = CHILD_KEY.fullmatch(entry.cache_key)
        if match and entry.entry_flags & 2:
            children.setdefault(match[1], []).append((int(match[2], 16), int(match[3], 16), entry))
    results: dict[str, SparseResult] = {}
    for key in parents.keys() | children.keys():
        result = SparseResult(key)
        results[key] = result
        parent = parents.get(key)
        if parent is None:
            result.errors.append("sparse parent unavailable; generation cannot be validated")
            continue
        try:
            signature, key_len, _, _, bitmap = _header(parent.sparse_data, child=False)
            if key_len != len(key.encode("utf-8")):
                raise ValueError("sparse parent key length mismatch")
        except ValueError as exc:
            result.errors.append(str(exc))
            continue
        content_range = CONTENT_RANGE.fullmatch(parent.response.get("content-range") or "")
        if content_range:
            first, last, total = map(int, content_range.groups())
            if 0 <= first <= last < total:
                result.expected_size = total
            else:
                result.errors.append("invalid parent Content-Range")
        if parent.content_encoding not in {None, "identity"}:
            result.errors.append("encoded sparse resource is unsupported")
        seen: set[int] = set()
        for child_signature, child_id, child in children.get(key, []):
            if child_signature != signature & ((1 << 64) - 1):
                result.warnings.append("stale child generation excluded")
                continue
            if not _allocated(bitmap, child_id):
                result.warnings.append("unallocated child excluded")
                continue
            try:
                child_sig, child_key_len, last_block, last_len, bits = _header(
                    child.sparse_data, child=True
                )
                if child_sig != signature or child_key_len != key_len:
                    raise ValueError("child header does not match parent")
                if child.warnings:
                    raise ValueError("child parser warnings: " + "; ".join(child.warnings))
                child_spans: list[Span] = []
                for block in range(1024):
                    size = (
                        BLOCK_SIZE
                        if _allocated(bits, block)
                        else last_len
                        if block == last_block
                        else 0
                    )
                    if not size:
                        continue
                    offset = block * BLOCK_SIZE
                    if offset + size > len(child.body):
                        raise ValueError("allocated block exceeds child body")
                    # Coalesce adjacent blocks but retain their original stream offset.
                    start = child_id * CHILD_SIZE + offset
                    if child_spans and child_spans[-1].end == start:
                        child_spans[-1].data += child.body[offset : offset + size]
                    else:
                        child_spans.append(
                            Span(start, child.body[offset : offset + size], child.cache_key, offset)
                        )
                result.spans.extend(child_spans)
                seen.add(child_id)
            except ValueError as exc:
                result.errors.append(str(exc))
        missing = [i for i in range(len(bitmap) * 8) if _allocated(bitmap, i) and i not in seen]
        if missing:
            result.warnings.append(f"{len(missing)} allocated children unavailable")
        body, result.coverage, errors = assemble(result.spans, result.expected_size)
        result.errors.extend(errors)
        result.body = body if not result.errors else None
    return results

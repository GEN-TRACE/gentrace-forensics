"""Blockfile 파서 테스트.

로컬 Chrome 캐시 픽스처(`cache_fixture_dir`)에 대해 돈다. 픽스처가 없으면
conftest 가 skip 처리하므로 CI 에서는 실행되지 않는다.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from gentrace_forensics.classification.blockfile.parser import (
    ParsedCacheEntry,
    parse_cache_dir,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UNSAFE = re.compile(r"[\x00/\\]")


@pytest.fixture(scope="module")
def entries(cache_fixture_dir: Path) -> list[ParsedCacheEntry]:
    return parse_cache_dir(cache_fixture_dir)


def test_parses_many_entries(entries: list[ParsedCacheEntry]) -> None:
    assert len(entries) > 100


def test_every_entry_has_url_and_key(entries: list[ParsedCacheEntry]) -> None:
    for e in entries:
        assert e.cache_key
        assert e.url
        assert "\x00" not in e.url


def test_no_parse_warnings(entries: list[ParsedCacheEntry]) -> None:
    warned = {e.url: e.warnings for e in entries if e.warnings}
    assert not warned, f"파싱 경고 발생: {warned}"


def test_body_sha256_matches_body(entries: list[ParsedCacheEntry]) -> None:
    for e in entries[:200]:
        assert _SHA256.match(e.body_sha256)
        assert e.body_sha256 == hashlib.sha256(e.body).hexdigest()


def test_filenames_are_safe(entries: list[ParsedCacheEntry]) -> None:
    for e in entries:
        name = e.filename
        assert name
        assert not _UNSAFE.search(name)


def test_gzip_bodies_are_decompressed(entries: list[ParsedCacheEntry]) -> None:
    gzipped = [e for e in entries if (e.content_encoding or "").lower() == "gzip" and e.body]
    assert gzipped, "gzip 엔트리가 하나도 없음 (픽스처 확인)"
    # 압축 해제됐다면 대부분 저장 크기보다 본문이 크고, gzip 매직으로 시작하지 않는다
    expanded = [e for e in gzipped if len(e.body) > e.stored_body_size]
    assert len(expanded) >= len(gzipped) // 2
    for e in gzipped:
        assert not e.body.startswith(b"\x1f\x8b")


def test_source_file_is_recorded(entries: list[ParsedCacheEntry]) -> None:
    for e in entries:
        assert e.source_file
        assert e.source_file == "?" or e.source_file.startswith(("data_", "f_"))


def test_timestamps_present(entries: list[ParsedCacheEntry]) -> None:
    with_ts = [e for e in entries if e.cache_timestamps.get("creation_time_us")]
    assert len(with_ts) > len(entries) // 2
    for e in with_ts[:50]:
        # Chrome epoch(1601) microseconds → 2000년 이후면 대략 1.26e16 이상
        assert e.cache_timestamps["creation_time_us"] > 12_000_000_000_000_000

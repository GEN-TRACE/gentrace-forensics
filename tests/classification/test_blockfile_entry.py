"""entry.py 테스트.

CacheKey / Stream 0 pickle 파싱은 합성 값으로, `iter_entries` 는 로컬 캐시
픽스처 전체를 `_ccl_backend`(참조 구현, Phase 1 엔진)와 URL·상태코드·헤더·
본문 SHA-256 까지 전부 대조해 검증한다 — CONTRIBUTING.md 3.2.1/7절의
"참조 구현과 대조" 요구를 만족하는 가장 강한 테스트.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from gentrace_forensics.classification.blockfile import entry
from gentrace_forensics.classification.blockfile._ccl_backend import iter_raw_entries


def _build_stream0_pickle(
    *, status_line: str = "HTTP/1.1 200 OK", headers: dict[str, str] | None = None
) -> bytes:
    """Stream 0 pickle 합성 바이트를 만든다 (entry._parse_response_info 테스트용)."""
    headers = headers or {}
    parts = [status_line] + [f"{k}: {v}" for k, v in headers.items()]
    header_blob = b"\x00".join(p.encode("latin-1") for p in parts) + b"\x00\x00"
    padded = header_blob + b"\x00" * (-len(header_blob) % 4)

    payload = struct.pack("<I", 0)  # flags (no extra flags bit)
    payload += struct.pack("<q", 0)  # request_time
    payload += struct.pack("<q", 0)  # response_time
    payload += struct.pack("<I", len(header_blob))
    payload += padded

    return struct.pack("<I", len(payload)) + payload


def test_parse_response_info_extracts_status_and_headers() -> None:
    buf = _build_stream0_pickle(
        status_line="HTTP/1.1 404 Not Found",
        headers={"Content-Type": "application/json", "X-Custom": "value"},
    )
    info = entry._parse_response_info(buf)
    assert info.status == 404
    assert info.get("content-type") == "application/json"
    assert info.get("x-custom") == "value"


def test_parse_response_info_rejects_bad_length() -> None:
    buf = _build_stream0_pickle()
    corrupted = struct.pack("<I", 999) + buf[4:]
    try:
        entry._parse_response_info(corrupted)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for mismatched pickle length")


def test_cache_key_plain_url() -> None:
    assert entry.CacheKey("https://example.com/a").url == "https://example.com/a"


def test_cache_key_upload_only_prefix() -> None:
    assert entry.CacheKey("0/https://example.com/a").url == "https://example.com/a"


def test_cache_key_credential_upload_prefix() -> None:
    assert entry.CacheKey("1/0/https://example.com/a").url == "https://example.com/a"


def test_cache_key_double_key_prefix() -> None:
    key = "1/0/_dk_https://top.example https://top.example https://example.com/a"
    assert entry.CacheKey(key).url == "https://example.com/a"


def test_cache_key_range_and_sparse_suffix_stripped() -> None:
    key = "Range_1/0/https://example.com/big.mp4:2fb884ac72675a:0"
    assert entry.CacheKey(key).url == "https://example.com/big.mp4"


# --- 통합: 로컬 캐시 픽스처 전체를 참조 구현(ccl_chromium_reader)과 대조 ---


def test_iter_entries_matches_reference_implementation(cache_fixture_dir: Path) -> None:
    mine = {}
    for e in entry.iter_entries(cache_fixture_dir):
        info = e.response_info(cache_fixture_dir)
        body = e.body_bytes(cache_fixture_dir)
        mine[e.key.raw] = (
            e.key.url,
            info.status,
            dict(info.headers),
            hashlib.sha256(body).hexdigest(),
        )

    ref = {}
    for raw in iter_raw_entries(cache_fixture_dir):
        ref[raw.cache_key] = (
            raw.url,
            raw.http_status,
            raw.headers,
            hashlib.sha256(raw.stored_body).hexdigest(),
        )

    assert mine, "픽스처에서 엔트리를 하나도 못 읽음"
    assert set(mine) == set(ref), (
        f"키 집합 불일치: mine 전용 {len(set(mine) - set(ref))}개, "
        f"ref 전용 {len(set(ref) - set(mine))}개"
    )
    mismatches = {k: (mine[k], ref[k]) for k in mine if mine[k] != ref[k]}
    assert not mismatches, f"{len(mismatches)}개 엔트리 불일치: {list(mismatches)[:3]}"

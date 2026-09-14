"""http.py 유닛 테스트 (픽스처 불필요, CI 에서 실행)."""

from __future__ import annotations

import gzip
import zlib

import pytest

from gentrace_forensics.classification import http


class TestDecompress:
    def test_gzip_roundtrip(self) -> None:
        raw = b"hello world" * 50
        assert http.decompress(gzip.compress(raw), "gzip") == raw

    def test_deflate_zlib_wrapped(self) -> None:
        raw = b"deflate me" * 20
        assert http.decompress(zlib.compress(raw), "deflate") == raw

    def test_deflate_raw(self) -> None:
        raw = b"raw deflate" * 20
        comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        blob = comp.compress(raw) + comp.flush()
        assert http.decompress(blob, "deflate") == raw

    def test_identity_and_none(self) -> None:
        assert http.decompress(b"plain", "identity") == b"plain"
        assert http.decompress(b"plain", None) == b"plain"
        assert http.decompress(b"", "gzip") == b""

    def test_unknown_encoding_passthrough(self) -> None:
        assert http.decompress(b"\x00\x01", "weird-thing") == b"\x00\x01"

    def test_truncated_gzip_returns_raw(self) -> None:
        truncated = gzip.compress(b"x" * 1000)[:20]
        assert http.decompress(truncated, "gzip") == truncated

    def test_truncated_gzip_records_warning(self) -> None:
        truncated = gzip.compress(b"x" * 1000)[:20]
        body, warnings = http.decompress_with_warnings(truncated, "gzip")
        assert body == truncated
        assert warnings == ["gzip decompression failed: EOFError"]

    def test_stacked_encodings(self) -> None:
        raw = b"double wrapped"
        assert http.decompress(gzip.compress(raw), "identity, gzip") == raw

    @pytest.mark.skipif(http.brotli is None, reason="brotli 미설치")
    def test_brotli(self) -> None:
        raw = b"brotli payload" * 10
        assert http.decompress(http.brotli.compress(raw), "br") == raw

    @pytest.mark.skipif(http.zstandard is None, reason="zstandard 미설치")
    def test_zstandard(self) -> None:
        raw = b"zstandard payload" * 20
        compressed = http.zstandard.ZstdCompressor().compress(raw)
        body, warnings = http.decompress_with_warnings(compressed, "zstd")
        assert body == raw
        assert warnings == []

    @pytest.mark.skipif(http.zstandard is None, reason="zstandard 미설치")
    def test_zstandard_without_content_size(self) -> None:
        raw = b"streamed zstandard payload" * 20
        compressor = http.zstandard.ZstdCompressor(write_content_size=False)
        compressed = compressor.compress(raw)
        body, warnings = http.decompress_with_warnings(compressed, "zstd")
        assert body == raw
        assert warnings == []

    @pytest.mark.parametrize("encoding", ["dcb", "dcz", "br-d", "zstd-d"])
    def test_dictionary_encoding_requires_dictionary(self, encoding: str) -> None:
        raw = b"dictionary-compressed"
        body, warnings = http.decompress_with_warnings(raw, encoding)
        assert body == raw
        assert warnings == [f"{encoding} decompression requires an external dictionary"]

    def test_unknown_encoding_records_warning(self) -> None:
        body, warnings = http.decompress_with_warnings(b"payload", "weird-thing")
        assert body == b"payload"
        assert warnings == ["unsupported content encoding: weird-thing"]


class TestContentDisposition:
    def test_quoted_filename(self) -> None:
        out = http.parse_content_disposition('attachment; filename="watermarked_img_123.png"')
        assert out["filename"] == "watermarked_img_123.png"

    def test_rfc5987_filename_star(self) -> None:
        out = http.parse_content_disposition("attachment; filename*=UTF-8''na%C3%AFve.txt")
        assert out["filename"] == "naïve.txt"

    def test_inline_no_filename(self) -> None:
        assert http.parse_content_disposition("inline") == {}

    def test_none(self) -> None:
        assert http.parse_content_disposition(None) == {}


class TestExtensionForMime:
    @pytest.mark.parametrize(
        ("ct", "ext"),
        [
            ("image/png", ".png"),
            ("image/jpeg; charset=binary", ".jpg"),
            ("application/json", ".json"),
            ("audio/mpeg", ".mp3"),
            ("video/mp4", ".mp4"),
            ("application/octet-stream", ""),
            ("application/x-unknown", ""),
            (None, ""),
        ],
    )
    def test_cases(self, ct: str | None, ext: str) -> None:
        assert http.extension_for_mime(ct) == ext


class TestDecideFilename:
    def test_content_disposition_wins(self) -> None:
        name = http.decide_filename(
            url="https://x.com/api/blob?id=1",
            content_type="image/png",
            content_disposition='attachment; filename="report.png"',
            entry_hash=0x1234,
        )
        assert name == "report.png"

    def test_url_last_segment_with_extension(self) -> None:
        name = http.decide_filename(
            url="https://cdn.example.com/a/b/photo.jpg?v=2",
            content_type="image/jpeg",
            content_disposition=None,
            entry_hash=0x1234,
        )
        assert name == "photo.jpg"

    def test_segment_plus_mime_extension(self) -> None:
        name = http.decide_filename(
            url="https://api.example.com/v2/voices",
            content_type="application/json",
            content_disposition=None,
            entry_hash=0x1234,
        )
        assert name == "voices.json"

    def test_hash_fallback(self) -> None:
        name = http.decide_filename(
            url="https://example.com/",
            content_type="application/octet-stream",
            content_disposition=None,
            entry_hash=0xDEADBEEF,
        )
        assert name == "deadbeef"

    def test_path_separators_stripped(self) -> None:
        name = http.decide_filename(
            url="https://x.com/f",
            content_type=None,
            content_disposition='attachment; filename="../../etc/passwd"',
            entry_hash=1,
        )
        assert "/" not in name and "\\" not in name

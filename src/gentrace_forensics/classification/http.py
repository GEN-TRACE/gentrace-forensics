"""HTTP 헤더 파싱, 압축 해제, 논리적 파일명 결정.

압축 해제: gzip / deflate(zlib) / Brotli / Zstandard (Content-Encoding 기준).
파일명 결정 순서 (ChromeCacheView 와 동일):
  1. Content-Disposition 의 filename
  2. URL 마지막 경로 세그먼트
  3. URL 경로 + MIME 기반 확장자
  4. 없으면 엔트리 해시 기반 이름
"""

from __future__ import annotations

import gzip
import io
import re
import zlib
from email.message import Message
from urllib.parse import unquote, urlsplit

try:  # brotli 는 필수 의존성이지만 방어적으로
    import brotli
except ImportError:  # pragma: no cover
    brotli = None  # type: ignore[assignment]

try:  # zstandard 는 필수 의존성이지만 방어적으로
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None  # type: ignore[assignment]

_DECOMPRESS_ERRORS: tuple[type[BaseException], ...] = (EOFError, OSError, zlib.error)
if brotli is not None:  # pragma: no branch
    _DECOMPRESS_ERRORS = (*_DECOMPRESS_ERRORS, brotli.error)
if zstandard is not None:  # pragma: no branch
    _DECOMPRESS_ERRORS = (*_DECOMPRESS_ERRORS, zstandard.ZstdError)

_DICTIONARY_ENCODINGS = {"dcb", "dcz", "br-d", "zstd-d"}

_MIME_EXT: dict[str, str] = {
    "text/html": ".html",
    "text/plain": ".txt",
    "text/css": ".css",
    "text/javascript": ".js",
    "application/javascript": ".js",
    "application/json": ".json",
    "application/pdf": ".pdf",
    "application/octet-stream": "",
    "application/zip": ".zip",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "image/svg+xml": ".svg",
    "audio/mpeg": ".mp3",
    "audio/mp4": ".m4a",
    "audio/wav": ".wav",
    "audio/ogg": ".ogg",
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "font/woff2": ".woff2",
    "font/woff": ".woff",
}

_UNSAFE_NAME = re.compile(r'[\x00-\x1f/\\:*?"<>|]+')


def decompress(body: bytes, content_encoding: str | None) -> bytes:
    """Content-Encoding 에 따라 본문 해제. 알 수 없거나 실패하면 원본 그대로 반환.

    쉼표로 겹친 인코딩(`gzip, br`)은 오른쪽→왼쪽 순서로 적용한다.
    """
    return decompress_with_warnings(body, content_encoding)[0]


def decompress_with_warnings(body: bytes, content_encoding: str | None) -> tuple[bytes, list[str]]:
    """본문을 해제하고 원문 반환이 필요한 이유를 경고로 함께 돌려준다.

    `dcb`/`dcz` 는 응답 외부의 공유 사전이 반드시 필요하므로 임의로 해제하지 않는다.
    알 수 없는 인코딩과 손상된 압축 데이터도 원문을 보존하되 경고를 남긴다.
    """
    if not body or not content_encoding:
        return body, []

    warnings: list[str] = []
    tokens = [t.strip().lower() for t in content_encoding.split(",") if t.strip()]
    for token in reversed(tokens):
        body, warning = _decompress_one(body, token)
        if warning:
            warnings.append(warning)
    return body, warnings


def _decompress_one(body: bytes, encoding: str) -> tuple[bytes, str | None]:
    if encoding == "identity":
        return body, None
    if encoding in _DICTIONARY_ENCODINGS:
        return body, f"{encoding} decompression requires an external dictionary"

    try:
        if encoding in ("gzip", "x-gzip"):
            return gzip.decompress(body), None
        if encoding == "deflate":
            try:
                return zlib.decompress(body), None
            except zlib.error:
                # 헤더 없는 raw deflate
                return zlib.decompress(body, -zlib.MAX_WBITS), None
        if encoding == "br":
            if brotli is None:
                return body, "br decompression unavailable: brotli is not installed"
            return brotli.decompress(body), None
        if encoding == "zstd":
            if zstandard is None:
                return body, "zstd decompression unavailable: zstandard is not installed"
            # Chrome 캐시는 프레임 헤더에 원본 크기가 없는 zstd 응답도 저장한다.
            # one-shot decompress() 대신 스트리밍 API 를 써서 두 형식을 모두 처리한다.
            with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(body)) as reader:
                return reader.read(), None
    except _DECOMPRESS_ERRORS as exc:
        return body, f"{encoding} decompression failed: {type(exc).__name__}"
    return body, f"unsupported content encoding: {encoding}"


def parse_content_disposition(value: str | None) -> dict[str, str]:
    """`attachment; filename="x.png"; filename*=UTF-8''x.png` → {'filename': 'x.png', ...}."""
    if not value:
        return {}
    msg = Message()
    msg["content-disposition"] = value
    out: dict[str, str] = {}
    filename = msg.get_filename()
    if filename:
        out["filename"] = filename
    for key, val in msg.get_params(failobj=[], header="content-disposition"):
        if key and val and key.lower() not in ("filename", "filename*"):
            out[key.lower()] = val
    return out


def extension_for_mime(content_type: str | None) -> str:
    """`image/png; charset=…` → `.png`. 모르면 빈 문자열."""
    if not content_type:
        return ""
    base = content_type.split(";", 1)[0].strip().lower()
    return _MIME_EXT.get(base, "")


def _sanitize(name: str) -> str:
    name = _UNSAFE_NAME.sub("_", name).strip(". ")
    return name[:255] or "unnamed"


def decide_filename(
    *,
    url: str,
    content_type: str | None,
    content_disposition: str | None,
    entry_hash: int,
) -> str:
    """위 4단계 규칙으로 논리적 파일명 결정."""
    disposition = parse_content_disposition(content_disposition)
    if disposition.get("filename"):
        return _sanitize(disposition["filename"])

    path = urlsplit(url).path
    segment = unquote(path.rsplit("/", 1)[-1]) if path else ""
    if segment and "." in segment:
        return _sanitize(segment)

    ext = extension_for_mime(content_type)
    if segment:
        return _sanitize(segment + ext)

    slug = _sanitize(path.strip("/").replace("/", "_")) if path.strip("/") else ""
    if slug and slug != "unnamed":
        return slug + ext
    return f"{entry_hash & 0xFFFFFFFF:08x}{ext}"

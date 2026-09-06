"""HTTP 헤더 파싱, 압축 해제, 논리적 파일명 결정.

압축 해제: gzip / deflate(zlib) / Brotli (Content-Encoding 기준).
파일명 결정 순서 (ChromeCacheView 와 동일):
  1. Content-Disposition 의 filename
  2. URL 마지막 경로 세그먼트
  3. URL 경로 + MIME 기반 확장자
  4. 없으면 엔트리 해시 기반 이름
"""

from __future__ import annotations

import gzip
import re
import zlib
from email.message import Message
from urllib.parse import unquote, urlsplit

try:  # brotli 는 필수 의존성이지만 방어적으로
    import brotli
except ImportError:  # pragma: no cover
    brotli = None  # type: ignore[assignment]

_DECOMPRESS_ERRORS: tuple[type[BaseException], ...] = (EOFError, OSError, zlib.error)
if brotli is not None:  # pragma: no branch
    _DECOMPRESS_ERRORS = (*_DECOMPRESS_ERRORS, brotli.error)

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
    if not body or not content_encoding:
        return body
    tokens = [t.strip().lower() for t in content_encoding.split(",") if t.strip()]
    for token in reversed(tokens):
        body = _decompress_one(body, token)
    return body


def _decompress_one(body: bytes, encoding: str) -> bytes:
    try:
        if encoding in ("gzip", "x-gzip"):
            return gzip.decompress(body)
        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)  # 헤더 없는 raw deflate
        if encoding == "br":
            return body if brotli is None else brotli.decompress(body)
    except _DECOMPRESS_ERRORS:
        return body
    return body  # identity / 알 수 없는 인코딩


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

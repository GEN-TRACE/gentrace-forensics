"""HTTP 헤더 파싱, 압축 해제, 논리적 파일명 결정.

압축 해제: gzip / zlib(deflate) / Brotli (Content-Encoding 기준).
파일명 결정 순서 (ChromeCacheView 와 동일):
  1. Content-Disposition 의 filename
  2. URL 마지막 경로 세그먼트
  3. URL 경로 + MIME 기반 확장자
  4. 없으면 엔트리 해시 기반 이름
"""

from __future__ import annotations


def decompress(body: bytes, content_encoding: str | None) -> bytes:
    """Content-Encoding 에 따라 본문 해제. 알 수 없는 인코딩이면 그대로 반환."""
    raise NotImplementedError


def parse_content_disposition(value: str | None) -> dict[str, str]:
    """`attachment; filename="x.png"; filename*=UTF-8''x.png` → {'filename': ...}."""
    raise NotImplementedError


def extension_for_mime(content_type: str | None) -> str:
    """`image/png` → `.png`. 모르면 빈 문자열."""
    raise NotImplementedError


def decide_filename(
    *,
    url: str,
    content_type: str | None,
    content_disposition: str | None,
    entry_hash: int,
) -> str:
    """위 4단계 규칙으로 논리적 파일명 결정."""
    raise NotImplementedError

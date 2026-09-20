"""URL 정규화 — tldextract 기반 도메인·경로.

- registrable domain / subdomain 추출
- 인코딩된 경로 디코딩 (Claude generated file 등)
"""

from __future__ import annotations

from urllib.parse import unquote, urlsplit

import tldextract

# 네트워크로 Public Suffix List를 갱신하지 않고 패키지에 번들된 snapshot만 사용한다.
_EXTRACT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def _split(url: str):
    value = url.strip()
    if "://" not in value and not value.startswith("//"):
        value = f"//{value}"
    return urlsplit(value)


def full_host(url: str) -> str:
    """URL의 호스트명만 소문자로 반환. 포트/사용자정보는 제외한다."""
    host = _split(url).hostname
    return (host or "").rstrip(".").lower()


def domain_of(url: str) -> str:
    """`https://a.b.example.com/x` → `example.com` (registrable domain)."""
    host = full_host(url)
    if not host:
        return ""

    extracted = _EXTRACT(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()

    # localhost, IP 주소, 사설/비표준 suffix 등은 host를 그대로 보존한다.
    return host


def decode_path(url: str) -> str:
    """퍼센트 인코딩된 경로를 사람이 읽는 형태로."""
    return unquote(_split(url).path)


def last_segment(url: str) -> str:
    """URL 경로의 마지막 비어있지 않은 세그먼트를 percent-decoding하여 반환."""
    path = decode_path(url).rstrip("/")
    if not path:
        return ""
    return path.rsplit("/", 1)[-1]

"""URL 정규화 — tldextract 기반 도메인·경로.

- registrable domain / subdomain 추출
- 쿼리 파라미터 정렬·불필요 파라미터 제거(선택)
- 인코딩된 경로 디코딩 (Claude generated file 등)
"""

from __future__ import annotations


def domain_of(url: str) -> str:
    """`https://a.b.example.com/x` → `example.com` (registrable domain)."""
    raise NotImplementedError


def full_host(url: str) -> str:
    raise NotImplementedError


def decode_path(url: str) -> str:
    """퍼센트 인코딩된 경로를 사람이 읽는 형태로. 예: `/mnt/user-data/outputs/...`."""
    raise NotImplementedError


def last_segment(url: str) -> str:
    raise NotImplementedError

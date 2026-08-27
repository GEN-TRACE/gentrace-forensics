"""E01 이미지 열기.

libewf-python(pyewf)로 분할 이미지(E01, E02, E03...)를 하나의 스트림으로 연다.
pytsk3가 소비할 수 있는 Img_Info 호환 핸들을 제공한다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def glob_segments(first_segment: str | Path) -> list[Path]:
    """E01 첫 세그먼트 경로에서 E0*/Ex* 전체 세그먼트 목록을 순서대로 반환."""
    raise NotImplementedError


def open_ewf(first_segment: str | Path) -> Any:
    """pyewf handle을 연다. (pytsk3.Img_Info 호환 래퍼 반환)"""
    raise NotImplementedError


def image_sha256(first_segment: str | Path) -> str:
    """전체 이미지(모든 세그먼트)의 SHA-256. 대용량이면 생략 가능(None 허용)."""
    raise NotImplementedError

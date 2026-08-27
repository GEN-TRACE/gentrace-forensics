"""Cache_Data 추출 + 해시.

index, data_*, f_* 전부를 원래 디렉터리 구조 그대로 추출하고
파일별 NTFS 시간정보 / inode / 크기 / SHA-256 을 기록한다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from gentrace_forensics.acquisition.filesystem import ProfileLocation
from gentrace_forensics.schemas.acquisition import AcquiredCache, AcquiredFile


def extract_file(fs: Any, image_inner_path: str, dest: Path) -> AcquiredFile:
    """단일 파일을 dest 로 추출하고 provenance 를 채운 AcquiredFile 반환."""
    raise NotImplementedError


def extract_cache(
    img: Any,
    fs: Any,
    profile: ProfileLocation,
    out_dir: Path,
    *,
    image_path: str,
    image_sha256: str | None = None,
    chrome_version: str | None = None,
) -> AcquiredCache:
    """한 프로필의 Cache_Data 전체를 추출해 AcquiredCache 로 반환."""
    raise NotImplementedError

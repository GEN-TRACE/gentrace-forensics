"""파티션 · NTFS · Chrome 프로필 탐색.

GPT/MBR 파티션 순회 → Windows NTFS 파티션 식별 → 오프셋 계산 →
`Users/<name>/AppData/Local/Google/Chrome/User Data/<profile>/Cache/Cache_Data`
경로 패턴으로 직접 접근. 전체 NTFS 재귀 탐색은 하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Partition:
    offset: int  # 바이트 오프셋
    length: int
    description: str
    is_ntfs: bool


@dataclass
class ProfileLocation:
    windows_user: str
    chrome_profile: str  # Default, Profile 2, Guest Profile
    cache_data_path: str  # 이미지 내부 절대 경로
    fs_offset: int


def list_partitions(img: Any) -> list[Partition]:
    """pytsk3.Volume_Info로 파티션 목록 반환."""
    raise NotImplementedError


def open_fs(img: Any, offset: int) -> Any:
    """pytsk3.FS_Info 반환."""
    raise NotImplementedError


def find_chrome_profiles(fs: Any, fs_offset: int) -> list[ProfileLocation]:
    """알려진 경로 패턴으로 Cache_Data 를 가진 프로필만 찾는다.

    `/Users/*/AppData/Local/Google/Chrome/User Data/` 아래
    Default / Profile * / Guest Profile 의 Cache/Cache_Data 존재 확인.
    """
    raise NotImplementedError


def read_chrome_version(fs: Any, profile: ProfileLocation) -> str | None:
    """가능하면 'Last Version' 파일 또는 설치 경로에서 Chrome 버전 추출."""
    raise NotImplementedError

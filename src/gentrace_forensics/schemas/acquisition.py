"""획득 → 분류 데이터 계약.

예은(획득) 단계가 산출하고 지민(분류) 단계가 소비한다.
CONTRIBUTING.md 4.1 절 참조. 필드 변경은 셋이 합의 후에만.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field


class AcquiredFile(BaseModel):
    """E01에서 추출한 개별 Cache_Data 파일 하나."""

    relative_path: str = Field(
        description="Cache_Data 기준 상대 경로 (index, data_1, f_00001a ...)"
    )
    local_path: Path = Field(description="추출된 파일의 로컬 경로")
    size: int
    sha256: str
    ntfs_inode: int | None = None
    created: datetime | None = Field(default=None, description="NTFS $STANDARD_INFORMATION, UTC")
    modified: datetime | None = None
    accessed: datetime | None = None


class AcquiredCache(BaseModel):
    """한 Chrome 프로필의 Cache_Data 디렉터리 전체와 그 출처(provenance)."""

    image_path: str = Field(description="E01 경로")
    image_sha256: str | None = None
    partition_offset: int
    windows_user: str = Field(description="Users/<name>")
    chrome_profile: str = Field(description="Default, Profile 2 ...")
    source_path: str = Field(description="이미지 내부 Cache_Data 절대 경로")
    chrome_version: str | None = None
    files: list[AcquiredFile] = Field(default_factory=list)

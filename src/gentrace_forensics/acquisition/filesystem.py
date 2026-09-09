"""파티션 · NTFS · Chrome 프로필 탐색.

GPT/MBR 파티션 순회 → Windows NTFS 파티션 식별 → 오프셋 계산 →
`Users/<name>/AppData/Local/Google/Chrome/User Data/<profile>/Cache/Cache_Data`
경로 패턴으로 직접 접근. 전체 NTFS 재귀 탐색은 하지 않는다.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any


class FilesystemDiscoveryError(RuntimeError):
    """파티션 테이블 또는 NTFS 파일시스템을 안전하게 열 수 없을 때 발생한다."""


@dataclass(frozen=True, slots=True)
class Partition:
    offset: int  # 바이트 오프셋
    length: int
    description: str
    is_ntfs: bool


@dataclass(frozen=True, slots=True)
class ProfileLocation:
    windows_user: str
    chrome_profile: str  # Default, Profile 2, Guest Profile
    cache_data_path: str  # 이미지 내부 절대 경로
    fs_offset: int


def _load_pytsk3() -> Any:
    """획득 optional 의존성을 파일시스템 사용 시점에 불러온다."""
    try:
        return importlib.import_module("pytsk3")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            'E01 filesystem discovery requires pytsk3; install with ".[acquisition]"'
        ) from exc


def _description(value: Any) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    return text.rstrip("\x00").strip() or "Unnamed partition"


def _is_ntfs(fs: Any, pytsk3: Any) -> bool:
    fs_type = getattr(getattr(fs, "info", None), "ftype", None)
    ntfs_types = [
        getattr(pytsk3, name, None) for name in ("TSK_FS_TYPE_NTFS", "TSK_FS_TYPE_NTFS_DETECT")
    ]
    return any(ntfs_type is not None and fs_type == ntfs_type for ntfs_type in ntfs_types)


def _close_fs(fs: Any) -> None:
    exit_method = getattr(fs, "exit", None)
    if callable(exit_method):
        exit_method()


def _probe_ntfs(img: Any, offset: int, pytsk3: Any) -> bool:
    try:
        fs = pytsk3.FS_Info(img, offset=offset)
    except OSError:  # pytsk3는 손상·비지원 파일시스템을 OSError로 보고한다.
        return False

    try:
        return _is_ntfs(fs, pytsk3)
    finally:
        _close_fs(fs)


def _whole_image_partition(img: Any, pytsk3: Any) -> Partition | None:
    """파티션 테이블이 없는 단일 NTFS 이미지이면 offset 0 파티션으로 취급한다."""
    if not _probe_ntfs(img, 0, pytsk3):
        return None

    media_size = int(img.get_size())
    if media_size < 0:
        raise FilesystemDiscoveryError("image size must be non-negative")
    return Partition(
        offset=0,
        length=media_size,
        description="Whole image (no GPT/MBR partition table)",
        is_ntfs=True,
    )


def list_partitions(img: Any) -> list[Partition]:
    """할당된 GPT/MBR 파티션을 반환하고 NTFS 여부를 실제 FS로 검증한다.

    TSK 설명 문자열에 ``NTFS``가 포함됐는지만 보지 않고, 각 할당 파티션을
    ``FS_Info``로 열어 파일시스템 형식을 확인한다. 파티션 테이블이 없는
    단일 NTFS 이미지도 byte offset 0의 가상 파티션으로 지원한다.
    """
    pytsk3 = _load_pytsk3()
    try:
        volume = pytsk3.Volume_Info(img)
    except Exception as exc:
        whole_image = _whole_image_partition(img, pytsk3)
        if whole_image is not None:
            return [whole_image]
        raise FilesystemDiscoveryError(
            "unable to read a GPT/MBR partition table and no NTFS filesystem was found at "
            "byte offset 0"
        ) from exc

    block_size = int(getattr(getattr(volume, "info", None), "block_size", 0))
    if block_size <= 0:
        raise FilesystemDiscoveryError(f"invalid volume block size: {block_size}")

    allocated_flag = getattr(pytsk3, "TSK_VS_PART_FLAG_ALLOC", None)
    partitions: list[Partition] = []
    for entry in volume:
        if allocated_flag is not None:
            flags = int(getattr(entry, "flags", allocated_flag))
            if not (flags & int(allocated_flag)):
                continue

        start_block = int(entry.start)
        block_count = int(entry.len)
        if start_block < 0 or block_count <= 0:
            raise FilesystemDiscoveryError(
                f"invalid partition extent: start={start_block}, blocks={block_count}"
            )

        offset = start_block * block_size
        partitions.append(
            Partition(
                offset=offset,
                length=block_count * block_size,
                description=_description(getattr(entry, "desc", "")),
                is_ntfs=_probe_ntfs(img, offset, pytsk3),
            )
        )

    if partitions:
        return partitions

    whole_image = _whole_image_partition(img, pytsk3)
    if whole_image is not None:
        return [whole_image]
    raise FilesystemDiscoveryError("no allocated partitions or NTFS filesystem were found")


def open_fs(img: Any, offset: int) -> Any:
    """byte offset의 NTFS를 열어 ``pytsk3.FS_Info``로 반환한다.

    반환된 객체의 수명은 호출자가 관리한다. 더 이상 사용하지 않을 때
    객체가 제공하는 ``exit()``를 호출해야 한다.
    """
    if offset < 0:
        raise ValueError("filesystem offset must be non-negative")

    pytsk3 = _load_pytsk3()
    try:
        fs = pytsk3.FS_Info(img, offset=offset)
    except Exception as exc:
        raise FilesystemDiscoveryError(
            f"unable to open filesystem at byte offset {offset}"
        ) from exc

    if not _is_ntfs(fs, pytsk3):
        _close_fs(fs)
        raise FilesystemDiscoveryError(f"filesystem at byte offset {offset} is not NTFS")
    return fs


def find_chrome_profiles(fs: Any, fs_offset: int) -> list[ProfileLocation]:
    """알려진 경로 패턴으로 Cache_Data 를 가진 프로필만 찾는다.

    `/Users/*/AppData/Local/Google/Chrome/User Data/` 아래
    Default / Profile * / Guest Profile 의 Cache/Cache_Data 존재 확인.
    """
    raise NotImplementedError


def read_chrome_version(fs: Any, profile: ProfileLocation) -> str | None:
    """가능하면 'Last Version' 파일 또는 설치 경로에서 Chrome 버전 추출."""
    raise NotImplementedError

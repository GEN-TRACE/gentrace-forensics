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


def _probe_ntfs(img: Any, offset: int, pytsk3: Any) -> bool:
    try:
        fs = pytsk3.FS_Info(img, offset=offset)
    except OSError:  # pytsk3는 손상·비지원 파일시스템을 OSError로 보고한다.
        return False

    # pytsk3.FS_Info.exit()는 호스트 인터프리터를 종료하던 과거 동작 때문에
    # 의도적으로 비활성화되어 있다. 지역 참조가 해제될 때 네이티브 객체의
    # 수명도 Python 바인딩에 맡긴다.
    return _is_ntfs(fs, pytsk3)


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

    ``FS_Info.exit()``는 호출하지 않는다. 반환된 객체의 참조 수명에 따라
    Python 바인딩이 네이티브 자원을 정리한다.
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
        raise FilesystemDiscoveryError(f"filesystem at byte offset {offset} is not NTFS")
    return fs


def find_chrome_profiles(fs: Any, fs_offset: int) -> list[ProfileLocation]:
    """알려진 경로 패턴으로 Cache_Data 를 가진 프로필만 찾는다.

    `/Users/*/AppData/Local/Google/Chrome/User Data/` 아래
    Default / Profile * / Guest Profile 의 Cache/Cache_Data 존재 확인.
    """
    if fs_offset < 0:
        raise ValueError("filesystem offset must be non-negative")

    profiles: list[ProfileLocation] = []
    for windows_user in _directory_names(fs, "/Users"):
        user_data_path = f"/Users/{windows_user}/AppData/Local/Google/Chrome/User Data"
        if not _is_directory(fs, user_data_path):
            continue

        for chrome_profile in _directory_names(fs, user_data_path):
            if not _is_chrome_profile_name(chrome_profile):
                continue
            cache_data_path = f"{user_data_path}/{chrome_profile}/Cache/Cache_Data"
            if not _is_directory(fs, cache_data_path):
                continue
            profiles.append(
                ProfileLocation(
                    windows_user=windows_user,
                    chrome_profile=chrome_profile,
                    cache_data_path=cache_data_path,
                    fs_offset=fs_offset,
                )
            )

    return sorted(
        profiles,
        key=lambda profile: (
            profile.windows_user.casefold(),
            _profile_sort_key(profile.chrome_profile),
        ),
    )


def read_chrome_version(fs: Any, profile: ProfileLocation) -> str | None:
    """가능하면 'Last Version' 파일 또는 설치 경로에서 Chrome 버전 추출."""
    user_data_path = f"/Users/{profile.windows_user}/AppData/Local/Google/Chrome/User Data"
    last_version = _read_small_text_file(fs, f"{user_data_path}/Last Version")
    if last_version is not None and _parse_version(last_version) is not None:
        return last_version

    application_paths = [
        f"/Users/{profile.windows_user}/AppData/Local/Google/Chrome/Application",
        "/Program Files/Google/Chrome/Application",
        "/Program Files (x86)/Google/Chrome/Application",
    ]
    installed_versions: list[tuple[str, tuple[int, ...]]] = []
    for application_path in application_paths:
        for candidate in _directory_names(fs, application_path):
            version_key = _parse_version(candidate)
            if version_key is None:
                continue
            if _is_file(fs, f"{application_path}/{candidate}/chrome.exe"):
                installed_versions.append((candidate, version_key))

    if not installed_versions:
        return None
    return max(installed_versions, key=lambda item: item[1])[0]


_MAX_VERSION_FILE_SIZE = 256


def _decode_name(value: Any) -> str | None:
    if isinstance(value, bytes):
        decoded = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        decoded = value
    else:
        return None
    if not decoded or decoded in {".", "..", "$OrphanFiles"}:
        return None
    if "/" in decoded or "\x00" in decoded:
        return None
    return decoded


def _directory_names(fs: Any, path: str) -> list[str]:
    """디렉터리의 직계 항목 이름만 반환한다. 하위 재귀 탐색은 하지 않는다."""
    try:
        directory = fs.open_dir(path=path)
    except OSError:
        return []

    names: list[str] = []
    for entry in directory:
        name_info = getattr(getattr(entry, "info", None), "name", None)
        name = _decode_name(getattr(name_info, "name", None))
        if name is not None:
            names.append(name)
    return sorted(set(names), key=str.casefold)


def _is_directory(fs: Any, path: str) -> bool:
    try:
        fs.open_dir(path=path)
    except OSError:
        return False
    return True


def _is_file(fs: Any, path: str) -> bool:
    try:
        file_object = fs.open(path=path)
    except OSError:
        return False
    return getattr(getattr(file_object, "info", None), "meta", None) is not None


def _is_chrome_profile_name(name: str) -> bool:
    folded = name.casefold()
    return folded in {"default", "guest profile"} or _profile_number(name) is not None


def _profile_sort_key(name: str) -> tuple[int, int, str]:
    folded = name.casefold()
    if folded == "default":
        return (0, 0, folded)
    profile_number = _profile_number(name)
    if profile_number is not None:
        return (1, profile_number, folded)
    return (2, 0, folded)


def _profile_number(name: str) -> int | None:
    prefix = "profile "
    folded = name.casefold()
    if not folded.startswith(prefix):
        return None
    number = folded[len(prefix) :]
    if not number.isascii() or not number.isdigit() or number.startswith("0"):
        return None
    return int(number)


def _read_small_text_file(fs: Any, path: str) -> str | None:
    try:
        file_object = fs.open(path=path)
    except OSError:
        return None

    meta = getattr(getattr(file_object, "info", None), "meta", None)
    size = getattr(meta, "size", None)
    if not isinstance(size, int) or size < 1 or size > _MAX_VERSION_FILE_SIZE:
        return None

    try:
        content = file_object.read_random(0, size)
    except OSError:
        return None
    if not isinstance(content, bytes) or len(content) != size:
        return None

    try:
        return content.decode("utf-8-sig").strip().rstrip("\x00")
    except UnicodeDecodeError:
        return None


def _parse_version(version: str) -> tuple[int, ...] | None:
    parts = version.split(".")
    if not 2 <= len(parts) <= 5:
        return None
    if any(not part.isascii() or not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)

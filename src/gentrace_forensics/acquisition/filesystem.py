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

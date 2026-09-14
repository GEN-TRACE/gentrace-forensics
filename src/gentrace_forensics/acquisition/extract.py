"""Cache_Data 추출 + 해시.

index, data_*, f_* 전부를 원래 디렉터리 구조 그대로 추출하고
파일별 NTFS 시간정보 / inode / 크기 / SHA-256 을 기록한다.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from gentrace_forensics.acquisition.filesystem import ProfileLocation
from gentrace_forensics.schemas.acquisition import AcquiredCache, AcquiredFile

_CACHE_FILE = re.compile(r"^(?:index|data_[0-9]+|f_[0-9a-f]+)$", re.IGNORECASE)
_READ_CHUNK_SIZE = 1024 * 1024
_MANIFEST_NAME = "acquired.json"


def extract_file(fs: Any, image_inner_path: str, dest: Path) -> AcquiredFile:
    """단일 파일을 dest 로 추출하고 provenance 를 채운 AcquiredFile 반환."""
    source_path = _validated_image_path(image_inner_path)
    try:
        source = fs.open(path=source_path)
    except OSError as exc:
        raise OSError(f"unable to open image file: {source_path}") from exc

    meta = getattr(getattr(source, "info", None), "meta", None)
    size = getattr(meta, "size", None)
    if not isinstance(size, int) or size < 0:
        raise ValueError(f"invalid file size for {source_path}: {size!r}")

    destination = Path(dest).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    digest = hashlib.sha256()
    offset = 0
    try:
        with destination.open("xb") as output:
            created = True
            while offset < size:
                requested_size = min(_READ_CHUNK_SIZE, size - offset)
                chunk = source.read_random(offset, requested_size)
                if not isinstance(chunk, bytes) or not chunk:
                    raise OSError(
                        f"unexpected end of image file {source_path} at offset {offset} of {size}"
                    )
                if len(chunk) > requested_size:
                    raise OSError(
                        f"image file {source_path} returned {len(chunk)} bytes for a "
                        f"{requested_size}-byte read"
                    )
                output.write(chunk)
                digest.update(chunk)
                offset += len(chunk)
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise

    inode = getattr(meta, "addr", None)
    return AcquiredFile(
        relative_path=Path(source_path).name,
        local_path=destination.resolve(),
        size=size,
        sha256=digest.hexdigest(),
        ntfs_inode=inode if isinstance(inode, int) and inode >= 0 else None,
        created=_timestamp(meta, "crtime"),
        modified=_timestamp(meta, "mtime"),
        accessed=_timestamp(meta, "atime"),
    )


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
    """한 프로필의 Cache_Data와 프로필별 ``acquired.json``을 추출한다.

    출력은 ``partition_<offset>/Users/.../<profile>/`` 아래에 이미지 내부
    구조를 유지한다. 기존 프로필 출력은 덮어쓰지 않으며, 실패하면 이번
    호출이 새로 만든 프로필 출력만 제거한다.
    """
    del img  # 향후 sparse extent 등 이미지 직접 접근이 필요할 때를 위한 공개 API 인자
    _validate_profile(profile)
    destination_root = Path(out_dir).expanduser()
    profile_root = _profile_output_root(destination_root, profile)
    cache_root = profile_root / "Cache" / "Cache_Data"
    if profile_root.exists():
        raise FileExistsError(f"profile output already exists: {profile_root}")

    profile_root.mkdir(parents=True)
    try:
        names = _cache_file_names(fs, profile.cache_data_path)
        files = [
            extract_file(fs, f"{profile.cache_data_path}/{name}", cache_root / name)
            for name in names
        ]
        acquired = AcquiredCache(
            image_path=image_path,
            image_sha256=image_sha256,
            partition_offset=profile.fs_offset,
            windows_user=profile.windows_user,
            chrome_profile=profile.chrome_profile,
            source_path=profile.cache_data_path,
            chrome_version=chrome_version,
            files=files,
        )
        output_manifest = profile_root / _MANIFEST_NAME
        with output_manifest.open("x", encoding="utf-8", newline="\n") as manifest:
            manifest.write(acquired.model_dump_json(indent=2))
            manifest.write("\n")
    except Exception:
        shutil.rmtree(profile_root)
        raise

    return acquired


def manifest_path(out_dir: str | Path, profile: ProfileLocation) -> Path:
    """프로필별 ``AcquiredCache`` JSON의 예상 출력 경로를 반환한다."""
    _validate_profile(profile)
    return _profile_output_root(Path(out_dir).expanduser(), profile) / _MANIFEST_NAME


def _validated_image_path(path: str) -> str:
    if not path.startswith("/") or "\x00" in path or "\\" in path:
        raise ValueError(f"image path must be an absolute POSIX path: {path!r}")
    parts = path.split("/")[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"image path contains an unsafe component: {path!r}")
    return "/" + "/".join(parts)


def _validate_component(value: str, label: str) -> None:
    if not value or value in {".", ".."} or any(character in value for character in "/\\\x00"):
        raise ValueError(f"invalid {label}: {value!r}")


def _validate_profile(profile: ProfileLocation) -> None:
    if profile.fs_offset < 0:
        raise ValueError("filesystem offset must be non-negative")
    _validate_component(profile.windows_user, "Windows user")
    _validate_component(profile.chrome_profile, "Chrome profile")
    expected = (
        f"/Users/{profile.windows_user}/AppData/Local/Google/Chrome/User Data/"
        f"{profile.chrome_profile}/Cache/Cache_Data"
    )
    if profile.cache_data_path != expected:
        raise ValueError(
            f"Cache_Data path does not match profile provenance: {profile.cache_data_path!r}"
        )


def _profile_output_root(out_dir: Path, profile: ProfileLocation) -> Path:
    return (
        out_dir
        / f"partition_{profile.fs_offset}"
        / "Users"
        / profile.windows_user
        / "AppData"
        / "Local"
        / "Google"
        / "Chrome"
        / "User Data"
        / profile.chrome_profile
    )


def _decode_name(value: Any) -> str | None:
    if isinstance(value, bytes):
        name = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        name = value
    else:
        return None
    if "/" in name or "\\" in name or "\x00" in name:
        return None
    return name


def _cache_sort_key(name: str) -> tuple[int, int, str]:
    folded = name.casefold()
    if folded == "index":
        return (0, 0, folded)
    if folded.startswith("data_"):
        return (1, int(folded.removeprefix("data_")), folded)
    return (2, int(folded.removeprefix("f_"), 16), folded)


def _cache_file_names(fs: Any, cache_data_path: str) -> list[str]:
    try:
        directory = fs.open_dir(path=cache_data_path)
    except OSError as exc:
        raise OSError(f"unable to open Cache_Data directory: {cache_data_path}") from exc

    names: dict[str, str] = {}
    for entry in directory:
        name_info = getattr(getattr(entry, "info", None), "name", None)
        name = _decode_name(getattr(name_info, "name", None))
        if name is None or _CACHE_FILE.fullmatch(name) is None:
            continue
        folded = name.casefold()
        if folded in names:
            raise ValueError(f"duplicate Cache_Data filename: {names[folded]!r} and {name!r}")
        names[folded] = name
    return sorted(names.values(), key=_cache_sort_key)


def _timestamp(meta: Any, field: str) -> datetime | None:
    seconds = getattr(meta, field, None)
    if not isinstance(seconds, int) or seconds <= 0:
        return None

    nanoseconds = getattr(meta, f"{field}_nano", 0)
    if not isinstance(nanoseconds, int) or not 0 <= nanoseconds < 1_000_000_000:
        nanoseconds = 0
    try:
        return datetime.fromtimestamp(seconds, tz=UTC) + timedelta(
            microseconds=nanoseconds // 1_000
        )
    except (OSError, OverflowError, ValueError):
        return None

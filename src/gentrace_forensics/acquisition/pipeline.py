"""E01의 NTFS·Chrome 프로필을 획득 모듈에 연결한다."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from gentrace_forensics.acquisition.extract import extract_cache, manifest_path
from gentrace_forensics.acquisition.filesystem import (
    ProfileLocation,
    find_chrome_profiles,
    list_partitions,
    open_fs,
    read_chrome_version,
)
from gentrace_forensics.acquisition.image import image_sha256, open_ewf
from gentrace_forensics.reporting import write_report


def acquire_image(
    image_path: Path,
    out_dir: Path,
    *,
    progress: Callable[[str], None] | None = None,
) -> list[Path]:
    """새 출력 폴더에 프로필별 acquired.json을 만들고 절대 경로 목록을 반환한다.

    이미지 해시는 논리 디스크에 대해 한 번만 계산한다. 실패 시 이번 호출이 만든
    출력 폴더만 정리한다. 완성된 매니페스트 목록은 acquisition.json에 기록한다.
    """
    image_path = Path(image_path).expanduser().resolve()
    out_dir = Path(out_dir).expanduser().resolve()
    if out_dir.exists():
        raise FileExistsError(f"acquisition output already exists: {out_dir}")
    emit = progress or (lambda message: None)

    with closing(open_ewf(image_path)) as img:
        targets: list[tuple[int, list[tuple[ProfileLocation, str | None]]]] = []
        emit("discovering NTFS partitions and Chrome profiles")
        for partition in list_partitions(img):
            if not partition.is_ntfs:
                continue
            fs = open_fs(img, partition.offset)
            try:
                profiles = [
                    (profile, read_chrome_version(fs, profile))
                    for profile in find_chrome_profiles(fs, partition.offset)
                ]
                if profiles:
                    targets.append((partition.offset, profiles))
            finally:
                del fs
        if not targets:
            raise ValueError("no Chrome Cache_Data profiles found in NTFS filesystems")

        out_dir.mkdir(parents=True, exist_ok=False)
        try:
            last_bucket = -1

            def hash_progress(done: int, total: int) -> None:
                nonlocal last_bucket
                bucket = (done * 100 // total if total else 100) // 10
                if bucket != last_bucket:
                    emit(f"hashing logical image: {bucket * 10}% ({done}/{total} bytes)")
                    last_bucket = bucket

            digest = image_sha256(img, progress=hash_progress)
            manifests: list[Path] = []
            for offset, profiles in targets:
                fs = open_fs(img, offset)
                try:
                    for profile, version in profiles:
                        emit(f"extracting {profile.windows_user}/{profile.chrome_profile}")
                        extract_cache(
                            img,
                            fs,
                            profile,
                            out_dir,
                            image_path=str(image_path),
                            image_sha256=digest,
                            chrome_version=version,
                        )
                        manifests.append(manifest_path(out_dir, profile))
                finally:
                    del fs
            write_report(
                out_dir / "acquisition.json",
                {
                    "status": "complete",
                    "image_path": str(image_path),
                    "image_sha256": digest,
                    "image_hash_scope": "logical_media",
                    "profile_count": len(manifests),
                    "manifests": [str(path) for path in manifests],
                },
            )
        except BaseException:
            shutil.rmtree(out_dir)
            raise
    return manifests

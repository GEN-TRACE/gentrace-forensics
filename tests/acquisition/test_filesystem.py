"""GPT/MBR 파티션 및 NTFS 파일시스템 탐색 테스트."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from gentrace_forensics.acquisition.filesystem import (
    FilesystemDiscoveryError,
    Partition,
    list_partitions,
    open_fs,
)


@dataclass
class _FakeImage:
    size: int = 4_096_000

    def get_size(self) -> int:
        return self.size


class _FakeFs:
    def __init__(self, fs_type: int) -> None:
        self.info = SimpleNamespace(ftype=fs_type)
        self.exited = False

    def exit(self) -> None:
        self.exited = True


def _install_fake_pytsk3(
    monkeypatch: pytest.MonkeyPatch,
    *,
    partitions: list[Any] | None = None,
    filesystems: dict[int, int | Exception] | None = None,
    volume_error: Exception | None = None,
    block_size: int = 512,
) -> list[_FakeFs]:
    pytsk3 = ModuleType("pytsk3")
    pytsk3.TSK_VS_PART_FLAG_ALLOC = 1  # type: ignore[attr-defined]
    pytsk3.TSK_VS_PART_FLAG_UNALLOC = 2  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_NTFS = 10  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_NTFS_DETECT = 11  # type: ignore[attr-defined]
    pytsk3.TSK_FS_TYPE_EXT4 = 20  # type: ignore[attr-defined]

    class FakeVolumeInfo:
        def __init__(self, img: Any) -> None:
            del img
            if volume_error is not None:
                raise volume_error
            self.info = SimpleNamespace(block_size=block_size)

        def __iter__(self):
            return iter(partitions or [])

    opened_filesystems: list[_FakeFs] = []

    def fake_fs_info(img: Any, *, offset: int) -> _FakeFs:
        del img
        result = (filesystems or {}).get(offset, OSError("no filesystem"))
        if isinstance(result, Exception):
            raise result
        fs = _FakeFs(result)
        opened_filesystems.append(fs)
        return fs

    pytsk3.Volume_Info = FakeVolumeInfo  # type: ignore[attr-defined]
    pytsk3.FS_Info = fake_fs_info  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pytsk3", pytsk3)
    return opened_filesystems


def _partition(*, start: int, length: int, description: bytes, flags: int) -> Any:
    return SimpleNamespace(start=start, len=length, desc=description, flags=flags)


def test_list_partitions_returns_allocated_entries_and_probes_ntfs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        _partition(start=0, length=1, description=b"Primary Table", flags=2),
        _partition(start=2_048, length=200, description=b"EFI System", flags=1),
        _partition(start=4_096, length=1_000, description=b"Basic data partition", flags=1),
    ]
    opened = _install_fake_pytsk3(
        monkeypatch,
        partitions=entries,
        filesystems={2_048 * 512: 20, 4_096 * 512: 10},
    )

    actual = list_partitions(_FakeImage())

    assert actual == [
        Partition(
            offset=2_048 * 512,
            length=200 * 512,
            description="EFI System",
            is_ntfs=False,
        ),
        Partition(
            offset=4_096 * 512,
            length=1_000 * 512,
            description="Basic data partition",
            is_ntfs=True,
        ),
    ]
    assert all(fs.exited for fs in opened)


def test_list_partitions_supports_ntfs_without_partition_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = _FakeImage(size=123_456)
    opened = _install_fake_pytsk3(
        monkeypatch,
        volume_error=OSError("volume system not found"),
        filesystems={0: 11},
    )

    assert list_partitions(image) == [
        Partition(
            offset=0,
            length=123_456,
            description="Whole image (no GPT/MBR partition table)",
            is_ntfs=True,
        )
    ]
    assert opened[0].exited is True


def test_list_partitions_rejects_image_without_partition_table_or_ntfs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_pytsk3(
        monkeypatch,
        volume_error=OSError("volume system not found"),
        filesystems={0: OSError("filesystem not found")},
    )

    with pytest.raises(FilesystemDiscoveryError, match="no NTFS filesystem"):
        list_partitions(_FakeImage())


def test_list_partitions_rejects_invalid_volume_block_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_pytsk3(monkeypatch, partitions=[], block_size=0)

    with pytest.raises(FilesystemDiscoveryError, match="block size"):
        list_partitions(_FakeImage())


def test_list_partitions_rejects_invalid_allocated_extent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_pytsk3(
        monkeypatch,
        partitions=[_partition(start=-1, length=5, description=b"damaged", flags=1)],
    )

    with pytest.raises(FilesystemDiscoveryError, match="invalid partition extent"):
        list_partitions(_FakeImage())


def test_open_fs_returns_ntfs_and_leaves_lifetime_to_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = _install_fake_pytsk3(monkeypatch, filesystems={1_048_576: 10})

    fs = open_fs(_FakeImage(), 1_048_576)

    assert fs is opened[0]
    assert fs.exited is False


def test_open_fs_closes_and_rejects_non_ntfs(monkeypatch: pytest.MonkeyPatch) -> None:
    opened = _install_fake_pytsk3(monkeypatch, filesystems={512: 20})

    with pytest.raises(FilesystemDiscoveryError, match="is not NTFS"):
        open_fs(_FakeImage(), 512)

    assert opened[0].exited is True


def test_open_fs_wraps_native_open_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_pytsk3(monkeypatch, filesystems={512: OSError("damaged boot sector")})

    with pytest.raises(FilesystemDiscoveryError, match="byte offset 512"):
        open_fs(_FakeImage(), 512)


def test_open_fs_rejects_negative_offset() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        open_fs(_FakeImage(), -1)


def test_filesystem_discovery_reports_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(sys.modules, "pytsk3", raising=False)

    def missing_module(name: str) -> Any:
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(
        "gentrace_forensics.acquisition.filesystem.importlib.import_module", missing_module
    )

    with pytest.raises(RuntimeError, match=r"\.\[acquisition\]"):
        list_partitions(_FakeImage())

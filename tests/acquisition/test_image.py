"""분할 EWF 이미지 탐색·열기 테스트."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from gentrace_forensics.acquisition.image import glob_segments, image_sha256, open_ewf


def _write_segments(directory: Path, contents: list[bytes]) -> list[Path]:
    segments = []
    for index, content in enumerate(contents, start=1):
        segment = directory / f"disk.E{index:02d}"
        segment.write_bytes(content)
        segments.append(segment)
    return segments


def test_glob_segments_returns_numeric_segments_in_order(tmp_path: Path) -> None:
    segments = _write_segments(tmp_path, [b"one", b"two", b"three"])
    (tmp_path / "disk.txt").write_text("ignore", encoding="utf-8")

    assert glob_segments(tmp_path / "disk.E01") == segments


def test_glob_segments_matches_extension_case_insensitively(tmp_path: Path) -> None:
    first = tmp_path / "Disk.e01"
    second = tmp_path / "Disk.E02"
    first.write_bytes(b"one")
    second.write_bytes(b"two")

    assert glob_segments(tmp_path / "disk.E01") == [first, second]


def test_glob_segments_continues_from_e99_to_eaa(tmp_path: Path) -> None:
    numeric_segments = []
    for index in range(1, 100):
        segment = tmp_path / f"disk.E{index:02d}"
        segment.write_bytes(b"")
        numeric_segments.append(segment)
    alphabetic_segment = tmp_path / "disk.EAA"
    alphabetic_segment.write_bytes(b"")

    assert glob_segments(tmp_path / "disk.E01") == [*numeric_segments, alphabetic_segment]


def test_glob_segments_rejects_missing_intermediate_segment(tmp_path: Path) -> None:
    (tmp_path / "disk.E01").write_bytes(b"one")
    (tmp_path / "disk.E03").write_bytes(b"three")

    with pytest.raises(ValueError, match="missing segment number"):
        glob_segments(tmp_path / "disk.E01")


def test_glob_segments_requires_first_segment(tmp_path: Path) -> None:
    (tmp_path / "disk.E02").write_bytes(b"two")

    with pytest.raises(FileNotFoundError, match="first EWF segment"):
        glob_segments(tmp_path / "disk.E01")


def test_glob_segments_rejects_non_e01_input(tmp_path: Path) -> None:
    segment = tmp_path / "disk.E02"
    segment.write_bytes(b"two")

    with pytest.raises(ValueError, match=r"\.E01"):
        glob_segments(segment)


class _FakeEwfHandle:
    def __init__(self, data: bytes, *, fail_open: bool = False) -> None:
        self.data = data
        self.fail_open = fail_open
        self.offset = 0
        self.opened_paths: list[str] = []
        self.closed = False

    def open(self, paths: list[str]) -> None:
        self.opened_paths = paths
        if self.fail_open:
            raise OSError("damaged EWF")

    def seek(self, offset: int) -> None:
        self.offset = offset

    def read(self, size: int) -> bytes:
        chunk = self.data[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def get_media_size(self) -> int:
        return len(self.data)

    def close(self) -> None:
        self.closed = True


def _install_fake_native_modules(monkeypatch: pytest.MonkeyPatch, handle: _FakeEwfHandle) -> None:
    pyewf = ModuleType("pyewf")
    pyewf.handle = lambda: handle  # type: ignore[attr-defined]

    class FakeImgInfo:
        def __init__(self, *, url: str, type: int) -> None:
            self.url = url
            self.image_type = type

    pytsk3 = ModuleType("pytsk3")
    pytsk3.Img_Info = FakeImgInfo  # type: ignore[attr-defined]
    pytsk3.TSK_IMG_TYPE_EXTERNAL = 1  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "pyewf", pyewf)
    monkeypatch.setitem(sys.modules, "pytsk3", pytsk3)


def test_open_ewf_returns_pytsk3_compatible_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    segments = _write_segments(tmp_path, [b"container-one", b"container-two"])
    handle = _FakeEwfHandle(b"logical media bytes")
    _install_fake_native_modules(monkeypatch, handle)

    image: Any = open_ewf(segments[0])

    assert handle.opened_paths == [str(segment) for segment in segments]
    assert image.get_size() == len(handle.data)
    assert image.read(8, 5) == b"media"
    image.close()
    assert handle.closed is True
    with pytest.raises(ValueError, match="closed"):
        image.get_size()


def test_open_ewf_rejects_negative_read_ranges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    segment = _write_segments(tmp_path, [b"container"])[0]
    handle = _FakeEwfHandle(b"logical media")
    _install_fake_native_modules(monkeypatch, handle)

    with open_ewf(segment) as image:
        with pytest.raises(ValueError, match="non-negative"):
            image.read(-1, 1)
        with pytest.raises(ValueError, match="non-negative"):
            image.read(0, -1)


def test_image_sha256_hashes_logical_media_not_container_segments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    segments = _write_segments(tmp_path, [b"compressed-container-one", b"container-two"])
    logical_media = b"decompressed logical disk bytes"
    handle = _FakeEwfHandle(logical_media)
    _install_fake_native_modules(monkeypatch, handle)

    with open_ewf(segments[0]) as image:
        actual = image_sha256(image)

    assert actual == hashlib.sha256(logical_media).hexdigest()
    assert (
        actual != hashlib.sha256(b"".join(segment.read_bytes() for segment in segments)).hexdigest()
    )
    assert handle.closed is True


def test_image_sha256_rejects_truncated_logical_media() -> None:
    class TruncatedImage:
        def get_size(self) -> int:
            return 10

        def read(self, offset: int, size: int) -> bytes:
            return b"abc" if offset == 0 else b""

    with pytest.raises(OSError, match="unexpected end"):
        image_sha256(TruncatedImage())


def test_open_ewf_context_manager_closes_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    segment = _write_segments(tmp_path, [b"container"])[0]
    handle = _FakeEwfHandle(b"logical media")
    _install_fake_native_modules(monkeypatch, handle)

    with open_ewf(segment) as image:
        assert image.read(0, 7) == b"logical"

    assert handle.closed is True


def test_open_ewf_closes_handle_when_open_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    segment = _write_segments(tmp_path, [b"container"])[0]
    handle = _FakeEwfHandle(b"", fail_open=True)
    _install_fake_native_modules(monkeypatch, handle)

    with pytest.raises(OSError, match="damaged EWF"):
        open_ewf(segment)

    assert handle.closed is True

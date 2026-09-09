"""Cache_Data 원본 추출과 provenance manifest 테스트."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from gentrace_forensics.acquisition.extract import extract_cache, extract_file, manifest_path
from gentrace_forensics.acquisition.filesystem import ProfileLocation
from gentrace_forensics.schemas.acquisition import AcquiredCache


class _FakeFile:
    def __init__(
        self,
        content: bytes,
        *,
        inode: int = 42,
        size: int | None = None,
        max_chunk: int | None = None,
        fail_at: int | None = None,
    ) -> None:
        self.content = content
        self.max_chunk = max_chunk
        self.fail_at = fail_at
        self.info = SimpleNamespace(
            meta=SimpleNamespace(
                size=len(content) if size is None else size,
                addr=inode,
                crtime=1_700_000_000,
                crtime_nano=123_456_789,
                mtime=1_700_000_100,
                mtime_nano=0,
                atime=0,
                atime_nano=0,
            )
        )

    def read_random(self, offset: int, size: int) -> bytes:
        if self.fail_at is not None and offset >= self.fail_at:
            raise OSError("damaged extent")
        if self.max_chunk is not None:
            size = min(size, self.max_chunk)
        return self.content[offset : offset + size]


class _FakeEntry:
    def __init__(self, name: bytes | str | None) -> None:
        self.info = SimpleNamespace(name=SimpleNamespace(name=name))


class _FakeFs:
    def __init__(self, *, names: list[bytes | str | None], files: dict[str, _FakeFile]) -> None:
        self.names = names
        self.files = files

    def open_dir(self, *, path: str):
        if path != _CACHE_PATH:
            raise OSError("directory not found")
        return [_FakeEntry(name) for name in self.names]

    def open(self, *, path: str) -> _FakeFile:
        if path not in self.files:
            raise OSError("file not found")
        return self.files[path]


_CACHE_PATH = "/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data"
_PROFILE = ProfileLocation(
    windows_user="Alice",
    chrome_profile="Default",
    cache_data_path=_CACHE_PATH,
    fs_offset=1_048_576,
)


def _file_path(name: str) -> str:
    return f"{_CACHE_PATH}/{name}"


def test_extract_file_streams_content_and_records_provenance(tmp_path: Path) -> None:
    content = b"abcdefghijk"
    fs = _FakeFs(
        names=[],
        files={_file_path("data_0"): _FakeFile(content, max_chunk=3)},
    )
    destination = tmp_path / "data_0"

    acquired = extract_file(fs, _file_path("data_0"), destination)

    assert destination.read_bytes() == content
    assert acquired.relative_path == "data_0"
    assert acquired.local_path == destination.resolve()
    assert acquired.size == len(content)
    assert acquired.sha256 == hashlib.sha256(content).hexdigest()
    assert acquired.ntfs_inode == 42
    assert acquired.created == datetime.fromtimestamp(1_700_000_000, tz=UTC).replace(
        microsecond=123_456
    )
    assert acquired.modified == datetime.fromtimestamp(1_700_000_100, tz=UTC)
    assert acquired.accessed is None


def test_extract_file_supports_empty_file(tmp_path: Path) -> None:
    fs = _FakeFs(names=[], files={_file_path("index"): _FakeFile(b"")})

    acquired = extract_file(fs, _file_path("index"), tmp_path / "index")

    assert acquired.size == 0
    assert acquired.sha256 == hashlib.sha256(b"").hexdigest()
    assert (tmp_path / "index").read_bytes() == b""


def test_extract_file_removes_partial_output_on_read_failure(tmp_path: Path) -> None:
    destination = tmp_path / "f_000001"
    fs = _FakeFs(
        names=[],
        files={_file_path("f_000001"): _FakeFile(b"abcdef", max_chunk=3, fail_at=3)},
    )

    with pytest.raises(OSError, match="damaged extent"):
        extract_file(fs, _file_path("f_000001"), destination)

    assert not destination.exists()


def test_extract_file_rejects_truncated_source_and_removes_output(tmp_path: Path) -> None:
    destination = tmp_path / "data_1"
    fs = _FakeFs(names=[], files={_file_path("data_1"): _FakeFile(b"abc", size=10)})

    with pytest.raises(OSError, match="unexpected end"):
        extract_file(fs, _file_path("data_1"), destination)

    assert not destination.exists()


def test_extract_file_never_overwrites_existing_output(tmp_path: Path) -> None:
    destination = tmp_path / "index"
    destination.write_bytes(b"existing evidence")
    fs = _FakeFs(names=[], files={_file_path("index"): _FakeFile(b"new")})

    with pytest.raises(FileExistsError):
        extract_file(fs, _file_path("index"), destination)

    assert destination.read_bytes() == b"existing evidence"


def test_extract_cache_filters_orders_and_writes_per_profile_manifest(tmp_path: Path) -> None:
    files = {
        _file_path("index"): _FakeFile(b"index"),
        _file_path("data_0"): _FakeFile(b"data"),
        _file_path("data_10"): _FakeFile(b"ten"),
        _file_path("f_00000a"): _FakeFile(b"external"),
    }
    fs = _FakeFs(
        names=[
            b"f_00000a",
            b"data_10",
            b"index",
            b"data_0",
            b"index-dir",
            b"random.tmp",
            b".",
            None,
        ],
        files=files,
    )

    acquired = extract_cache(
        object(),
        fs,
        _PROFILE,
        tmp_path,
        image_path="evidence.E01",
        image_sha256="a" * 64,
        chrome_version="140.0.7339.81",
    )

    assert [item.relative_path for item in acquired.files] == [
        "index",
        "data_0",
        "data_10",
        "f_00000a",
    ]
    assert acquired.partition_offset == 1_048_576
    assert acquired.windows_user == "Alice"
    assert acquired.chrome_profile == "Default"
    assert acquired.source_path == _CACHE_PATH
    assert acquired.chrome_version == "140.0.7339.81"
    for item in acquired.files:
        assert item.local_path.read_bytes() == files[_file_path(item.relative_path)].content

    output_manifest = manifest_path(tmp_path, _PROFILE)
    saved = AcquiredCache.model_validate_json(output_manifest.read_text(encoding="utf-8"))
    assert saved == acquired
    assert output_manifest.name == "acquired.json"
    assert "partition_1048576" in output_manifest.parts


def test_extract_cache_writes_empty_profile_manifest(tmp_path: Path) -> None:
    fs = _FakeFs(names=[b"random.tmp"], files={})

    acquired = extract_cache(object(), fs, _PROFILE, tmp_path, image_path="empty.E01")

    assert acquired.files == []
    assert (
        AcquiredCache.model_validate_json(
            manifest_path(tmp_path, _PROFILE).read_text(encoding="utf-8")
        )
        == acquired
    )


def test_extract_cache_refuses_existing_profile_output(tmp_path: Path) -> None:
    output_manifest = manifest_path(tmp_path, _PROFILE)
    output_manifest.parent.mkdir(parents=True)
    output_manifest.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError, match="already exists"):
        extract_cache(object(), _FakeFs(names=[], files={}), _PROFILE, tmp_path, image_path="x.E01")

    assert output_manifest.read_text(encoding="utf-8") == "keep"


def test_extract_cache_cleans_new_profile_output_when_a_file_fails(tmp_path: Path) -> None:
    fs = _FakeFs(
        names=[b"index", b"data_0"],
        files={
            _file_path("index"): _FakeFile(b"ok"),
            _file_path("data_0"): _FakeFile(b"bad", size=20),
        },
    )

    with pytest.raises(OSError, match="unexpected end"):
        extract_cache(object(), fs, _PROFILE, tmp_path, image_path="x.E01")

    assert not manifest_path(tmp_path, _PROFILE).parent.exists()


@pytest.mark.parametrize(
    "profile",
    [
        ProfileLocation("..", "Default", _CACHE_PATH, 0),
        ProfileLocation("Alice", "../Default", _CACHE_PATH, 0),
        ProfileLocation("Alice", "Default", "/Users/Alice/other", 0),
        ProfileLocation("Alice", "Default", _CACHE_PATH, -1),
    ],
)
def test_extract_cache_rejects_unsafe_or_inconsistent_profile(
    tmp_path: Path, profile: ProfileLocation
) -> None:
    with pytest.raises(ValueError):
        extract_cache(object(), _FakeFs(names=[], files={}), profile, tmp_path, image_path="x.E01")

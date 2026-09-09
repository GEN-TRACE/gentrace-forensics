"""Windows 사용자별 Chrome 프로필 및 버전 탐색 테스트."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from gentrace_forensics.acquisition.filesystem import (
    ProfileLocation,
    find_chrome_profiles,
    read_chrome_version,
)


@dataclass
class _FakeEntry:
    name: bytes

    @property
    def info(self):
        return SimpleNamespace(name=SimpleNamespace(name=self.name))


class _FakeFile:
    def __init__(self, content: bytes, *, reported_size: int | None = None) -> None:
        self._content = content
        self.info = SimpleNamespace(
            meta=SimpleNamespace(size=len(content) if reported_size is None else reported_size)
        )

    def read_random(self, offset: int, size: int) -> bytes:
        return self._content[offset : offset + size]


class _FakeFs:
    def __init__(
        self,
        *,
        directories: dict[str, list[bytes]] | None = None,
        files: dict[str, _FakeFile] | None = None,
    ) -> None:
        self.directories = directories or {}
        self.files = files or {}
        self.opened_directories: list[str] = []

    def open_dir(self, *, path: str):
        self.opened_directories.append(path)
        if path not in self.directories:
            raise OSError("directory not found")
        return [_FakeEntry(name) for name in self.directories[path]]

    def open(self, *, path: str) -> _FakeFile:
        if path not in self.files:
            raise OSError("file not found")
        return self.files[path]


def _cache_path(user: str, profile: str) -> str:
    return f"/Users/{user}/AppData/Local/Google/Chrome/User Data/{profile}/Cache/Cache_Data"


def test_find_chrome_profiles_discovers_all_users_and_supported_profiles() -> None:
    alice_data = "/Users/Alice/AppData/Local/Google/Chrome/User Data"
    bob_data = "/Users/bob/AppData/Local/Google/Chrome/User Data"
    directories = {
        "/Users": [b"bob", b"Alice", b"Public", b"$OrphanFiles", b".", b".."],
        alice_data: [b"Profile 10", b"Default", b"Profile 2", b"System Profile"],
        bob_data: [b"Guest Profile", b"Profile Work", b"Default"],
        _cache_path("Alice", "Default"): [],
        _cache_path("Alice", "Profile 2"): [],
        _cache_path("Alice", "Profile 10"): [],
        _cache_path("bob", "Guest Profile"): [],
    }
    fs = _FakeFs(directories=directories)

    actual = find_chrome_profiles(fs, fs_offset=1_048_576)

    assert actual == [
        ProfileLocation("Alice", "Default", _cache_path("Alice", "Default"), 1_048_576),
        ProfileLocation("Alice", "Profile 2", _cache_path("Alice", "Profile 2"), 1_048_576),
        ProfileLocation("Alice", "Profile 10", _cache_path("Alice", "Profile 10"), 1_048_576),
        ProfileLocation("bob", "Guest Profile", _cache_path("bob", "Guest Profile"), 1_048_576),
    ]
    assert "/Users/Public/AppData/Local/Google/Chrome/User Data" in fs.opened_directories
    assert _cache_path("bob", "Default") in fs.opened_directories


def test_find_chrome_profiles_returns_empty_when_users_directory_is_missing() -> None:
    assert find_chrome_profiles(_FakeFs(), fs_offset=0) == []


def test_find_chrome_profiles_rejects_negative_filesystem_offset() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        find_chrome_profiles(_FakeFs(), fs_offset=-1)


def test_read_chrome_version_prefers_valid_last_version_file() -> None:
    user_data = "/Users/Alice/AppData/Local/Google/Chrome/User Data"
    fs = _FakeFs(files={f"{user_data}/Last Version": _FakeFile(b"140.0.7339.81\n")})
    profile = ProfileLocation("Alice", "Default", _cache_path("Alice", "Default"), 0)

    assert read_chrome_version(fs, profile) == "140.0.7339.81"


def test_read_chrome_version_uses_highest_verified_installation_directory() -> None:
    user_application = "/Users/Alice/AppData/Local/Google/Chrome/Application"
    machine_application = "/Program Files/Google/Chrome/Application"
    directories = {
        user_application: [b"139.0.1.2", b"not-a-version"],
        machine_application: [b"140.0.7339.80", b"141.0.1.1"],
    }
    files = {
        f"{user_application}/139.0.1.2/chrome.exe": _FakeFile(b"binary"),
        f"{machine_application}/140.0.7339.80/chrome.exe": _FakeFile(b"binary"),
        # 141 디렉터리는 남아 있지만 chrome.exe가 없으므로 설치 버전으로 보지 않는다.
    }
    fs = _FakeFs(directories=directories, files=files)
    profile = ProfileLocation("Alice", "Profile 2", _cache_path("Alice", "Profile 2"), 0)

    assert read_chrome_version(fs, profile) == "140.0.7339.80"


@pytest.mark.parametrize(
    "last_version",
    [
        _FakeFile(b"not-a-version"),
        _FakeFile(b"140.0", reported_size=300),
        _FakeFile(b"140.0", reported_size=20),
        _FakeFile(b"\xff\xfe\xfd"),
    ],
)
def test_read_chrome_version_rejects_invalid_last_version(last_version: _FakeFile) -> None:
    user_data = "/Users/Alice/AppData/Local/Google/Chrome/User Data"
    fs = _FakeFs(files={f"{user_data}/Last Version": last_version})
    profile = ProfileLocation("Alice", "Default", _cache_path("Alice", "Default"), 0)

    assert read_chrome_version(fs, profile) is None


def test_read_chrome_version_returns_none_when_no_source_exists() -> None:
    profile = ProfileLocation("Alice", "Default", _cache_path("Alice", "Default"), 0)

    assert read_chrome_version(_FakeFs(), profile) is None

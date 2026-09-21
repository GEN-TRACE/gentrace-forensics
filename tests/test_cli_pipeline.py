"""네이티브 이미지/파일시스템 경계만 대체한 CLI 전체 실행 회귀 테스트."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
from contextlib import closing
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from gentrace_forensics import cli
from gentrace_forensics.acquisition.filesystem import Partition
from gentrace_forensics.classification.blockfile.structs import (
    BLOCK_HEADER_SIZE,
    INDEX_HEADER_TOTAL_SIZE,
)
from gentrace_forensics.schemas.acquisition import AcquiredCache
from gentrace_forensics.schemas.classification import ClassifiedEntry
from gentrace_forensics.schemas.normalization import NormalizedArtifact


def _blockfile(body: bytes) -> dict[str, bytes]:
    """HTTP 응답 한 건을 담은 합성 Blockfile 캐시를 구성한다."""
    key = b"1/0/https://claude.ai/api/chat-1/files/file-1"
    headers = b"HTTP/1.1 200 OK\x00Content-Type: image/webp\x00\x00"
    metadata = struct.pack("<IqqI", 0, 13_344_473_601_000_000, 13_344_473_602_000_000, len(headers))
    metadata += headers + bytes(-len(headers) % 4)
    metadata = struct.pack("<I", len(metadata)) + metadata

    index = bytearray(INDEX_HEADER_TOTAL_SIZE + 65_536 * 4)
    struct.pack_into("<IIi", index, 0, 0xC103CAC3, 0x30000, 1)
    struct.pack_into("<i", index, 28, 65_536)
    struct.pack_into("<I", index, INDEX_HEADER_TOTAL_SIZE, 0xA0010000)
    entry = bytearray(256)
    struct.pack_into("<I", entry, 0, 1)
    struct.pack_into("<Qi", entry, 24, 13_344_473_600_000_000, len(key))
    struct.pack_into("<4i", entry, 40, len(metadata), len(body), 0, 0)
    struct.pack_into("<4I", entry, 56, 0x80000010, 0x80000011, 0, 0)
    entry[96 : 96 + len(key)] = key
    files = {"index": bytes(index), "f_000010": metadata, "f_000011": body}
    for number, size in enumerate((36, 256, 1024, 4096)):
        header = bytearray(BLOCK_HEADER_SIZE)
        struct.pack_into(
            "<IIhhiii", header, 0, 0xC104CAC3, 0x20000, number, 0, size, int(number == 1), 1024
        )
        files[f"data_{number}"] = bytes(header) + (bytes(entry) if number == 1 else b"")
    return files


class _Image:
    data = b"logical media" * 100_000

    def __init__(self):
        self.closed = False
        self.read_offsets: list[int] = []

    def get_size(self):
        return len(self.data)

    def read(self, offset, size):
        self.read_offsets.append(offset)
        return self.data[offset : offset + size]

    def close(self):
        self.closed = True


class _Fs:
    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.fail_on: str | None = None
        self.user_data = "/Users/alice/AppData/Local/Google/Chrome/User Data"
        self.files[f"{self.user_data}/Last Version"] = b"140.0.7339.81"
        for number, profile in enumerate(("Default", "Profile 1"), 1):
            for name, data in _blockfile(f"profile-{number}".encode()).items():
                self.files[f"{self.user_data}/{profile}/Cache/Cache_Data/{name}"] = data

    def open_dir(self, *, path):
        prefix = path.rstrip("/") + "/"
        names = sorted(
            {key[len(prefix) :].split("/", 1)[0] for key in self.files if key.startswith(prefix)}
        )
        if not names:
            raise OSError("directory not found")
        return [
            SimpleNamespace(info=SimpleNamespace(name=SimpleNamespace(name=name.encode())))
            for name in names
        ]

    def open(self, *, path):
        if path not in self.files:
            raise OSError("file not found")
        data = self.files[path]

        def read(offset, size):
            if path == self.fail_on:
                raise OSError("fixture read failure")
            return data[offset : offset + size]

        return SimpleNamespace(
            info=SimpleNamespace(meta=SimpleNamespace(size=len(data), addr=42)),
            read_random=read,
        )


@pytest.fixture
def native_boundary(monkeypatch):
    image, fs = _Image(), _Fs()
    monkeypatch.setattr("gentrace_forensics.acquisition.pipeline.open_ewf", lambda _: image)
    monkeypatch.setattr(
        "gentrace_forensics.acquisition.pipeline.list_partitions",
        lambda _: [
            Partition(0, 512, "EFI", False),
            Partition(1_048_576, len(image.data), "NTFS", True),
        ],
    )

    def open_fs(img, offset):
        assert img is image and offset == 1_048_576
        return fs

    monkeypatch.setattr("gentrace_forensics.acquisition.pipeline.open_fs", open_fs)
    return image, fs


def _check_results(out: Path):
    classified_path = out / "classified" / "classified.jsonl"
    entries = [
        ClassifiedEntry.model_validate_json(line)
        for line in classified_path.read_bytes().splitlines()
    ]
    normalized_path = out / "normalized" / "normalized.jsonl"
    records = [
        NormalizedArtifact.model_validate_json(line)
        for line in normalized_path.read_bytes().splitlines()
    ]
    assert len(entries) == len(records) == 2
    assert {entry.source_cache.chrome_profile for entry in entries} == {"Default", "Profile 1"}
    assert len({record.source_id for record in records}) == 2
    for entry, record in zip(entries, records, strict=True):
        assert entry.body_path and entry.body_path.is_file()
        assert record.sha256 == hashlib.sha256(entry.body_path.read_bytes()).hexdigest()
        provenance = json.loads(record.source_id)
        source = next(
            file for file in entry.source_cache.files if file.relative_path == entry.source_file
        )
        assert (
            provenance["source_file_sha256"]
            == hashlib.sha256(source.local_path.read_bytes()).hexdigest()
        )
        assert record.timestamp and record.timestamp.isoformat() == "2023-11-14T22:13:22+00:00"
        assert record.service == "claude" and record.artifact_kind == "other"
    with closing(sqlite3.connect(out / "normalized" / "normalized.db")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 2
    normalization = json.loads((out / "normalized" / "normalization.json").read_text())
    assert (
        normalization["classified_sha256"]
        == hashlib.sha256(classified_path.read_bytes()).hexdigest()
    )


def test_run_connects_all_stages_with_real_blockfile_parser(tmp_path, native_boundary, capsys):
    image, _ = native_boundary
    out = tmp_path / "run"
    assert cli.main(["run", "--image", str(tmp_path / "fixture.E01"), "--out", str(out)]) == 0
    _check_results(out)
    report = json.loads((out / "run.json").read_text())
    assert report["status"] == report["stage"] == "complete"
    assert report["classified_count"] == report["normalized_count"] == 2
    assert image.closed
    assert image.read_offsets.count(0) == 1  # 전체 디스크 해시는 프로필마다 반복하지 않는다.
    acquisition = json.loads((out / "acquired" / "acquisition.json").read_text())
    assert acquisition["image_sha256"] == hashlib.sha256(image.data).hexdigest()
    assert "100%" in capsys.readouterr().err


def test_each_command_can_run_independently(tmp_path, native_boundary, capsys):
    acquired = tmp_path / "acquired"
    assert cli.main(["acquire", "--image", "fixture.E01", "--out", str(acquired)]) == 0
    manifests = capsys.readouterr().out.splitlines()
    assert len(manifests) == 2
    for path in manifests:
        cache = AcquiredCache.model_validate_json(Path(path).read_bytes())
        assert cache.chrome_version == "140.0.7339.81"
    args = ["classify", "--out", str(tmp_path / "classified")]
    for path in manifests:
        args.extend(["--cache", path])
    assert cli.main(args) == 0
    assert (
        cli.main(
            [
                "normalize",
                "--entries",
                str(tmp_path / "classified" / "classified.jsonl"),
                "--out",
                str(tmp_path / "normalized"),
            ]
        )
        == 0
    )
    _check_results(tmp_path)


def test_acquire_without_profiles_closes_image_and_creates_no_output(tmp_path, native_boundary):
    image, fs = native_boundary
    fs.files.clear()
    out = tmp_path / "acquired"
    assert cli.main(["acquire", "--image", "fixture.E01", "--out", str(out)]) == 1
    assert image.closed and not out.exists()


def test_acquire_failure_removes_only_new_output(tmp_path, native_boundary):
    image, fs = native_boundary
    fs.fail_on = f"{fs.user_data}/Profile 1/Cache/Cache_Data/f_000011"
    out = tmp_path / "acquired"
    marker = tmp_path / "keep.txt"
    marker.write_text("keep")
    assert cli.main(["acquire", "--image", "fixture.E01", "--out", str(out)]) == 1
    assert image.closed and not out.exists()
    assert marker.read_text() == "keep"


def test_run_classification_failure_keeps_acquisition_and_reports_stage(tmp_path, native_boundary):
    _, fs = native_boundary
    fs.files = {
        name: body for name, body in fs.files.items() if PurePosixPath(name).name != "data_1"
    }
    out = tmp_path / "run"
    assert cli.main(["run", "--image", "fixture.E01", "--out", str(out)]) == 1
    report = json.loads((out / "run.json").read_text())
    assert report["status"] == "failed" and report["stage"] == "classify"
    assert len(report["manifests"]) == 2
    assert all(Path(path).is_file() for path in report["manifests"])
    assert not (out / "classified" / "classified.jsonl").exists()
    assert not (out / "normalized").exists()


def test_run_normalization_failure_keeps_classified_evidence(
    tmp_path, native_boundary, monkeypatch
):
    def fail(*args):
        raise ValueError("normalization failed")

    monkeypatch.setattr("gentrace_forensics.pipeline.normalize_entries", fail)
    out = tmp_path / "run"
    assert cli.main(["run", "--image", "fixture.E01", "--out", str(out)]) == 1
    report = json.loads((out / "run.json").read_text())
    assert report["status"] == "failed" and report["stage"] == "normalize"
    assert (out / "classified" / "classified.jsonl").is_file()
    assert len(list((out / "classified" / "bodies").rglob("*.bin"))) == 2


@pytest.mark.parametrize("command", ["acquire", "run"])
def test_existing_output_is_not_modified(tmp_path, native_boundary, command):
    out = tmp_path / "existing"
    out.mkdir()
    (out / "keep.txt").write_text("keep")
    assert cli.main([command, "--image", "fixture.E01", "--out", str(out)]) == 1
    assert [path.name for path in out.iterdir()] == ["keep.txt"]


def test_run_interruption_is_reported(tmp_path, monkeypatch):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("gentrace_forensics.pipeline.acquire_image", interrupt)
    out = tmp_path / "run"
    assert cli.main(["run", "--image", "fixture.E01", "--out", str(out)]) == 130
    report = json.loads((out / "run.json").read_text())
    assert report["status"] == "failed" and report["error"] == "KeyboardInterrupt"


def test_analyze_reuses_verified_acquisition_and_writes_review(tmp_path, native_boundary, capsys):
    out = tmp_path / "acquired"
    assert cli.main(["acquire", "--image", "fixture.E01", "--out", str(out)]) == 0
    manifests = capsys.readouterr().out.splitlines()
    args = ["analyze", "--out", str(tmp_path / "analysis")]
    for manifest in manifests:
        args += ["--cache", manifest]
    assert cli.main(args) == 0
    report = json.loads((tmp_path / "analysis" / "validation_summary.json").read_text())
    assert report["artifact_count"] == report["sqlite_artifact_count"] == 2
    assert report["validated_media_files"] == 0  # fixture bytes are not real WebP
    assert (tmp_path / "analysis" / "report" / "index.html").is_file()
    assert cli.main(args) == 1  # no overwrite


def test_network_only_profile_is_acquired_and_not_a_cache_event(tmp_path, native_boundary, capsys):
    image, fs = native_boundary
    fs.files = {
        f"{fs.user_data}/Default/Network/Network Persistent State": json.dumps(
            {
                "servers": [
                    {
                        "server": "https://chatgpt.com",
                        "alternative_service": [
                            {"protocol_str": "h3", "port": 443, "expiration": "13344473600000000"}
                        ],
                    }
                ]
            }
        ).encode()
    }
    out = tmp_path / "network-case"
    assert cli.main(["run", "--image", "fixture.E01", "--out", str(out)]) == 0
    summary = json.loads((out / "validation_summary.json").read_text())
    assert summary["cache_entry_count"] == summary["artifact_count"] == 0
    assert summary["network"][0]["status"] == "collected"
    network = json.loads((out / "network_records.jsonl").read_text())
    assert network["service"] == "chatgpt"
    assert next(iter(network["times"].values()))["meaning"] == "alternative_service_expiration"
    assert image.closed

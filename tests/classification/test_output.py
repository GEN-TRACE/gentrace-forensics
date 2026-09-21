"""여러 프로필의 분류 출력·본문·근거 보존과 실패 시 결과 보호."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gentrace_forensics import cli
from gentrace_forensics.classification.blockfile.parser import HttpResponseInfo, ParsedCacheEntry
from gentrace_forensics.classification.output import classify_manifests
from gentrace_forensics.schemas.acquisition import AcquiredCache
from gentrace_forensics.schemas.classification import ClassifiedEntry


def _manifest(root: Path, profile: str) -> Path:
    path = root / profile / "acquired.json"
    path.parent.mkdir(parents=True)
    cache = AcquiredCache(
        image_path="disk.E01",
        partition_offset=1_048_576,
        windows_user="alice",
        chrome_profile=profile,
        source_path=f"/Users/alice/AppData/Local/Google/Chrome/User Data/{profile}/Cache/Cache_Data",
    )
    path.write_text(cache.model_dump_json(), encoding="utf-8")
    return path


def _parsed(body: bytes) -> ParsedCacheEntry:
    return ParsedCacheEntry(
        cache_key="1/0/https://example.test/report",
        url="https://example.test/report",
        response=HttpResponseInfo(200, {"content-type": "application/octet-stream"}),
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        stored_body_size=len(body),
        content_encoding=None,
        source_file="f_000001",
        source_offset=0,
        entry_hash=1,
        entry_state="normal",
        warnings=["fixture warning"],
    )


def test_cli_combines_profiles_and_preserves_evidence_and_final_body_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifests = [_manifest(tmp_path, name) for name in ("Default", "Profile 1")]
    seen: list[Path] = []

    def parse(cache_dir: Path) -> list[ParsedCacheEntry]:
        seen.append(cache_dir)
        return [_parsed(f"profile {len(seen)}".encode())]

    monkeypatch.setattr("gentrace_forensics.classification.classify.parse_cache_dir", parse)
    out_dir = tmp_path / "out"
    assert (
        cli.main(
            [
                "classify",
                "--cache",
                str(manifests[0]),
                "--cache",
                str(manifests[1]),
                "--out",
                str(out_dir),
            ]
        )
        == 0
    )

    records = [
        ClassifiedEntry.model_validate_json(line)
        for line in (out_dir / "classified.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert seen == [path.parent / "Cache" / "Cache_Data" for path in manifests]
    assert [record.source_cache.chrome_profile for record in records] == ["Default", "Profile 1"]
    assert records[0].body_path != records[1].body_path
    for number, record in enumerate(records, 1):
        assert record.evidence["parse_warnings"] == ["fixture warning"]
        assert record.body_path and record.body_path.is_relative_to(out_dir / "bodies")
        assert record.body_path.read_bytes() == f"profile {number}".encode()
        assert hashlib.sha256(record.body_path.read_bytes()).hexdigest() == record.body_sha256
    assert not list(out_dir.glob(".classify-*"))


@pytest.mark.parametrize("existing_name", ["classified.jsonl", "bodies"])
def test_existing_output_is_preserved(tmp_path: Path, existing_name: str) -> None:
    manifest = _manifest(tmp_path, "Default")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    existing = out_dir / existing_name
    if existing_name == "bodies":
        existing.mkdir()
        existing = existing / "keep.bin"
    existing.write_bytes(b"keep")

    with pytest.raises(FileExistsError, match="already exists"):
        classify_manifests([manifest], out_dir)

    assert existing.read_bytes() == b"keep"
    assert not list(out_dir.glob(".classify-*"))


def test_later_profile_failure_does_not_publish_partial_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifests = [_manifest(tmp_path, name) for name in ("Default", "Profile 1")]

    def parse(cache_dir: Path) -> list[ParsedCacheEntry]:
        if "Profile 1" in cache_dir.parts:
            raise ValueError("unsupported cache format")
        return [_parsed(b"first profile")]

    monkeypatch.setattr("gentrace_forensics.classification.classify.parse_cache_dir", parse)
    out_dir = tmp_path / "out"
    with pytest.raises(ValueError, match="unsupported cache format"):
        classify_manifests(manifests, out_dir)

    assert not (out_dir / "classified.jsonl").exists()
    assert not (out_dir / "bodies").exists()
    assert not list(out_dir.glob(".classify-*"))


def test_publish_failure_removes_only_new_bodies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest(tmp_path, "Default")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    marker = out_dir / "unrelated.txt"
    marker.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(
        "gentrace_forensics.classification.classify.parse_cache_dir", lambda _: [_parsed(b"body")]
    )

    def fail_publish(*args):
        raise OSError("publish failed")

    monkeypatch.setattr("gentrace_forensics.classification.output.os.link", fail_publish)
    with pytest.raises(OSError, match="publish failed"):
        classify_manifests([manifest], out_dir)
    assert sorted(path.name for path in out_dir.iterdir()) == ["unrelated.txt"]
    assert marker.read_text(encoding="utf-8") == "keep"


def test_duplicate_manifest_rejected_before_output_is_created(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, "Default")
    out_dir = tmp_path / "out"
    with pytest.raises(ValueError, match="duplicate"):
        classify_manifests([manifest, manifest], out_dir)
    assert not out_dir.exists()


def test_jsonl_preserves_non_ascii_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest(tmp_path, "프로필")
    monkeypatch.setattr(
        "gentrace_forensics.classification.classify.parse_cache_dir", lambda _: [_parsed(b"body")]
    )
    out_dir = tmp_path / "out"
    assert classify_manifests([manifest], out_dir) == 1
    payload = json.loads((out_dir / "classified.jsonl").read_text(encoding="utf-8"))
    assert payload["source_cache"]["chrome_profile"] == "프로필"

"""`gentrace classify` CLI 배선 테스트.

실제 blockfile 파싱(`classify_cache`)은 monkeypatch 로 대체해, ccl/캐시
픽스처 없이도 인자 파싱·매니페스트 로딩·JSONL 출력만 검증한다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from gentrace_forensics import cli
from gentrace_forensics.schemas.acquisition import AcquiredCache
from gentrace_forensics.schemas.classification import ClassifiedEntry


def _write_manifest(path: Path) -> AcquiredCache:
    cache = AcquiredCache(
        image_path="/tmp/disk.E01",
        partition_offset=0,
        windows_user="alice",
        chrome_profile="Default",
        source_path="/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data",
    )
    path.write_text(cache.model_dump_json(), encoding="utf-8")
    return cache


def test_build_parser_routes_classify_args() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["classify", "--cache", "a.json", "--out", "outdir"])
    assert args.func is cli.cmd_classify
    assert args.cache == "a.json"
    assert args.out == "outdir"


def test_cmd_classify_writes_jsonl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest_path = tmp_path / "acquired.json"
    cache = _write_manifest(manifest_path)

    classified = [
        ClassifiedEntry(
            entry_id="abc123",
            cache_key="1/0/https://chatgpt.com/x",
            url="https://chatgpt.com/x",
            filename="x.json",
            size=3,
            source_file="data_1",
            source_cache=cache,
        )
    ]
    seen: dict[str, object] = {}

    def fake_classify_cache(
        cache_arg: AcquiredCache, cache_dir_arg: str | Path, *, body_dir: str | Path | None = None
    ) -> list[ClassifiedEntry]:
        seen["cache"] = cache_arg
        seen["cache_dir"] = Path(cache_dir_arg)
        seen["body_dir"] = Path(body_dir) if body_dir is not None else None
        return classified

    monkeypatch.setattr(
        "gentrace_forensics.classification.classify.classify_cache", fake_classify_cache
    )

    out_dir = tmp_path / "out"
    args = argparse.Namespace(cache=str(manifest_path), out=str(out_dir))
    assert cli.cmd_classify(args) == 0

    assert seen["cache"] == cache
    assert seen["cache_dir"] == manifest_path.parent / "Cache" / "Cache_Data"
    assert seen["body_dir"] == out_dir / "bodies"

    lines = (out_dir / "classified.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["entry_id"] == "abc123"
    assert record["url"] == "https://chatgpt.com/x"


def test_cmd_classify_no_entries_writes_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = tmp_path / "acquired.json"
    _write_manifest(manifest_path)

    monkeypatch.setattr(
        "gentrace_forensics.classification.classify.classify_cache",
        lambda *args, **kwargs: [],
    )

    out_dir = tmp_path / "out"
    args = argparse.Namespace(cache=str(manifest_path), out=str(out_dir))
    assert cli.cmd_classify(args) == 0
    assert (out_dir / "classified.jsonl").read_text(encoding="utf-8") == ""

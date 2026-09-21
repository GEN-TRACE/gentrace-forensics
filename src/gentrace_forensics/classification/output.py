"""프로필별 매니페스트를 분류하고 본문·근거를 하나의 결과 묶음으로 저장한다."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path

from gentrace_forensics.classification.classify import classify_cache
from gentrace_forensics.schemas.acquisition import AcquiredCache


def classify_manifests(manifests: Sequence[Path], out_dir: Path) -> int:
    """매니페스트 순서대로 분류 결과를 모은다. 기존 결과는 덮어쓰지 않는다.

    모든 프로필의 분류가 끝나야 최종 본문 폴더와 classified.jsonl을 공개한다.
    JSONL에는 분류 근거·경고·출처와 최종 본문 경로를 함께 보존한다.
    """
    if not manifests:
        raise ValueError("at least one acquired manifest is required")
    paths = [Path(path).resolve() for path in manifests]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate acquired manifest")
    inputs = [
        (path, AcquiredCache.model_validate_json(path.read_text(encoding="utf-8")))
        for path in paths
    ]

    out_dir = Path(out_dir).resolve()
    out_path = out_dir / "classified.jsonl"
    bodies = out_dir / "bodies"
    if out_path.exists() or bodies.exists():
        raise FileExistsError(f"classification output already exists: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    with tempfile.TemporaryDirectory(prefix=".classify-", dir=out_dir) as staging:
        stage = Path(staging)
        stage_bodies = stage / "bodies"
        stage_bodies.mkdir()
        stage_jsonl = stage / "classified.jsonl"
        with stage_jsonl.open("x", encoding="utf-8", newline="\n") as output:
            for path, cache in inputs:
                if not cache.files and (path.parent / "network_acquired.json").is_file():
                    continue
                entries = classify_cache(
                    cache, path.parent / "Cache" / "Cache_Data", body_dir=stage_bodies
                )
                for entry in entries:
                    if entry.body_path is not None:
                        entry = entry.model_copy(
                            update={"body_path": bodies / entry.body_path.relative_to(stage_bodies)}
                        )
                    output.write(entry.model_dump_json())
                    output.write("\n")
                    count += 1
            output.flush()
            os.fsync(output.fileno())

        # mkdir은 기존 본문 폴더를 보호한다. JSONL은 같은 파일시스템에서 hard link로
        # 완성본만 공개하며, 동시에 생긴 기존 결과도 덮어쓰지 않는다.
        bodies.mkdir()
        try:
            for profile_dir in stage_bodies.iterdir():
                profile_dir.rename(bodies / profile_dir.name)
            os.link(stage_jsonl, out_path)
        except Exception:
            shutil.rmtree(bodies)
            raise
    return count

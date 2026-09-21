"""분류 JSONL을 공통 스키마 JSONL·SQLite로 저장한다."""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from gentrace_forensics.normalization.store import write_jsonl, write_sqlite
from gentrace_forensics.normalization.transform import transform
from gentrace_forensics.reporting import write_report
from gentrace_forensics.schemas.classification import ClassifiedEntry
from gentrace_forensics.schemas.normalization import NormalizedArtifact


def normalize_entries(entries_path: Path, out_dir: Path) -> int:
    """원본 JSONL을 한 번 읽어 정규화한다. 실패 시 새 출력만 정리한다.

    두 저장 형식은 같은 정규화 결과를 사용한다. 입력 JSONL의 경로와 SHA-256을
    normalization.json에 남겨, 스키마에 담기지 않는 분류 근거와 본문을 연결한다.
    """
    entries_path = Path(entries_path).expanduser().resolve()
    out_dir = Path(out_dir).expanduser().resolve()
    if not entries_path.is_file():
        raise FileNotFoundError(f"classified JSONL not found: {entries_path}")
    out_dir.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256()

    def normalized() -> Iterator[NormalizedArtifact]:
        with entries_path.open("rb") as source:
            for line_number, line in enumerate(source, 1):
                digest.update(line)
                if not line.strip():
                    continue
                try:
                    entry = ClassifiedEntry.model_validate_json(line)
                    yield transform(entry)
                except (ValidationError, ValueError) as exc:
                    raise ValueError(
                        f"invalid classified entry at {entries_path}:{line_number}"
                    ) from exc

    jsonl_path = out_dir / "normalized.jsonl"
    db_path = out_dir / "normalized.db"
    try:
        count = write_jsonl(normalized(), jsonl_path)
        # 원본을 두 번 읽지 않고 검증·변환을 마친 동일한 스냅샷을 DB에도 쓴다.
        with jsonl_path.open("rb") as normalized_source:
            write_sqlite(
                (NormalizedArtifact.model_validate_json(line) for line in normalized_source),
                db_path,
            )
        with closing(sqlite3.connect(db_path)) as connection:
            row_count = connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        if row_count != count:
            raise ValueError(
                "duplicate normalized source_id; refusing inconsistent JSONL/SQLite output"
            )
        write_report(
            out_dir / "normalization.json",
            {
                "status": "complete",
                "classified_entries": str(entries_path),
                "classified_sha256": digest.hexdigest(),
                "record_count": count,
                "jsonl": str(jsonl_path),
                "sqlite": str(db_path),
            },
        )
    except BaseException:
        shutil.rmtree(out_dir)
        raise
    return count

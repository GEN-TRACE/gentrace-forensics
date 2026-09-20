"""E01 → 획득 → 분류 → 정규화 전체 실행."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gentrace_forensics.acquisition.pipeline import acquire_image
from gentrace_forensics.classification.output import classify_manifests
from gentrace_forensics.normalization.pipeline import normalize_entries
from gentrace_forensics.reporting import write_report


def run_pipeline(
    image_path: Path, out_dir: Path, *, progress: Callable[[str], None] | None = None
) -> dict[str, Any]:
    """새 실행 폴더를 만든다. 실패해도 완료된 앞 단계와 실패 보고서는 보존한다."""
    image_path = Path(image_path).expanduser().resolve()
    out_dir = Path(out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=False)
    emit = progress or (lambda message: None)
    report: dict[str, Any] = {
        "status": "running",
        "stage": "acquire",
        "image_path": str(image_path),
        "started_at": datetime.now(UTC).isoformat(),
    }
    report_path = out_dir / "run.json"
    try:
        write_report(report_path, report)
        emit("[1/3] acquire")
        manifests = acquire_image(image_path, out_dir / "acquired", progress=emit)
        report.update(manifests=[str(path) for path in manifests], profile_count=len(manifests))

        report["stage"] = "classify"
        write_report(report_path, report)
        emit("[2/3] classify")
        classified_dir = out_dir / "classified"
        count = classify_manifests(manifests, classified_dir)
        entries_path = classified_dir / "classified.jsonl"
        report.update(classified_entries=str(entries_path), classified_count=count)

        report["stage"] = "normalize"
        write_report(report_path, report)
        emit("[3/3] normalize")
        normalized_dir = out_dir / "normalized"
        normalized_count = normalize_entries(entries_path, normalized_dir)
        if normalized_count != count:
            raise ValueError("classification and normalization record counts differ")
        report.update(
            status="complete",
            stage="complete",
            normalized_count=normalized_count,
            normalized_jsonl=str(normalized_dir / "normalized.jsonl"),
            normalized_sqlite=str(normalized_dir / "normalized.db"),
            finished_at=datetime.now(UTC).isoformat(),
        )
        write_report(report_path, report)
    except BaseException as exc:
        report.update(
            status="failed",
            error=str(exc) or type(exc).__name__,
            finished_at=datetime.now(UTC).isoformat(),
        )
        try:
            write_report(report_path, report)
        except OSError:
            pass  # 최초 처리 오류를 보고서 저장 실패로 가리지 않는다.
        raise
    return report

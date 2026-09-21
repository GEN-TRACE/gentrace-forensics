"""`gentrace` CLI 진입점.

각 단계는 독립 실행하거나 run으로 연결할 수 있다.

    gentrace acquire   --image disk.E01 --out outputs/
    gentrace classify  --cache path/to/profile/acquired.json --out outputs/classified/
    gentrace normalize --entries outputs/classified/classified.jsonl --out outputs/normalized/
    gentrace run       --image disk.E01 --out outputs/   # 전체 파이프라인
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path


def _add_acquire(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("acquire", help="E01에서 Chrome 캐시·네트워크 상태 획득")
    p.add_argument("--image", required=True, help="E01 이미지 경로")
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_acquire)


def _add_classify(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("classify", help="캐시 관측 분류·파일 근거 보존")
    p.add_argument(
        "--cache",
        required=True,
        action="append",
        help="AcquiredCache JSON 경로 (여러 번 지정 가능)",
    )
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_classify)


def _add_normalize(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("normalize", help="공통 관측 스키마로 정규화·저장")
    p.add_argument("--entries", required=True, help="ClassifiedEntry JSONL 경로")
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_normalize)


def _add_analyze(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("analyze", help="기존 획득본 검증 → 분류·정규화·아티팩트 복원·열람 보고서")
    p.add_argument(
        "--cache", required=True, action="append", help="acquired.json 경로 (반복 지정 가능)"
    )
    p.add_argument("--out", required=True, help="새 결과 디렉터리")
    p.set_defaults(func=cmd_analyze)


def cmd_analyze(args: argparse.Namespace) -> int:
    from gentrace_forensics.pipeline import analyze_manifests

    report = analyze_manifests(
        [Path(path) for path in args.cache], Path(args.out), progress=_progress
    )
    print(
        f"recovered {report['artifact_count']} artifacts -> {report['review_report']}",
        file=sys.stderr,
    )
    return 0


def _add_run(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("run", help="획득 → 분류·정규화 → 아티팩트 복원·열람 보고서")
    p.add_argument("--image", required=True, help="E01 이미지 경로")
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_run)


def cmd_acquire(args: argparse.Namespace) -> int:
    from gentrace_forensics.acquisition.pipeline import acquire_image

    manifests = acquire_image(Path(args.image), Path(args.out), progress=_progress)
    print(f"acquired {len(manifests)} profiles", file=sys.stderr)
    for path in manifests:
        print(path)
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    from gentrace_forensics.classification.output import classify_manifests

    out_dir = Path(args.out).resolve()
    count = classify_manifests([Path(path) for path in args.cache], out_dir)
    print(f"classified {count} entries -> {out_dir / 'classified.jsonl'}", file=sys.stderr)
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    from gentrace_forensics.normalization.pipeline import normalize_entries

    count = normalize_entries(Path(args.entries), Path(args.out))
    print(f"normalized {count} entries -> {Path(args.out).resolve()}", file=sys.stderr)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from gentrace_forensics.pipeline import run_pipeline

    report = run_pipeline(Path(args.image), Path(args.out), progress=_progress)
    print(
        f"completed {report['profile_count']} profiles, {report['normalized_count']} cache entries, "
        f"{report['artifact_count']} artifacts -> {report['review_report']}",
        file=sys.stderr,
    )
    return 0


def _progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gentrace",
        description="GEN-TRACE: 로컬 증거 획득·분류·정규화·아티팩트 복원",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_acquire(sub)
    _add_classify(sub)
    _add_normalize(sub)
    _add_run(sub)
    _add_analyze(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"gentrace: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("gentrace: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

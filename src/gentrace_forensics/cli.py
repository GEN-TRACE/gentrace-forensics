"""`gentrace` CLI 진입점.

classify는 프로필별 매니페스트를 받아 실행한다. acquire / normalize / run은 연결 예정.

    gentrace acquire   --image disk.E01 --out outputs/
    gentrace classify  --cache path/to/profile/acquired.json --out outputs/classified/
    gentrace normalize --entries outputs/classified.json --out outputs/
    gentrace run       --image disk.E01 --out outputs/   # 전체 파이프라인
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path


def _add_acquire(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("acquire", help="E01에서 Chrome Cache_Data 추출 (예은)")
    p.add_argument("--image", required=True, help="E01 이미지 경로")
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_acquire)


def _add_classify(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("classify", help="Blockfile 파싱 + 서비스 분류 (지민)")
    p.add_argument(
        "--cache",
        required=True,
        action="append",
        help="AcquiredCache JSON 경로 (여러 번 지정 가능)",
    )
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_classify)


def _add_normalize(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("normalize", help="공통 스키마로 정규화·저장 (신아)")
    p.add_argument("--entries", required=True, help="ClassifiedEntry JSONL 경로")
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_normalize)


def _add_run(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("run", help="acquire → classify → normalize 전체 실행")
    p.add_argument("--image", required=True, help="E01 이미지 경로")
    p.add_argument("--out", required=True, help="출력 디렉터리")
    p.set_defaults(func=cmd_run)


def cmd_acquire(args: argparse.Namespace) -> int:
    raise NotImplementedError("acquisition 단계 미구현 (예은)")


def cmd_classify(args: argparse.Namespace) -> int:
    from gentrace_forensics.classification.output import classify_manifests

    out_dir = Path(args.out).resolve()
    count = classify_manifests([Path(path) for path in args.cache], out_dir)
    print(f"classified {count} entries -> {out_dir / 'classified.jsonl'}", file=sys.stderr)
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    raise NotImplementedError("normalization 단계 미구현 (신아)")


def cmd_run(args: argparse.Namespace) -> int:
    raise NotImplementedError("run 파이프라인 미구현")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gentrace",
        description="GEN-TRACE 포렌식 파이프라인 (획득·분류·정규화)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_acquire(sub)
    _add_classify(sub)
    _add_normalize(sub)
    _add_run(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

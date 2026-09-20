"""`gentrace` CLI 진입점.

서브커맨드 골격만 둔다. 각 단계 구현은 담당 폴더에서 진행.

    gentrace acquire   --image disk.E01 --out outputs/
    gentrace classify  --cache outputs/acquired.json --out outputs/
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
    p.add_argument("--cache", required=True, help="AcquiredCache JSON 경로")
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
    from gentrace_forensics.classification.classify import classify_cache
    from gentrace_forensics.schemas.acquisition import AcquiredCache

    manifest_path = Path(args.cache)
    cache = AcquiredCache.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    cache_dir = manifest_path.parent / "Cache" / "Cache_Data"

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    entries = classify_cache(cache, cache_dir, body_dir=out_dir / "bodies")

    out_path = out_dir / "classified.jsonl"
    with out_path.open("w", encoding="utf-8", newline="\n") as f:
        for entry in entries:
            f.write(entry.model_dump_json())
            f.write("\n")

    print(f"classified {len(entries)} entries -> {out_path}", file=sys.stderr)
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

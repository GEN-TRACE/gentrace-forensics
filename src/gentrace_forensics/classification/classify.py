"""서비스 라우팅 + artifact_kind 결정.

흐름:
  AcquiredCache → blockfile.parser 로 ParsedCacheEntry 목록
  → 각 엔트리를 ServiceClassifier 로 라우팅
  → http.decide_filename 으로 파일명, 본문 저장 + SHA-256
  → ClassifiedEntry 산출
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from gentrace_forensics.schemas.acquisition import AcquiredCache
from gentrace_forensics.schemas.classification import ClassifiedEntry


def classify_cache(cache: AcquiredCache, out_dir: Path) -> list[ClassifiedEntry]:
    """한 프로필 캐시를 분류해 ClassifiedEntry 목록 반환."""
    raise NotImplementedError


def iter_classified(cache: AcquiredCache, out_dir: Path) -> Iterator[ClassifiedEntry]:
    raise NotImplementedError

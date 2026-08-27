"""Gemini (Nano Banana 2) 분류 — 페어링 방식.

업로드와 생성본이 같은 도메인·Content-Type·파일명.
  - Content-Type: image/jpeg
  - 도메인: lh3.googleusercontent.com
  - 구분 1: URL 경로 세그먼트 `rd-gg`(업로드) vs `rd-gg-dl`(생성본)
  - 구분 2: 파일 크기 — 생성본이 워터마크 때문에 더 큼

같은 파일명끼리 페어링 후 세그먼트 + 크기로 판별.
페어링 실패 → artifact_kind = "unmatched" (evidence 에 사유).
"""

from __future__ import annotations

from collections.abc import Iterable

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)


class GeminiClassifier(ServiceClassifier):
    service = "gemini"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        raise NotImplementedError

    def classify(
        self, entry: ParsedCacheEntry, *, context: Iterable[ParsedCacheEntry]
    ) -> Classification:
        raise NotImplementedError

    def pair_entries(
        self, entries: Iterable[ParsedCacheEntry]
    ) -> list[tuple[ParsedCacheEntry | None, ParsedCacheEntry | None]]:
        """(upload, generated) 페어 목록. 한쪽이 None 이면 unmatched."""
        raise NotImplementedError

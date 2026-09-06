"""Gemini (Nano Banana) 분류.

이 시나리오 캐시에서 관측된 형태:
  - `lh3.googleusercontent.com/rd-gg/…`     : 생성 이미지 전체해상도 PNG (~2MB)
  - `lh3.googleusercontent.com/rd-gg-dl/…`  : 같은 생성 이미지의 다운로드 JPG (~150KB)
  둘 다 Content-Disposition 파일명이 `watermarked_img_<id>.<ext>` (워터마크 = 생성본).

`<id>` 로 `rd-gg`(전체해상도) ↔ `rd-gg-dl`(다운로드) 를 페어링한다.
`watermarked_img_<id>` 가 없는 `rd-gg*` 이미지(= 페어링 근거 없음)는 `unmatched`.

주의: CONTRIBUTING.md 3.2.2 는 `rd-gg`=업로드 / `rd-gg-dl`=생성본 으로 적고 있으나,
이 캐시에는 사용자 업로드가 관측되지 않고 두 세그먼트 모두 생성본(워터마크)이다.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)

_GEN_SEGMENT = re.compile(r"lh3\.google(?:usercontent)?\.com/(rd-gg-dl|rd-gg)/")
_WATERMARKED = re.compile(r"watermarked_img_(\d+)")

_VARIANT = {"rd-gg": "fullres", "rd-gg-dl": "download"}


def _variant(url: str) -> str | None:
    m = _GEN_SEGMENT.search(url)
    return _VARIANT[m.group(1)] if m else None


def _artifact_id(entry: ParsedCacheEntry) -> str | None:
    cd = entry.response.get("content-disposition") or ""
    m = _WATERMARKED.search(cd)
    if m:
        return m.group(1)
    m = _WATERMARKED.search(entry.filename)
    return m.group(1) if m else None


class GeminiClassifier(ServiceClassifier):
    service = "gemini"

    def __init__(self) -> None:
        self._groups_cache: dict[int, dict[str, set[str]]] = {}

    def matches(self, entry: ParsedCacheEntry) -> bool:
        if _variant(entry.url) is None:
            return False
        return (entry.content_type or "").startswith("image/") or _artifact_id(entry) is not None

    def _groups(self, entries: Sequence[ParsedCacheEntry]) -> dict[str, set[str]]:
        """{artifact_id: {관측된 variant 들}}"""
        cache_id = id(entries)
        cached = self._groups_cache.get(cache_id)
        if cached is None:
            cached = {}
            for entry in entries:
                variant = _variant(entry.url)
                artifact_id = _artifact_id(entry)
                if variant and artifact_id:
                    cached.setdefault(artifact_id, set()).add(variant)
            self._groups_cache[cache_id] = cached
        return cached

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        variant = _variant(entry.url)
        artifact_id = _artifact_id(entry)

        if artifact_id is None:
            return Classification(
                "unmatched",
                evidence={
                    "reason": "watermarked_img id 없음 — 업로드/생성 판별 불가",
                    "variant": variant,
                },
            )

        group = self._groups(entries).get(artifact_id, set())
        evidence: dict[str, Any] = {
            "artifact_id": artifact_id,
            "variant": variant,  # fullres(PNG) / download(JPG)
            "paired": {"fullres", "download"} <= group,
            "group_variants": sorted(group),
            "watermarked": True,
        }
        return Classification("generated_file", evidence=evidence)

"""Google Veo 3 (deevid.ai) 분류.

- `api.deevid.ai/my-assets` : 생성 이력 JSON (자산 인덱스) → `conversation`
- `cdn2.deevid.ai/**/user-video/<name>.mp4` : 생성된 영상 → `generated_file`
- `cdn2.deevid.ai/**/user-image/<name>` : 업로드 원본 이미지 → `file_upload`
  (단 `v2_rs-image-cover-*` 는 생성 결과 커버 → `generated_file`)

my-assets JSON 의 `detail.creation` 에서
  - `videoUrl` / `noWaterMarkVideoUrl` → 영상 (생성본)
  - `originalImageNameUrls` / `inputUserImageName` → 입력 이미지 (업로드)
  - `resultVideoCoverImageName` → 결과 커버
을 뽑아 CDN 엔트리와 URL 로 교차 대조한다.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)

_MY_ASSETS = "api.deevid.ai/my-assets"
_ASSET_PATH = re.compile(r"/(user-video|user-image)/([^/?#]+)")
_COVER = re.compile(r"(?:^|/)v2_rs-image-cover-", re.IGNORECASE)


def _asset_key(url: str) -> str | None:
    """`.../cdn-cgi/image/.../user-image/v2_x.png?y` → `user-image/v2_x.png`."""
    m = _ASSET_PATH.search(url)
    return f"{m.group(1)}/{m.group(2)}" if m else None


@dataclass
class _Creation:
    creation_id: int | None
    kind: str | None  # TXT2VIDEO / IMAGE2VIDEO / MULTIMODAL_VIDEO ...
    task_state: str | None
    prompt: str | None
    length_seconds: str | None
    created_timestamp_ms: int | None
    video_keys: set[str] = field(default_factory=set)
    input_image_keys: set[str] = field(default_factory=set)
    cover_image_keys: set[str] = field(default_factory=set)


@dataclass
class _AssetIndex:
    creations: list[_Creation]
    by_video: dict[str, _Creation]
    by_input_image: dict[str, _Creation]
    cover_keys: set[str]


def _iter_creations(payload: Any) -> list[dict[str, Any]]:
    try:
        groups = payload["data"]["data"]["groups"]
    except (KeyError, TypeError):
        return []
    out: list[dict[str, Any]] = []
    for group in groups:
        for item in group.get("items", []):
            creation = (item.get("detail") or {}).get("creation")
            if isinstance(creation, dict):
                out.append(creation)
    return out


def _build_index(my_assets_bodies: Sequence[bytes]) -> _AssetIndex:
    creations: list[_Creation] = []
    for body in my_assets_bodies:
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            continue
        for raw in _iter_creations(payload):
            video_urls = [raw.get("videoUrl"), raw.get("noWaterMarkVideoUrl")]
            image_urls = list(raw.get("originalImageNameUrls") or [])
            if raw.get("inputUserImageName"):
                image_urls.append(raw["inputUserImageName"])
            creations.append(
                _Creation(
                    creation_id=raw.get("id"),
                    kind=raw.get("type"),
                    task_state=raw.get("taskState"),
                    prompt=raw.get("prompt"),
                    length_seconds=raw.get("lengthOfSecond"),
                    created_timestamp_ms=raw.get("createTimestamp"),
                    video_keys={k for u in video_urls if u and (k := _asset_key(u))},
                    input_image_keys={k for u in image_urls if u and (k := _asset_key(u))},
                    cover_image_keys={
                        k
                        for u in [raw.get("resultVideoCoverImageName")]
                        if u and (k := _asset_key(u))
                    },
                )
            )

    by_video: dict[str, _Creation] = {}
    by_input: dict[str, _Creation] = {}
    covers: set[str] = set()
    for creation in creations:
        for key in creation.video_keys:
            by_video.setdefault(key, creation)
        for key in creation.input_image_keys:
            by_input.setdefault(key, creation)
        covers |= creation.cover_image_keys
    return _AssetIndex(creations, by_video, by_input, covers)


def _creation_evidence(creation: _Creation) -> dict[str, Any]:
    prompt = creation.prompt or ""
    return {
        "matched_my_assets": True,
        "creation_id": creation.creation_id,
        "creation_type": creation.kind,
        "task_state": creation.task_state,
        "length_seconds": creation.length_seconds,
        "created_timestamp_ms": creation.created_timestamp_ms,
        "prompt_preview": prompt[:280] + ("…" if len(prompt) > 280 else ""),
    }


class Veo3Classifier(ServiceClassifier):
    service = "veo3"

    def __init__(self) -> None:
        self._index_cache: dict[int, _AssetIndex] = {}

    def _index(self, entries: Sequence[ParsedCacheEntry]) -> _AssetIndex:
        cache_id = id(entries)
        cached = self._index_cache.get(cache_id)
        if cached is None:
            bodies = [e.body for e in entries if _MY_ASSETS in e.url and e.body]
            cached = _build_index(bodies)
            self._index_cache[cache_id] = cached
        return cached

    def matches(self, entry: ParsedCacheEntry) -> bool:
        url = entry.url
        if _MY_ASSETS in url:
            return True
        return "cdn2.deevid.ai" in url and ("/user-video/" in url or "/user-image/" in url)

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        index = self._index(entries)
        url = entry.url

        if _MY_ASSETS in url:
            return Classification(
                "conversation",
                evidence={
                    "creation_count": len(index.creations),
                    "creations": [
                        {
                            "id": c.creation_id,
                            "type": c.kind,
                            "task_state": c.task_state,
                            "created_timestamp_ms": c.created_timestamp_ms,
                            "video_keys": sorted(c.video_keys),
                            "input_image_keys": sorted(c.input_image_keys),
                        }
                        for c in index.creations
                    ],
                },
            )

        key = _asset_key(url)
        evidence: dict[str, Any] = {"asset_key": key}

        if "/user-video/" in url:
            creation = index.by_video.get(key) if key else None
            if creation:
                evidence.update(_creation_evidence(creation))
            else:
                evidence["matched_my_assets"] = False
            return Classification("generated_file", evidence=evidence)

        # /user-image/
        if key and (_COVER.search(key) or key in index.cover_keys):
            evidence["role"] = "result_video_cover"
            return Classification("generated_file", evidence=evidence)

        creation = index.by_input_image.get(key) if key else None
        if creation:
            evidence.update(_creation_evidence(creation))
            evidence["role"] = "video_input_image"
        else:
            evidence["matched_my_assets"] = False
            evidence["role"] = "user_image"
        return Classification("file_upload", evidence=evidence)

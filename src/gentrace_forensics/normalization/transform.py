"""ClassifiedEntry → NormalizedArtifact.

- timestamp: cache_timestamps 중 가장 신뢰도 높은 값 → UTC
- service: mapping.normalize_service
- event_type: mapping.event_type_for(artifact_kind)
- source_id: entry_id + 이미지/프로필/오프셋을 되짚을 수 있는 문자열
- 모르는 값은 None. 추측 금지.
"""

from __future__ import annotations

from gentrace_forensics.schemas.classification import ClassifiedEntry
from gentrace_forensics.schemas.normalization import NormalizedArtifact


def build_source_id(entry: ClassifiedEntry) -> str:
    """원본 E01 → 파일 → 오프셋까지 역추적 가능한 식별자."""
    raise NotImplementedError


def transform(entry: ClassifiedEntry) -> NormalizedArtifact:
    raise NotImplementedError


def transform_many(entries: list[ClassifiedEntry]) -> list[NormalizedArtifact]:
    return [transform(e) for e in entries]

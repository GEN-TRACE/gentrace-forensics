"""서비스 분류기 베이스.

각 서비스 모듈은 `ServiceClassifier` 를 구현한다.
- `matches()` : 이 엔트리가 해당 서비스 소속인지 (URL/도메인/Content-Type/JSON)
- `classify()`: `artifact_kind` 와 근거(evidence) 결정. 같은 캐시의 전체 엔트리를
  `entries` 로 받으므로 페어링(Gemini)·JSON 상호참조도 가능.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.schemas.classification import ArtifactKind, Service


@dataclass
class Classification:
    """한 엔트리의 분류 결과."""

    artifact_kind: ArtifactKind
    evidence: dict[str, Any] = field(default_factory=dict)
    filename: str | None = None  # 파서 기본값 대신 쓸 논리 파일명 (선택)
    service: Service | None = None  # 분류기 기본 service 를 덮어쓸 때만 (선택)


class ServiceClassifier(ABC):
    """서비스별 분류기. `service` 는 클래스 속성으로 지정한다."""

    service: ClassVar[Service]

    @abstractmethod
    def matches(self, entry: ParsedCacheEntry) -> bool:
        """이 엔트리가 이 서비스에서 나온 것인지."""

    @abstractmethod
    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        """`entries` 는 같은 캐시의 전체 ParsedCacheEntry (페어링·상호참조용)."""

"""서비스 분류기 베이스.

각 서비스 모듈은 ServiceClassifier 를 구현한다.
- matches(): 이 엔트리가 해당 서비스 소속인지 (URL/도메인/Content-Type/JSON)
- classify(): artifact_kind 와 evidence 결정. 필요 시 여러 엔트리 페어링(Gemini).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.schemas.classification import ArtifactKind, Service


class Classification:
    def __init__(
        self,
        artifact_kind: ArtifactKind,
        evidence: dict,
        filename: str | None = None,
    ) -> None:
        self.artifact_kind = artifact_kind
        self.evidence = evidence
        self.filename = filename


class ServiceClassifier(ABC):
    service: Service

    @abstractmethod
    def matches(self, entry: ParsedCacheEntry) -> bool: ...

    @abstractmethod
    def classify(
        self, entry: ParsedCacheEntry, *, context: Iterable[ParsedCacheEntry]
    ) -> Classification:
        """context 는 같은 캐시의 전체 엔트리 (페어링용)."""

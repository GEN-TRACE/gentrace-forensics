"""단계 간 데이터 계약 (Pydantic 모델).

CONTRIBUTING.md 4 절. 세 단계 담당자가 합의 후에만 변경한다.
"""

from gentrace_forensics.schemas.acquisition import AcquiredCache, AcquiredFile
from gentrace_forensics.schemas.classification import (
    ArtifactKind,
    ClassifiedEntry,
    Service,
)
from gentrace_forensics.schemas.normalization import NormalizedArtifact

__all__ = [
    "AcquiredCache",
    "AcquiredFile",
    "ArtifactKind",
    "ClassifiedEntry",
    "NormalizedArtifact",
    "Service",
]

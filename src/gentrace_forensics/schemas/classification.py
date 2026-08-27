"""분류 → 정규화 데이터 계약.

지민(분류) 단계가 산출하고 신아(정규화) 단계가 소비한다.
CONTRIBUTING.md 4.2 절 참조. 필드 변경은 셋이 합의 후에만.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from gentrace_forensics.schemas.acquisition import AcquiredCache

Service = Literal["chatgpt", "claude", "gemini", "veo3", "elevenlabs", "unknown"]
ArtifactKind = Literal["file_upload", "generated_file", "conversation", "unmatched", "other"]


class ClassifiedEntry(BaseModel):
    """분류된 캐시 엔트리 하나."""

    entry_id: str = Field(description="엔트리 해시 등 고유 ID")
    cache_key: str
    url: str
    content_type: str | None = None
    content_encoding: str | None = None
    content_disposition: str | None = None
    filename: str = Field(description="CONTRIBUTING.md 3.2.1 규칙으로 결정한 논리적 파일명")
    size: int
    body_path: Path | None = Field(default=None, description="압축 해제된 본문 저장 경로")
    body_sha256: str | None = None
    service: Service = "unknown"
    artifact_kind: ArtifactKind = "other"
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="분류 근거 (매칭된 패턴, JSON 필드, 페어 정보 등)",
    )
    source_file: str = Field(description="data_N 또는 f_XXXXXX")
    source_offset: int | None = None
    cache_timestamps: dict[str, Any] = Field(
        default_factory=dict, description="엔트리에 남은 시간값 (raw)"
    )
    source_cache: AcquiredCache = Field(description="어느 프로필/이미지에서 왔는지")

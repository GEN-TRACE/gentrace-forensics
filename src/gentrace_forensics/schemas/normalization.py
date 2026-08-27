"""정규화 출력 스키마 (Common Schema).

신아(정규화) 단계가 산출한다. 타임라인·통합검색·상관분석의 입력.
CONTRIBUTING.md 4.3 절 참조. 필드 변경은 셋이 합의 후에만.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class NormalizedArtifact(BaseModel):
    """공통 스키마로 검증된 아티팩트 레코드 하나."""

    timestamp: datetime | None = Field(default=None, description="UTC")
    service: str
    user_id: str | None = None
    session_id: str | None = None
    event_type: str = Field(description="visit, cache_write, download, request, response ...")
    actor: str | None = None
    content: str | None = Field(default=None, description="URL, HTTP 응답, JSON, 캐시 본문")
    content_type: str = Field(description="html, json, image, audio, video ...")
    artifact_source: str = Field(description="cache, history, cookie, indexeddb ...")
    artifact_kind: str = Field(description="file_upload, generated_file ...")
    filename: str | None = None
    url: str
    domain: str
    source_id: str = Field(
        description="ClassifiedEntry.entry_id + AcquiredCache 정보. 원본으로 역추적 가능해야 함"
    )
    sha256: str | None = None

"""Additive artifact contract v1; cache-entry contracts remain readable."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Role = Literal["upload", "generated", "unknown"]
Attribution = Literal["evidence_linked", "pattern_candidate", "unresolved"]
Representation = Literal["original", "preview", "cover", "metadata", "fragment", "unknown"]
Recovery = Literal["complete", "partial", "metadata_only", "missing", "invalid", "unverified"]


class SourceRef(BaseModel):
    source_id: str
    profile_id: str
    image_path: str
    image_sha256: str | None
    partition_offset: int
    windows_user: str
    chrome_profile: str
    cache_path: str
    source_file: str
    source_file_sha256: str | None
    source_offset: int | None
    entry_id: str | None = None
    cache_key: str | None = None
    json_pointer: str | None = None
    timestamps: dict[str, Any] = Field(default_factory=dict)
    locations: dict[str, Any] = Field(default_factory=dict)


class RecoveredFile(BaseModel):
    representation: Representation = "unknown"
    recovery_status: Recovery
    declared_mime: str | None = None
    detected_mime: str | None = None
    original_name: str | None = None
    path: str | None = None
    sha256: str | None = None
    size: int = 0
    expected_size: int | None = None
    validation: dict[str, Any] = Field(default_factory=dict)
    source_ids: list[str] = Field(default_factory=list)
    ranges: list[dict[str, Any]] = Field(default_factory=list)


class Artifact(BaseModel):
    schema_version: str = "1.0"
    rule_version: str = "artifact-1"
    artifact_id: str
    profile_id: str
    service: str
    asset_key: str
    role: Role = "unknown"
    attribution: Attribution = "pattern_candidate"
    recovery_status: Recovery = "metadata_only"
    names: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    metadata: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    source_refs: list[SourceRef] = Field(default_factory=list)
    files: list[RecoveredFile] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class Relationship(BaseModel):
    profile_id: str
    service: str
    subject_id: str
    relation: Literal["input", "output", "preview", "variant", "sample", "history"]
    artifact_id: str
    source_id: str
    json_pointer: str


class NetworkRecord(BaseModel):
    record_id: str
    profile_id: str
    service: str
    record_type: str
    source_ref: SourceRef
    properties: dict[str, Any]
    times: dict[str, Any] = Field(default_factory=dict)

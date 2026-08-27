"""서비스명 · 이벤트 타입 · Content-Type 매핑 테이블.

CONTRIBUTING.md 3.3 절. 추측으로 채우지 않는다. 매핑에 없으면 원본 유지 또는 None.
"""

from __future__ import annotations

SERVICE_NAMES: dict[str, str] = {
    "chatgpt": "chatgpt",
    "openai": "chatgpt",
    "claude": "claude",
    "anthropic": "claude",
    "gemini": "gemini",
    "veo3": "veo3",
    "deevid": "veo3",
    "elevenlabs": "elevenlabs",
}

ARTIFACT_KIND_TO_EVENT: dict[str, str] = {
    "file_upload": "upload",
    "generated_file": "generate",
    "conversation": "response",
    "unmatched": "cache_write",
    "other": "cache_write",
}

CONTENT_TYPE_GROUPS: dict[str, str] = {
    "text/html": "html",
    "application/json": "json",
    "image/png": "image",
    "image/jpeg": "image",
    "image/webp": "image",
    "audio/mpeg": "audio",
    "audio/mp4": "audio",
    "video/mp4": "video",
    "application/octet-stream": "binary",
}


def normalize_service(raw: str | None) -> str | None:
    raise NotImplementedError


def event_type_for(artifact_kind: str) -> str:
    raise NotImplementedError


def content_type_group(content_type: str | None) -> str | None:
    raise NotImplementedError

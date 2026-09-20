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
    """서비스 별칭을 canonical name으로 변환. 알 수 없는 값은 소문자 원본을 유지."""
    if raw is None:
        return None
    value = raw.strip().lower()
    if not value:
        return None
    return SERVICE_NAMES.get(value, value)


def event_type_for(artifact_kind: str) -> str:
    """분류 artifact_kind를 공통 event_type으로 변환."""
    value = artifact_kind.strip().lower()
    return ARTIFACT_KIND_TO_EVENT.get(value, value or "unknown")


def content_type_group(content_type: str | None) -> str | None:
    """MIME Content-Type을 검색/분석용 상위 그룹으로 정규화."""
    if content_type is None:
        return None

    mime = content_type.split(";", 1)[0].strip().lower()
    if not mime:
        return None

    mapped = CONTENT_TYPE_GROUPS.get(mime)
    if mapped is not None:
        return mapped

    if mime.endswith("+json"):
        return "json"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("video/"):
        return "video"
    if mime.startswith("text/"):
        return "text"

    # 정의되지 않은 MIME은 추측해 다른 그룹으로 넣지 않고 canonicalized 원본을 보존한다.
    return mime

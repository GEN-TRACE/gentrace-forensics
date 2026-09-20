"""ChatGPT 분류.

File Upload:
  - URL: `chatgpt.com/backend-api/estuary/content?id=file_...`
  - Content-Type: image/png
  - 식별자: URL 의 file_id
Generated File:
  - 대화 캐시 JSON 내부 필드로 판별 (`conversation_id`, `download_url`)
비고: 비로그인 상태에서도 `file_name`, `file_size_bytes` 는 평문 잔존.
      본문은 "File stream access denied".

이 시나리오 캐시(`01_Cache_Data`)엔 `backend-api/conversations`(목록) 응답만
있고 개별 대화 상세·`estuary/content` 응답은 없다. 목록 분류는 실데이터로
검증했고, 업로드·생성 판별은 CONTRIBUTING.md 스펙 기반 구현이라 실데이터
검증 전이다.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any
from urllib.parse import parse_qs, urlsplit

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)

_HOST = "chatgpt.com"
_ESTUARY = re.compile(r"/backend-api/estuary/content")
_CONVERSATION_DETAIL = re.compile(r"/backend-api/conversation/[^/?#]+")
_CONVERSATIONS_LIST = re.compile(r"/backend-api/conversations(?:$|[/?])")

_ACCESS_DENIED_TEXT = "File stream access denied"


def _find_all(data: Any, key: str) -> list[Any]:
    """data 안 어디에 있든 key 이름과 일치하는 값을 전부 찾는다 (JSON 형태 불확실할 때)."""
    found: list[Any] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k == key:
                found.append(v)
            found.extend(_find_all(v, key))
    elif isinstance(data, list):
        for item in data:
            found.extend(_find_all(item, key))
    return found


def _file_id_from_query(url: str) -> str | None:
    values = parse_qs(urlsplit(url).query).get("id")
    return values[0] if values else None


def _parse_json(body: bytes) -> Any | None:
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


class ChatGPTClassifier(ServiceClassifier):
    service = "chatgpt"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        if _HOST not in entry.url:
            return False
        url = entry.url
        return bool(
            _ESTUARY.search(url)
            or _CONVERSATION_DETAIL.search(url)
            or _CONVERSATIONS_LIST.search(url)
        )

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        url = entry.url

        if _ESTUARY.search(url):
            return self._classify_estuary_content(entry)
        if _CONVERSATION_DETAIL.search(url):
            return self._classify_conversation_detail(entry)
        return self._classify_conversations_list(entry)

    def _classify_estuary_content(self, entry: ParsedCacheEntry) -> Classification:
        evidence: dict[str, Any] = {
            "role": "file_upload_content",
            "file_id": _file_id_from_query(entry.url),
        }
        text_body = entry.body.decode("utf-8", errors="replace") if entry.body else ""
        if _ACCESS_DENIED_TEXT in text_body:
            evidence["access_denied"] = True

        data = _parse_json(entry.body)
        if isinstance(data, dict):
            for field in ("file_name", "file_size_bytes"):
                if field in data:
                    evidence[field] = data[field]

        content_disposition = entry.response.get("content-disposition")
        if content_disposition:
            evidence["content_disposition"] = content_disposition

        return Classification("file_upload", evidence=evidence)

    def _classify_conversation_detail(self, entry: ParsedCacheEntry) -> Classification:
        data = _parse_json(entry.body)
        if data is None:
            return Classification(
                "other", evidence={"role": "conversation_detail", "note": "json parse failed"}
            )

        conversation_id = (
            data.get("conversation_id") or data.get("id") if isinstance(data, dict) else None
        )
        download_urls = _find_all(data, "download_url")
        if download_urls:
            return Classification(
                "generated_file",
                evidence={
                    "role": "conversation_generated_file",
                    "conversation_id": conversation_id,
                    "download_urls": download_urls,
                    "file_names": _find_all(data, "file_name"),
                    "file_size_bytes": _find_all(data, "file_size_bytes"),
                },
            )
        return Classification(
            "conversation",
            evidence={"role": "conversation_detail", "conversation_id": conversation_id},
        )

    def _classify_conversations_list(self, entry: ParsedCacheEntry) -> Classification:
        data = _parse_json(entry.body)
        items = data.get("items") if isinstance(data, dict) else None
        conversations = [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "create_time": item.get("create_time"),
                "update_time": item.get("update_time"),
            }
            for item in (items or [])
            if isinstance(item, dict)
        ]
        return Classification(
            "conversation",
            evidence={
                "role": "conversation_list",
                "conversation_count": len(conversations),
                "conversations": conversations,
            },
        )

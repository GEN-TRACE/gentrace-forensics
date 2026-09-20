"""Claude 분류.

File Upload:
  - URL: `claude.ai/api/[conversation_id]/files/[file_id]`
  - Content-Type: image/webp, 파일명 preview.webp
Generated File:
  - Content-Type: application/octet-stream
  - 인코딩된 URL 경로 디코딩 필요 → `/mnt/user-data/outputs/<파일명>` 형태

실데이터(캐시 픽스처)에 claude.ai 파일 업로드/생성 트래픽이 없어 전부
CONTRIBUTING.md 3.2.2 스펙 기반 구현이다. 실데이터 확보 시 재검증 필요.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any
from urllib.parse import unquote

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)

_HOST = "claude.ai"
_UPLOAD_FILE = re.compile(r"/api/(?P<conversation_id>[^/]+)/files/(?P<file_id>[^/?#]+)")
_GENERATED_OUTPUT = re.compile(r"/mnt/user-data/outputs/(?P<filename>[^/?#]+)")


class ClaudeClassifier(ServiceClassifier):
    service = "claude"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        if _HOST not in entry.url:
            return False
        if _UPLOAD_FILE.search(entry.url):
            return True
        return bool(
            entry.content_type == "application/octet-stream"
            and _GENERATED_OUTPUT.search(unquote(entry.url))
        )

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        url = entry.url

        upload_match = _UPLOAD_FILE.search(url)
        if upload_match:
            evidence: dict[str, Any] = {
                "role": "file_preview",
                "conversation_id": upload_match.group("conversation_id"),
                "file_id": upload_match.group("file_id"),
            }
            return Classification("file_upload", evidence=evidence)

        decoded_url = unquote(url)
        output_match = _GENERATED_OUTPUT.search(decoded_url)
        if output_match:
            filename = output_match.group("filename")
            return Classification(
                "generated_file",
                evidence={"role": "generated_output_file", "decoded_url": decoded_url},
                filename=filename,
            )

        return Classification("other")

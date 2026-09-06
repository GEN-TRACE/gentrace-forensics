"""ChatGPT 분류.

File Upload:
  - URL: `chatgpt.com/backend-api/estuary/content?id=file_...`
  - Content-Type: image/png
  - 식별자: URL 의 file_id
Generated File:
  - 대화 캐시 JSON 내부 필드로 판별 (`conversation_id`, `download_url`)
비고: 비로그인 상태에서도 `file_name`, `file_size_bytes` 는 평문 잔존.
      본문은 "File stream access denied".
"""

from __future__ import annotations

from collections.abc import Sequence

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)


class ChatGPTClassifier(ServiceClassifier):
    service = "chatgpt"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        return False  # TODO(PR7): 구현

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        return Classification("other")

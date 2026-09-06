"""Claude 분류.

File Upload:
  - URL: `claude.ai/api/[conversation_id]/files/[file_id]`
  - Content-Type: image/webp, 파일명 preview.webp
Generated File:
  - Content-Type: application/octet-stream
  - 인코딩된 URL 경로 디코딩 필요 → `/mnt/user-data/outputs/<파일명>` 형태
"""

from __future__ import annotations

from collections.abc import Sequence

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)


class ClaudeClassifier(ServiceClassifier):
    service = "claude"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        return False  # TODO(PR7): 구현

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        return Classification("other")

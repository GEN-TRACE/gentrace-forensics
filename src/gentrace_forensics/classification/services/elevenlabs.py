"""ElevenLabs 분류.

File Upload:
  - URL: `api.us.elevenlabs.io/v2/voices` (Content-Type: application/json)
  - JSON: voices[].samples[] → file_name, size_bytes, hash, preview_url
  - 파일명 예: forensicuser.m4a → 서버 저장명 forensicuser.mp3
Generated File:
  - Content-Type: audio/mpeg
  - URL: `v1/voices/[voice_id]/samples/[sample_id]` 또는 `v1/history/[history_item_id]/audio`
"""

from __future__ import annotations

from collections.abc import Sequence

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)


class ElevenLabsClassifier(ServiceClassifier):
    service = "elevenlabs"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        return False  # TODO(PR6): 구현

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        return Classification("other")

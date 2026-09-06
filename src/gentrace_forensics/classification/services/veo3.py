"""Google Veo 3 (deevid.ai) 분류.

같은 캐시 항목(application/json) 내부 필드로 업로드/생성 구분.
  - URL: `api.deevid.ai/my-assets`
  - Upload:    JSON `inputUserImageId`, `originalImageNameUrls`
               CDN `cdn2.deevid.ai/user-image/...`
  - Generated: JSON `videoUrl`, `noWatermarkVideoUrl`
               CDN `cdn2.deevid.ai/user-video/...mp4`
한 JSON 응답에서 upload/generated 를 각각 별도 ClassifiedEntry 로 낼 수 있다.
"""

from __future__ import annotations

from collections.abc import Sequence

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)


class Veo3Classifier(ServiceClassifier):
    service = "veo3"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        return False  # TODO(PR4): 구현

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        return Classification("other")

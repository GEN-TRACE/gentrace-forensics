"""ElevenLabs 분류.

이 시나리오 캐시에서 관측된 형태 (오디오 바이트는 캐시 안 됨, JSON 메타데이터만):
  - `api.us.elevenlabs.io/v2/voices…`        : 보이스 라이브러리. `voices[].samples[]` 에
    클론 보이스 원본 오디오 정보 (file_name·size_bytes·hash·duration) → `file_upload`
  - `api.us.elevenlabs.io/v1/voices/<id>`     : 단일 보이스. `samples[]` 있으면 `file_upload`
  - `api.us.elevenlabs.io/v1/history…`        : TTS 생성 이력 (text·voice·date) → `conversation`
  - `.../v1/voices/<id>/samples/<sid>[/audio]`: 클론 원본 오디오 바이트 → `file_upload`
  - `.../v1/history/<hid>/audio`              : 생성 오디오 바이트 → `generated_file`

CONTRIBUTING.md 3.2.2 참조.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)

_API_HOST = "api.us.elevenlabs.io"
_VOICES = re.compile(r"/v[12]/voices(?:/[^/?#]+)?(?:[/?#]|$)")
_HISTORY = re.compile(r"/v1/history(?:[/?#]|$)")
_SAMPLE_AUDIO = re.compile(r"/v1/voices/[^/?#]+/samples/[^/?#]+")
_HISTORY_AUDIO = re.compile(r"/v1/history/[^/?#]+/audio")

_SAMPLE_FIELDS = ("sample_id", "file_name", "mime_type", "size_bytes", "hash", "duration_secs")
_HISTORY_FIELDS = (
    "history_item_id",
    "request_id",
    "voice_id",
    "voice_name",
    "model_id",
    "date_unix",
    "content_type",
    "state",
)


def _collect_samples(data: Any) -> list[dict[str, Any]]:
    voices: list[dict[str, Any]]
    if isinstance(data, dict) and isinstance(data.get("voices"), list):
        voices = [v for v in data["voices"] if isinstance(v, dict)]
    elif isinstance(data, dict) and "voice_id" in data:
        voices = [data]
    else:
        return []

    out: list[dict[str, Any]] = []
    for voice in voices:
        for sample in voice.get("samples") or []:
            if not isinstance(sample, dict):
                continue
            record = {k: sample.get(k) for k in _SAMPLE_FIELDS}
            record["voice_id"] = voice.get("voice_id")
            record["voice_name"] = voice.get("name")
            record["voice_category"] = voice.get("category")
            out.append(record)
    return out


def _history_items(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    items = data.get("history")
    if isinstance(data.get("history_item_id"), str):  # 단일 항목 응답
        items = [data]
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        record = {k: item.get(k) for k in _HISTORY_FIELDS}
        text = item.get("text") or ""
        record["text_preview"] = text[:280] + ("…" if len(text) > 280 else "")
        out.append(record)
    return out


class ElevenLabsClassifier(ServiceClassifier):
    service = "elevenlabs"

    def matches(self, entry: ParsedCacheEntry) -> bool:
        url = entry.url
        if _API_HOST not in url:
            return False
        if _VOICES.search(url) or _HISTORY.search(url):
            return True
        return (entry.content_type or "").startswith("audio/")

    def classify(
        self, entry: ParsedCacheEntry, *, entries: Sequence[ParsedCacheEntry]
    ) -> Classification:
        url = entry.url
        content_type = entry.content_type or ""

        if _SAMPLE_AUDIO.search(url):
            return Classification("file_upload", evidence={"role": "voice_clone_sample_audio"})
        if _HISTORY_AUDIO.search(url):
            return Classification("generated_file", evidence={"role": "tts_history_audio"})
        if content_type.startswith("audio/"):
            role = "tts_audio" if "/history" in url else "audio"
            return Classification("generated_file", evidence={"role": role})

        if not content_type.startswith("application/json"):
            return Classification("other", evidence={"role": "api_metadata"})
        try:
            data = json.loads(entry.body)
        except (ValueError, TypeError):
            return Classification("other", evidence={"note": "json parse failed"})

        if _HISTORY.search(url):
            items = _history_items(data)
            return Classification(
                "conversation",
                evidence={
                    "role": "tts_history",
                    "generation_count": len(items),
                    "generations": items,
                },
            )

        samples = _collect_samples(data)
        if samples:
            return Classification(
                "file_upload",
                evidence={
                    "role": "cloned_voice_samples",
                    "sample_count": len(samples),
                    "samples": samples,
                },
            )

        if isinstance(data, dict) and isinstance(data.get("voices"), list):
            return Classification(
                "conversation",
                evidence={"role": "voice_library", "voice_count": len(data["voices"])},
            )
        if isinstance(data, dict) and "voice_id" in data:
            return Classification(
                "conversation",
                evidence={"role": "voice_detail", "voice_id": data.get("voice_id")},
            )
        return Classification("other", evidence={"role": "api_metadata"})

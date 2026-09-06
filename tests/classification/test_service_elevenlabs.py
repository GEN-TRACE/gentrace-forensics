"""ElevenLabs 분류기 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gentrace_forensics.classification.classify import (
    _local_acquired_cache,
    classify_cache_dir,
    classify_entries,
)
from gentrace_forensics.classification.services.elevenlabs import ElevenLabsClassifier
from gentrace_forensics.schemas.acquisition import AcquiredCache

from .test_classify import make_entry

_VOICES_BODY = json.dumps(
    {
        "voices": [
            {
                "voice_id": "premadeXXXXXXXXXXXXX1",
                "name": "Roger",
                "category": "premade",
                "samples": None,
            },
            {
                "voice_id": "clonedXXXXXXXXXXXXXX2",
                "name": "forensicuser",
                "category": "cloned",
                "samples": [
                    {
                        "sample_id": "sampAAAAAAAAAAAAAAAA",
                        "file_name": "forensicuser.mp3",
                        "mime_type": "audio/mpeg",
                        "size_bytes": 212385,
                        "hash": "a0ccec72eceaa599b1bac362f57aa38b",
                        "duration_secs": 11.05,
                    }
                ],
            },
        ]
    }
).encode()

_HISTORY_BODY = json.dumps(
    {
        "history": [
            {
                "history_item_id": "histAAAAAAAAAAAAAAAA",
                "voice_id": "clonedXXXXXXXXXXXXXX2",
                "voice_name": "forensicuser",
                "model_id": "eleven_english_sts_v2",
                "text": "Mom, I'm Rensik. Send virtual currency.",
                "date_unix": 1785043216,
                "content_type": "audio/mpeg",
                "state": "created",
            }
        ],
        "has_more": False,
    }
).encode()


@pytest.fixture
def source_cache() -> AcquiredCache:
    return _local_acquired_cache(Path("/tmp/Cache_Data"))


def test_v2_voices_with_cloned_samples_is_upload(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://api.us.elevenlabs.io/v2/voices?page_size=100",
        body=_VOICES_BODY,
        content_type="application/json",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("elevenlabs", "file_upload")
    assert c.evidence["role"] == "cloned_voice_samples"
    assert c.evidence["sample_count"] == 1
    sample = c.evidence["samples"][0]
    assert sample["file_name"] == "forensicuser.mp3"
    assert sample["hash"] == "a0ccec72eceaa599b1bac362f57aa38b"
    assert sample["size_bytes"] == 212385
    assert sample["voice_name"] == "forensicuser"


def test_history_json_is_conversation(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://api.us.elevenlabs.io/v1/history?page_size=25",
        body=_HISTORY_BODY,
        content_type="application/json",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert (c.service, c.artifact_kind) == ("elevenlabs", "conversation")
    assert c.evidence["role"] == "tts_history"
    assert c.evidence["generation_count"] == 1
    gen = c.evidence["generations"][0]
    assert gen["voice_name"] == "forensicuser"
    assert "Rensik" in gen["text_preview"]


def test_audio_url_patterns(source_cache: AcquiredCache) -> None:
    sample_audio = make_entry(
        "https://api.us.elevenlabs.io/v1/voices/clonedXXX/samples/sampAAA/audio",
        content_type="audio/mpeg",
    )
    history_audio = make_entry(
        "https://api.us.elevenlabs.io/v1/history/histAAA/audio", content_type="audio/mpeg"
    )
    out = {
        c.url: c for c in classify_entries([sample_audio, history_audio], source_cache=source_cache)
    }
    assert out[sample_audio.url].artifact_kind == "file_upload"
    assert out[sample_audio.url].evidence["role"] == "voice_clone_sample_audio"
    assert out[history_audio.url].artifact_kind == "generated_file"


def test_non_artifact_api_is_other(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://api.us.elevenlabs.io/v1/voices/settings/default",
        body=b'{"stability": 0.5}',
        content_type="application/json",
    )
    (c,) = classify_entries([entry], source_cache=source_cache)
    assert c.service == "elevenlabs"
    assert c.artifact_kind == "other"


def test_matches_scope() -> None:
    clf = ElevenLabsClassifier()
    assert clf.matches(make_entry("https://api.us.elevenlabs.io/v2/voices"))
    assert clf.matches(make_entry("https://api.us.elevenlabs.io/v1/history"))
    assert not clf.matches(make_entry("https://elevenlabs.io/app/page"))
    assert not clf.matches(make_entry("https://api.us.elevenlabs.io/v1/workspace/groups"))


# --- 통합 ---


def test_elevenlabs_on_local_fixture(cache_fixture_dir: Path) -> None:
    out = classify_cache_dir(cache_fixture_dir)
    el = [c for c in out if c.service == "elevenlabs"]
    assert len(el) >= 10
    uploads = [c for c in el if c.artifact_kind == "file_upload"]
    assert uploads
    hashes = {s["hash"] for c in uploads for s in c.evidence["samples"]}
    assert len(hashes) >= 1
    names = {s["file_name"] for c in uploads for s in c.evidence["samples"]}
    assert any(n and n.endswith(".mp3") for n in names)

    history = [c for c in el if c.evidence.get("role") == "tts_history"]
    assert history
    assert any(c.evidence["generation_count"] > 0 for c in history)

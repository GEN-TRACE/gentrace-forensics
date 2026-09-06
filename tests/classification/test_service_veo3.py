"""Veo 3 (deevid.ai) 분류기 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gentrace_forensics.classification.classify import classify_cache_dir, classify_entries
from gentrace_forensics.classification.services.veo3 import Veo3Classifier, _asset_key
from gentrace_forensics.schemas.acquisition import AcquiredCache

from .test_classify import make_entry

_MY_ASSETS_BODY = json.dumps(
    {
        "error": {"code": 0},
        "data": {
            "data": {
                "groups": [
                    {
                        "date": "2026-08-26",
                        "items": [
                            {
                                "id": 1,
                                "assetType": "VIDEO",
                                "title": "img2video",
                                "detail": {
                                    "creation": {
                                        "id": 111,
                                        "type": "IMAGE2VIDEO",
                                        "taskState": "SUCCESS",
                                        "prompt": "a fictional forensic training clip",
                                        "lengthOfSecond": "4.00",
                                        "createTimestamp": 1787748905022,
                                        "videoUrl": "https://cdn2.deevid.ai/user-video/v2_traced-aaa.mp4",
                                        "noWaterMarkVideoUrl": "https://cdn2.deevid.ai/user-video/v2_traced-aaa.mp4",
                                        "originalImageNameUrls": [
                                            "https://cdn2.deevid.ai/user-image/v2_src-1.png"
                                        ],
                                        "resultVideoCoverImageName": "https://cdn2.deevid.ai/user-image/v2_rs-image-cover-traced-aaa.png",
                                    }
                                },
                            }
                        ],
                    }
                ]
            }
        },
    }
).encode()


@pytest.fixture
def source_cache() -> AcquiredCache:
    from gentrace_forensics.classification.classify import _local_acquired_cache

    return _local_acquired_cache(Path("/tmp/Cache_Data"))


def test_asset_key_extraction() -> None:
    assert _asset_key("https://cdn2.deevid.ai/user-video/v2_x.mp4") == "user-video/v2_x.mp4"
    assert (
        _asset_key(
            "https://cdn2.deevid.ai/cdn-cgi/image/format=webp,width=480/user-image/v2_y.png?v=1"
        )
        == "user-image/v2_y.png"
    )
    assert _asset_key("https://deevid.ai/app/_next/static/x.js") is None


def test_classifies_deevid_artifacts(source_cache: AcquiredCache) -> None:
    entries = [
        make_entry(
            "https://api.deevid.ai/my-assets?limit=30",
            body=_MY_ASSETS_BODY,
            content_type="application/json",
        ),
        make_entry("https://cdn2.deevid.ai/user-video/v2_traced-aaa.mp4", content_type="video/mp4"),
        make_entry("https://cdn2.deevid.ai/user-image/v2_src-1.png", content_type="image/png"),
        make_entry(
            "https://cdn2.deevid.ai/user-image/v2_rs-image-cover-traced-aaa.png",
            content_type="image/png",
        ),
        make_entry("https://cdn2.deevid.ai/user-image/v2_unknown.jpg", content_type="image/jpeg"),
        make_entry("https://deevid.ai/app/_next/static/chunk.js", content_type="text/javascript"),
    ]
    out = {c.url: c for c in classify_entries(entries, source_cache=source_cache)}

    my_assets = out["https://api.deevid.ai/my-assets?limit=30"]
    assert my_assets.service == "veo3"
    assert my_assets.artifact_kind == "conversation"
    assert my_assets.evidence["creation_count"] == 1

    video = out["https://cdn2.deevid.ai/user-video/v2_traced-aaa.mp4"]
    assert (video.service, video.artifact_kind) == ("veo3", "generated_file")
    assert video.evidence["matched_my_assets"] is True
    assert video.evidence["creation_type"] == "IMAGE2VIDEO"
    assert "forensic training" in video.evidence["prompt_preview"]

    upload = out["https://cdn2.deevid.ai/user-image/v2_src-1.png"]
    assert (upload.service, upload.artifact_kind) == ("veo3", "file_upload")
    assert upload.evidence["role"] == "video_input_image"

    cover = out["https://cdn2.deevid.ai/user-image/v2_rs-image-cover-traced-aaa.png"]
    assert (cover.service, cover.artifact_kind) == ("veo3", "generated_file")
    assert cover.evidence["role"] == "result_video_cover"

    unknown_img = out["https://cdn2.deevid.ai/user-image/v2_unknown.jpg"]
    assert (unknown_img.service, unknown_img.artifact_kind) == ("veo3", "file_upload")
    assert unknown_img.evidence["matched_my_assets"] is False

    site_asset = out["https://deevid.ai/app/_next/static/chunk.js"]
    assert site_asset.service == "unknown"


def test_matches_only_artifact_urls() -> None:
    clf = Veo3Classifier()
    assert clf.matches(make_entry("https://api.deevid.ai/my-assets"))
    assert clf.matches(make_entry("https://cdn2.deevid.ai/user-video/v2_a.mp4"))
    assert not clf.matches(make_entry("https://api.deevid.ai/account/info"))
    assert not clf.matches(make_entry("https://deevid.ai/app/favicon.png"))


# --- 통합 ---


def test_veo3_on_local_fixture(cache_fixture_dir: Path) -> None:
    out = classify_cache_dir(cache_fixture_dir)
    veo3 = [c for c in out if c.service == "veo3"]
    assert len(veo3) >= 10
    kinds = {c.artifact_kind for c in veo3}
    assert {"generated_file", "file_upload", "conversation"} <= kinds
    my_assets = [c for c in veo3 if c.artifact_kind == "conversation"]
    assert len(my_assets) == 1
    assert my_assets[0].evidence["creation_count"] > 0
    # 최소 하나의 생성 영상은 my-assets 와 매칭돼 prompt 근거가 있어야 함
    matched_videos = [
        c
        for c in veo3
        if c.artifact_kind == "generated_file" and c.evidence.get("matched_my_assets")
    ]
    assert matched_videos
    assert any(c.evidence.get("prompt_preview") for c in matched_videos)

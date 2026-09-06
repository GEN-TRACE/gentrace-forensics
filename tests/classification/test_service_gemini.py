"""Gemini (Nano Banana) 분류기 테스트."""

from __future__ import annotations

from pathlib import Path

import pytest

from gentrace_forensics.classification.classify import (
    _local_acquired_cache,
    classify_cache_dir,
    classify_entries,
)
from gentrace_forensics.classification.services.gemini import GeminiClassifier
from gentrace_forensics.schemas.acquisition import AcquiredCache

from .test_classify import make_entry


def _gen(segment: str, artifact_id: str, ext: str, ct: str) -> object:
    url = f"https://lh3.googleusercontent.com/{segment}/AAQ_{artifact_id}{ext}"
    entry = make_entry(url, content_type=ct)
    entry.response.headers["content-disposition"] = (
        f'inline;filename="watermarked_img_{artifact_id}{ext}"'
    )
    return entry


@pytest.fixture
def source_cache() -> AcquiredCache:
    return _local_acquired_cache(Path("/tmp/Cache_Data"))


def test_pairs_fullres_and_download(source_cache: AcquiredCache) -> None:
    entries = [
        _gen("rd-gg", "111", ".png", "image/png"),
        _gen("rd-gg-dl", "111", ".jpg", "image/jpeg"),
        _gen("rd-gg-dl", "222", ".jpg", "image/jpeg"),  # 페어 없음
    ]
    out = list(classify_entries(entries, source_cache=source_cache))  # type: ignore[arg-type]
    assert all(c.service == "gemini" for c in out)
    assert all(c.artifact_kind == "generated_file" for c in out)

    by_id = {(c.evidence["artifact_id"], c.evidence["variant"]): c for c in out}
    assert by_id[("111", "fullres")].evidence["paired"] is True
    assert by_id[("111", "download")].evidence["paired"] is True
    assert by_id[("222", "download")].evidence["paired"] is False
    assert by_id[("222", "download")].evidence["group_variants"] == ["download"]


def test_rd_gg_image_without_id_is_unmatched(source_cache: AcquiredCache) -> None:
    entry = make_entry(
        "https://lh3.googleusercontent.com/rd-gg/ACRw_nofilename", content_type="image/png"
    )
    (c,) = classify_entries([entry], source_cache=source_cache)  # type: ignore[arg-type]
    assert c.service == "gemini"
    assert c.artifact_kind == "unmatched"
    assert "watermarked_img id 없음" in c.evidence["reason"]


def test_matches_scope() -> None:
    clf = GeminiClassifier()
    assert clf.matches(_gen("rd-gg-dl", "1", ".jpg", "image/jpeg"))  # type: ignore[arg-type]
    # 아바타·위젯·텍스트 포인터는 매치 안 함
    assert not clf.matches(
        make_entry("https://lh3.googleusercontent.com/a/xyz=s128", content_type="image/png")
    )
    assert not clf.matches(
        make_entry(
            "https://lh3.googleusercontent.com/gg-dl/AAQ_x",
            content_type="text/plain; charset=UTF-8",
        )
    )
    assert not clf.matches(
        make_entry("https://lh3.googleusercontent.com/rd-ogw/AF2", content_type="image/png")
    )


# --- 통합 ---


def test_gemini_on_local_fixture(cache_fixture_dir: Path) -> None:
    out = classify_cache_dir(cache_fixture_dir)
    gem = [c for c in out if c.service == "gemini"]
    assert len(gem) >= 5
    assert {c.artifact_kind for c in gem} == {"generated_file"}
    ids = {c.evidence["artifact_id"] for c in gem}
    assert len(ids) >= 3
    assert any(c.evidence["paired"] for c in gem)
    assert any(not c.evidence["paired"] for c in gem)
    assert {c.evidence["variant"] for c in gem} <= {"fullres", "download"}

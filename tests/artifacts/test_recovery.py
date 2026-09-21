"""Synthetic evidence cases: attribution, byte recovery and source preservation."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import struct
import zipfile
from contextlib import closing
from dataclasses import replace

import pytest
from PIL import Image

from gentrace_forensics.artifacts.evidence import service_for
from gentrace_forensics.artifacts.formats import inspect_bytes
from gentrace_forensics.artifacts.pipeline import build_profile, verify_manifests
from gentrace_forensics.artifacts.report import write_outputs
from gentrace_forensics.artifacts.sparse import MAGIC, Span, assemble, recover_sparse
from gentrace_forensics.classification.blockfile.entry import CacheKey, HttpResponseInfo
from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry
from gentrace_forensics.classification.classify import classify_entries
from gentrace_forensics.normalization.transform import transform
from gentrace_forensics.schemas.acquisition import AcquiredCache, AcquiredFile


def entry(url, body=b"", mime="application/json", *, key=None, status=200, headers=None, **kwargs):
    return ParsedCacheEntry(
        cache_key=key or "1/0/" + url,
        url=url,
        response=HttpResponseInfo(status, {"content-type": mime, **(headers or {})}),
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        stored_body_size=len(body),
        content_encoding=None,
        source_file="f_000001",
        source_offset=0,
        entry_hash=1,
        entry_state="normal",
        **kwargs,
    )


def image_bytes(fmt="WEBP"):
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), "green").save(buffer, fmt)
    return buffer.getvalue()


@pytest.fixture
def cache():
    return AcquiredCache(
        image_path="fixture.E01",
        image_sha256="a" * 64,
        partition_offset=1024,
        windows_user="alice",
        chrome_profile="Default",
        source_path="/profile/Cache/Cache_Data",
    )


def deevid_metadata(creations):
    return entry(
        "https://api.deevid.ai/my-assets",
        json.dumps(
            {
                "data": {
                    "data": {
                        "groups": [
                            {
                                "items": [
                                    {"detail": {"creation": creation}} for creation in creations
                                ]
                            }
                        ]
                    }
                }
            }
        ).encode(),
    )


def test_deevid_candidates_and_multiple_tasks_keep_all_sources(cache, tmp_path):
    linked = "https://cdn2.deevid.ai/cdn-cgi/image/format=webp/user-image/input.jpg"
    unrelated = "https://cdn2.deevid.ai/user-image/unrelated.jpg"
    meta = deevid_metadata(
        [
            {
                "id": 1,
                "inputUserImageName": "input.jpg",
                "videoUrl": "https://cdn2.deevid.ai/user-video/one.mp4",
            },
            {"id": 2, "originalImageNameUrls": ["https://cdn2.deevid.ai/user-image/input.jpg"]},
        ]
    )
    entries = [
        meta,
        entry(linked, image_bytes(), "image/jpeg"),
        entry(unrelated, image_bytes(), "image/jpeg"),
    ]
    assets, relations = build_profile(cache, entries, tmp_path)
    uploaded = next(a for a in assets if a.asset_key == "user-image/input.jpg")
    assert uploaded.role == "upload" and uploaded.attribution == "evidence_linked"
    assert {r.subject_id for r in relations if r.artifact_id == uploaded.artifact_id} == {"1", "2"}
    assert len([s for s in uploaded.source_refs if s.json_pointer]) == 2
    file = uploaded.files[0]
    assert file.representation == "preview" and file.recovery_status == "complete"
    assert file.detected_mime == "image/webp" and file.path.endswith(".webp")
    assert (tmp_path / file.path).read_bytes() == entries[1].body
    candidate = next(a for a in assets if a.asset_key == "user-image/unrelated.jpg")
    assert candidate.role == "unknown" and candidate.attribution == "pattern_candidate"
    output = next(a for a in assets if a.asset_key == "user-video/one.mp4")
    assert output.recovery_status == "metadata_only" and output.files == []
    classified = classify_entries(entries, source_cache=cache)
    assert classified[0].artifact_kind == "conversation"
    assert all(transform(e).actor is None for e in classified)
    assert all(transform(e).event_type != "upload" for e in classified)


def test_elevenlabs_metadata_is_not_audio_and_preview_not_original(cache, tmp_path):
    metadata = {
        "voices": [
            {
                "voice_id": "voice1",
                "category": "cloned",
                "preview_url": "https://cdn.example/preview.mp3",
                "samples": [
                    {
                        "sample_id": "sample1",
                        "file_name": "input.wav",
                        "size_bytes": 99000,
                        "hash": "service-hash",
                    }
                ],
            }
        ]
    }
    assets, _ = build_profile(
        cache,
        [entry("https://api.us.elevenlabs.io/v2/voices", json.dumps(metadata).encode())],
        tmp_path,
    )
    assert len(assets) == 2 and all(a.recovery_status == "metadata_only" for a in assets)
    sample = next(a for a in assets if a.asset_key.startswith("sample:"))
    assert sample.role == "upload" and sample.files == []
    assert sample.metadata[0]["properties"]["sample"]["hash"] == "service-hash"
    preview = next(a for a in assets if a.asset_key.startswith("preview:"))
    assert preview.role == "unknown"


def test_chatgpt_roles_follow_messages_not_endpoint_and_errors_are_not_files(cache, tmp_path):
    payload = {
        "mapping": {
            "one": {
                "message": {
                    "id": "message1",
                    "author": {"role": "user"},
                    "metadata": {
                        "attachments": [
                            {"id": "file-input", "name": "input.png", "source": "local"}
                        ]
                    },
                }
            },
            "two": {
                "message": {
                    "id": "message2",
                    "author": {"role": "assistant"},
                    "content": {"parts": [{"asset_pointer": "file-service://file-output"}]},
                }
            },
        }
    }
    entries = [
        entry("https://chatgpt.com/backend-api/conversation/chat1", json.dumps(payload).encode()),
        entry(
            "https://chatgpt.com/backend-api/estuary/content?id=file-input",
            image_bytes("PNG"),
            "image/png",
        ),
        entry(
            "https://chatgpt.com/backend-api/estuary/content?id=file-output",
            b'{"detail":"File stream access denied"}',
            status=403,
        ),
    ]
    assets, links = build_profile(cache, entries, tmp_path)
    assert len(assets) == 2 and len(links) == 2
    assert next(a for a in assets if a.asset_key == "file-input").role == "upload"
    result = next(a for a in assets if a.asset_key == "file-output")
    assert result.role == "generated" and result.recovery_status == "invalid"
    assert result.files[0].representation == "metadata"


def test_voice_catalog_preview_is_not_a_user_file(cache, tmp_path):
    catalog = entry(
        "https://chatgpt.com/backend-api/voices",
        json.dumps(
            {"voices": [{"name": "Example", "preview_url": "https://cdn.example/voice.mp3"}]}
        ).encode(),
    )
    assets, links = build_profile(cache, [catalog], tmp_path)
    assert assets == [] and links == []


def test_host_spoofing_and_claude_scope_are_not_attribution(cache):
    assert service_for("https://evil.example/?url=https://claude.ai/api/x/files/y") == "unknown"
    assert service_for("https://claude.ai.evil.example/api/x/files/y") == "unknown"
    classified = classify_entries(
        [entry("https://claude.ai/api/scope1/files/file1", image_bytes(), "image/webp")],
        source_cache=cache,
    )[0]
    assert classified.evidence["artifact_role"] == "unknown"
    assert "conversation_id" not in classified.evidence
    assert transform(classified).session_id is None


def sparse_header(key, signature=123, *, bits=(), last=-1, length=0, child=True):
    bitmap = bytearray(128 if child else 4)
    for bit in bits:
        bitmap[bit // 8] |= 1 << (bit % 8)
    return (
        struct.pack("<qIiii10i", signature, MAGIC, len(key.encode()), last, length, *([0] * 10))
        + bitmap
    )


def sparse_pair(body, *, bits=(0,), last=-1, length=0, total=None, signature=123):
    url = "https://cdn2.deevid.ai/user-video/output.mp4"
    key = "1/0/" + url
    parent = entry(
        url,
        key=key,
        status=206,
        headers={"content-range": f"bytes 0-0/{total or len(body)}"},
        entry_flags=1,
        sparse_data=sparse_header(key, child=False, bits=(0,)),
    )
    child = entry(
        url,
        body,
        key=f"Range_{key}:{signature:x}:0",
        status=None,
        entry_flags=2,
        sparse_data=sparse_header(key, signature, bits=bits, last=last, length=length),
    )
    return parent, child


def test_sparse_bitmap_holes_partial_tail_and_minus_one_sentinel():
    body = b"a" * 1024 + b"b" * 1024 + b"c" * 50
    parent, child = sparse_pair(body, bits=(0, 1), last=2, length=50)
    result = recover_sparse([parent, child])[parent.cache_key]
    assert result.body == body and result.coverage == [(0, len(body))]
    _, hole = sparse_pair(body, bits=(0,), last=2, length=50)
    result = recover_sparse([parent, hole])[parent.cache_key]
    assert result.body is None and result.coverage == [(0, 1024), (2048, 2098)]
    parent, child = sparse_pair(b"a" * 1024, length=500)
    assert recover_sparse([parent, child])[parent.cache_key].body == b"a" * 1024


def test_sparse_wrong_generation_and_truncated_allocation_not_complete():
    parent, child = sparse_pair(b"a" * 1024, signature=456)
    result = recover_sparse([parent, child])[parent.cache_key]
    assert result.body is None and "stale" in result.warnings[0]
    parent, child = sparse_pair(b"a" * 100)
    result = recover_sparse([parent, child])[parent.cache_key]
    assert result.body is None and result.errors


def test_sparse_hex_id_and_overlap_conflict():
    key = "Range_1/0/https://example.test/file.mp4:abc123:a"
    assert CacheKey(key).url == "https://example.test/file.mp4"
    assert CacheKey("https://example.test/a:abc123:a").url.endswith(":abc123:a")
    assert assemble([Span(0, b"abcd", "a", 0), Span(2, b"cd", "b", 0)], 4)[0] == b"abcd"
    data, _, errors = assemble([Span(0, b"abcd", "a", 0), Span(2, b"XX", "b", 0)], 4)
    assert data is None and errors == ["conflicting overlapping bytes"]


def test_sparse_complete_image_decodes_partial_never_masquerades(cache, tmp_path):
    data = image_bytes("PNG")
    parent, child = sparse_pair(data, bits=(), last=0, length=len(data))
    assets, _ = build_profile(cache, [parent, child], tmp_path)
    file = assets[0].files[0]
    assert file.recovery_status == "complete" and file.path.endswith(".png")
    assert (tmp_path / file.path).read_bytes() == data and file.ranges[0]["start"] == 0
    parent = replace(parent, response=HttpResponseInfo(206, {"content-range": "bytes 0-0/10000"}))
    assets, _ = build_profile(cache, [parent, child], tmp_path / "partial-case")
    assert assets[0].files[0].recovery_status == "partial"
    assert assets[0].files[0].path.endswith(".bin")


def test_truncated_image_and_mislabeled_docx():
    assert inspect_bytes(image_bytes("PNG")[:40]).status == "invalid"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("arbitrary.txt", "not a Word document")
    assert inspect_bytes(archive.getvalue()).extension == "zip"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(
            "[Content_Types].xml",
            '<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        output.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
        )
        output.writestr("_rels/.rels", "<Relationships/>")
    assert inspect_bytes(archive.getvalue()).extension == "docx"


def test_integrity_verification_rejects_modified_sources(cache, tmp_path):
    root = tmp_path / "Cache" / "Cache_Data"
    root.mkdir(parents=True)
    (root / "index").write_bytes(b"original")
    cache.files = [
        AcquiredFile(
            relative_path="index",
            local_path=root / "index",
            size=8,
            sha256=hashlib.sha256(b"original").hexdigest(),
        )
    ]
    manifest = tmp_path / "acquired.json"
    manifest.write_text(cache.model_dump_json())
    assert verify_manifests([manifest])
    (root / "index").write_bytes(b"modified")
    with pytest.raises(ValueError, match="integrity"):
        verify_manifests([manifest])


def test_report_escapes_evidence_and_sqlite_retains_relationships(cache, tmp_path):
    meta = deevid_metadata([{"id": 1, "inputUserImageName": '<script>alert("x")</script>.jpg'}])
    assets, links = build_profile(cache, [meta], tmp_path)
    summary = {"cache_entry_count": 1, "validated_media_files": 0, "network": []}
    write_outputs(tmp_path, assets, links, [], summary)
    report = (tmp_path / "report" / "index.html").read_text()
    assert '<script>alert("x")</script>' not in report and "&lt;script&gt;" in report
    with closing(sqlite3.connect(tmp_path / "artifacts.sqlite3")) as db:
        assert db.execute("SELECT count(*) FROM relationships").fetchone()[0] == 1
        assert db.execute("SELECT role FROM artifacts").fetchone()[0] == "upload"
    with pytest.raises(FileExistsError):
        write_outputs(tmp_path, assets, links, [], summary)


def test_video_full_decode_and_sparse_reassembly(cache, tmp_path):
    import subprocess

    from gentrace_forensics.artifacts.formats import _ffmpeg

    executable = _ffmpeg()
    assert executable, "bundled media decoder is required"
    path = tmp_path / "synthetic.mp4"
    subprocess.run(
        [
            executable,
            "-nostdin",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:s=32x32:r=2:d=1",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            str(path),
        ],
        check=True,
        timeout=30,
    )
    body = path.read_bytes()
    result = inspect_bytes(body)
    assert result.status == "valid" and result.details["method"] == "full_media_decode"
    assert inspect_bytes(body[:-50]).status == "invalid"
    blocks, tail = divmod(len(body), 1024)
    parent, child = sparse_pair(body, bits=tuple(range(blocks)), last=blocks, length=tail)
    assets, _ = build_profile(cache, [parent, child], tmp_path / "result")
    recovered = assets[0].files[0]
    assert recovered.recovery_status == "complete"
    assert recovered.sha256 == hashlib.sha256(body).hexdigest()


def test_decoder_unavailable_does_not_claim_complete(monkeypatch):
    from gentrace_forensics.artifacts import formats

    monkeypatch.setattr(formats, "_ffmpeg", lambda: None)
    result = formats.inspect_bytes(b"ID3" + b"\x00" * 100)
    assert result.status == "unverified"


def test_gemini_text_pointer_links_local_image_without_counting_pointer_as_image(cache, tmp_path):
    url = "https://lh3.googleusercontent.com/rd-gg-dl/image1"
    image = entry(
        url,
        image_bytes("PNG"),
        "image/png",
        headers={"content-disposition": 'attachment; filename="watermarked_img_123.png"'},
    )
    pointer = entry("https://lh3.googleusercontent.com/rd-gg/pointer1", url.encode(), "text/plain")
    assets, _ = build_profile(cache, [pointer, image], tmp_path)
    assert len(assets) == 1 and assets[0].role == "unknown"
    assert {f.recovery_status for f in assets[0].files} == {"metadata_only", "complete"}
    assert {f.detected_mime for f in assets[0].files} == {"text/uri-list", "image/png"}


def test_claude_encoded_output_query_is_retained_as_candidate(cache, tmp_path):
    from urllib.parse import quote

    url = "https://claude.ai/api/scope/download?path=" + quote(
        "/mnt/user-data/outputs/file.doc", safe=""
    )
    assets, _ = build_profile(
        cache, [entry(url, b"not actually a document", "application/octet-stream")], tmp_path
    )
    assert len(assets) == 1 and assets[0].role == "unknown"
    assert assets[0].files[0].recovery_status == "unverified"
    assert assets[0].files[0].path.endswith(".bin")

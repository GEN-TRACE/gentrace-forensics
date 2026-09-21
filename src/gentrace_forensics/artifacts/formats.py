"""Byte-based format identification and bounded, offline file validation."""

from __future__ import annotations

import io
import json
import shutil
import struct
import subprocess  # nosec B404
import tempfile
import warnings
import wave
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from PIL import Image


@dataclass
class FormatResult:
    mime: str = "application/octet-stream"
    extension: str = "bin"
    status: str = "unverified"
    details: dict[str, Any] = field(default_factory=dict)


def _ffmpeg() -> str | None:
    executable = shutil.which("ffmpeg")
    if executable:
        return executable
    try:
        import imageio_ffmpeg

        return str(imageio_ffmpeg.get_ffmpeg_exe())
    except (ImportError, RuntimeError, OSError):
        return None


def _decode_media(body: bytes, result: FormatResult) -> FormatResult:
    executable = _ffmpeg()
    if not executable:
        result.details["reason"] = "media decoder unavailable"
        return result
    with tempfile.TemporaryDirectory(prefix="gentrace-decode-") as tmp:
        source = Path(tmp) / ("media." + result.extension)
        source.write_bytes(body)
        # Only local file/pipe protocols; no playlist or remote-resource access.
        try:
            run = subprocess.run(  # nosec B603
                [
                    executable,
                    "-nostdin",
                    "-v",
                    "error",
                    "-xerror",
                    "-threads",
                    "1",
                    "-protocol_whitelist",
                    "file,pipe",
                    "-i",
                    str(source),
                    "-map",
                    "0:v?",
                    "-map",
                    "0:a?",
                    "-f",
                    "null",
                    "-",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.details["reason"] = "media decoder timeout"
            return result
        except OSError as exc:
            result.details["reason"] = str(exc)
            return result
    result.status = "valid" if run.returncode == 0 else "invalid"
    result.details.update(method="full_media_decode", decoder="ffmpeg", exit_code=run.returncode)
    if run.stderr:
        result.details["diagnostic"] = run.stderr.decode("utf-8", "replace")[:2000]
    return result


def _mp4_structure(body: bytes) -> bool:
    offset = 0
    types: set[bytes] = set()
    while offset + 8 <= len(body):
        size, kind = struct.unpack_from(">I4s", body, offset)
        header = 8
        if size == 1:
            if offset + 16 > len(body):
                return False
            size = struct.unpack_from(">Q", body, offset + 8)[0]
            header = 16
        elif size == 0:
            size = len(body) - offset
        if size < header or offset + size > len(body):
            return False
        types.add(kind)
        offset += size
    return offset == len(body) and {b"ftyp", b"moov", b"mdat"} <= types


def inspect_bytes(body: bytes) -> FormatResult:
    if not body:
        return FormatResult(status="invalid", details={"reason": "empty body"})
    image_signature = (
        body.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a"))
        or body[:4] == b"RIFF"
        and body[8:12] == b"WEBP"
    )
    if image_signature:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(body)) as picture:
                    fmt = picture.format or ""
                    size = picture.size
                    picture.verify()
                with Image.open(io.BytesIO(body)) as picture:
                    for frame in range(getattr(picture, "n_frames", 1)):
                        picture.seek(frame)
                        picture.load()
            mime, extension = {
                "JPEG": ("image/jpeg", "jpg"),
                "PNG": ("image/png", "png"),
                "WEBP": ("image/webp", "webp"),
                "GIF": ("image/gif", "gif"),
            }[fmt]
            return FormatResult(
                mime,
                extension,
                "valid",
                {"method": "image_decode", "width": size[0], "height": size[1]},
            )
        except (
            OSError,
            ValueError,
            SyntaxError,
            KeyError,
            Image.DecompressionBombError,
            Image.DecompressionBombWarning,
        ) as exc:
            return FormatResult(
                status="invalid", details={"reason": str(exc), "method": "image_decode"}
            )
    if body[:4] == b"RIFF" and body[8:12] == b"WAVE":
        result = FormatResult("audio/wav", "wav")
        try:
            with wave.open(io.BytesIO(body)) as audio:
                expected = audio.getnframes() * audio.getnchannels() * audio.getsampwidth()
                actual = len(audio.readframes(audio.getnframes()))
                if expected != actual or int.from_bytes(body[4:8], "little") + 8 != len(body):
                    raise ValueError("truncated or inconsistent WAV")
                result.status = "valid"
                result.details = {
                    "method": "pcm_decode",
                    "frames": audio.getnframes(),
                    "sample_rate": audio.getframerate(),
                }
        except (wave.Error, EOFError, ValueError) as exc:
            result.status = "invalid"
            result.details["reason"] = str(exc)
        return result
    if len(body) >= 12 and body[4:8] == b"ftyp":
        result = FormatResult("video/mp4", "mp4")
        if not _mp4_structure(body):
            result.status = "invalid"
            result.details["reason"] = "incomplete MP4 box structure"
            return result
        return _decode_media(body, result)
    if body.startswith(b"ID3") or len(body) > 2 and body[0] == 255 and body[1] & 0xE0 == 0xE0:
        return _decode_media(body, FormatResult("audio/mpeg", "mp3"))
    if body.startswith(b"OggS"):
        return _decode_media(body, FormatResult("application/ogg", "ogg"))
    if body.startswith(b"fLaC"):
        return _decode_media(body, FormatResult("audio/flac", "flac"))
    if body.startswith(b"\x1aE\xdf\xa3"):
        return _decode_media(body, FormatResult("video/webm", "webm"))
    if body.startswith(b"PK\x03\x04"):
        result = FormatResult("application/zip", "zip")
        try:
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                if sum(info.file_size for info in archive.infolist()) > 128 * 1024 * 1024:
                    result.details["reason"] = "expanded document exceeds validation limit"
                    return result
                if archive.testzip() is not None:
                    raise ValueError("ZIP CRC mismatch")
                names = set(archive.namelist())
                if {"[Content_Types].xml", "word/document.xml", "_rels/.rels"} <= names:
                    content = archive.read("[Content_Types].xml")
                    document = archive.read("word/document.xml")
                    if b"<!DOCTYPE" in content or b"<!DOCTYPE" in document:
                        raise ValueError("unsupported XML DTD")
                    root = ElementTree.fromstring(content, forbid_dtd=True)
                    main = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
                    if any(
                        node.get("PartName") == "/word/document.xml"
                        and node.get("ContentType") == main
                        for node in root
                    ):
                        doc = ElementTree.fromstring(document, forbid_dtd=True)
                        if (
                            doc.tag
                            != "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}document"
                        ):
                            raise ValueError("unexpected Word document root")
                        result.mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        result.extension = "docx"
                result.status = "valid"
                result.details["method"] = "zip_crc_and_document_structure"
        except (
            zipfile.BadZipFile,
            ValueError,
            RuntimeError,
            ElementTree.ParseError,
            DefusedXmlException,
        ) as exc:
            result.status = "invalid"
            result.details["reason"] = str(exc)
        return result
    if body.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return FormatResult(
            "application/x-ole-storage",
            "ole",
            details={"reason": "OLE signature only; application type unverified"},
        )
    if body.startswith(b"%PDF-"):
        return FormatResult(
            "application/pdf", "pdf", details={"reason": "PDF signature only; rendering unverified"}
        )
    if body.startswith(b"{\\rtf"):
        return FormatResult(
            "application/rtf", "rtf", details={"reason": "RTF signature only; rendering unverified"}
        )
    if len(body) < 16384:
        try:
            value = body.decode("utf-8").strip()
            parsed = urlsplit(value)
            if (
                parsed.scheme in {"http", "https"}
                and parsed.hostname
                and not any(c.isspace() for c in value)
            ):
                return FormatResult("text/uri-list", "txt", "valid", {"method": "url_reference"})
        except (UnicodeError, ValueError):
            pass
    if body.lstrip().startswith((b"{", b"[")):
        try:
            json.loads(body)
            return FormatResult("application/json", "json", "valid", {"method": "json_parse"})
        except (ValueError, UnicodeError, RecursionError):
            pass
    return FormatResult(details={"reason": "unrecognized byte format"})

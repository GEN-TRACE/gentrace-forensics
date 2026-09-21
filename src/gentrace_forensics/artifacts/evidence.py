"""Service evidence extraction. JSON objects retain their own pointers and associations."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlsplit

from gentrace_forensics.artifacts.models import Representation, Role
from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry


def service_for(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    for domain, service in (
        ("deevid.ai", "veo3"),
        ("elevenlabs.io", "elevenlabs"),
        ("chatgpt.com", "chatgpt"),
        ("claude.ai", "claude"),
        ("gemini.google.com", "gemini"),
    ):
        if host == domain or host.endswith("." + domain):
            return service
    if host in {"lh3.googleusercontent.com", "lh3.google.com"} and re.match(
        r"/rd-gg(?:-dl)?/", urlsplit(url).path
    ):
        return "gemini"
    return "unknown"


def walk(value: Any, pointer: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        yield pointer, value
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from walk(child, f"{pointer}/{escaped}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{pointer}/{index}")


def text(value: Any) -> str | None:
    return str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else None


def asset_key(service: str, url: str, filename: str = "") -> str:
    parsed = urlsplit(url)
    path = unquote(parsed.path)
    if service == "veo3":
        match = re.search(r"/(user-image|user-video)/([^/]+)", path)
        if match:
            return match.group(1) + "/" + match.group(2)
    if service == "chatgpt":
        query = parse_qs(parsed.query)
        file_id = (query.get("id") or query.get("file_id") or [""])[0]
        if file_id:
            return file_id
    if service == "elevenlabs":
        match = re.search(r"/voices/([^/]+)/samples/([^/]+)", path)
        if match:
            return "sample:" + match.group(1) + ":" + match.group(2)
        match = re.search(r"/history/([^/]+)/audio(?:/|$)", path)
        if match:
            return "history:" + match.group(1)
    if service == "claude":
        match = re.search(r"/files/([^/]+)", path)
        if match:
            return match.group(1)
    if service == "gemini":
        match = re.search(r"watermarked_img_(\d+)", filename)
        if match:
            return "watermarked:" + match.group(1)
    # Query parameters can identify different objects; never drop them wholesale.
    return "url:" + hashlib.sha256(url.encode()).hexdigest()


@dataclass
class Reference:
    service: str
    key: str
    entry_key: str
    pointer: str
    role: Role = "unknown"
    representation: Representation = "unknown"
    urls: list[str] = field(default_factory=list)
    name: str | None = None
    subject: str | None = None
    relation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    rule: str = "structured_file_reference"


def _deevid(entry: ParsedCacheEntry, data: Any) -> Iterator[Reference]:
    for pointer, obj in walk(data):
        creation = obj.get("creation")
        if not isinstance(creation, dict):
            continue
        base = pointer + "/creation"
        subject = text(creation.get("id"))
        meta = {
            key: creation[key]
            for key in (
                "id",
                "type",
                "taskState",
                "prompt",
                "lengthOfSecond",
                "createTimestamp",
                "inputUserImageId",
                "inputUserImageName",
            )
            if key in creation
        }
        fields = (
            ("videoUrl", "generated", "original", "output", "user-video"),
            ("noWaterMarkVideoUrl", "generated", "original", "output", "user-video"),
            ("originalImageNameUrls", "upload", "original", "input", "user-image"),
            ("inputUserImageName", "upload", "original", "input", "user-image"),
            ("resultVideoCoverImageName", "unknown", "cover", "preview", "user-image"),
        )
        for name, role, representation, relation, folder in fields:
            value = creation.get(name)
            values = value if isinstance(value, list) else [value]
            for index, item in enumerate(values):
                if not isinstance(item, str) or not item:
                    continue
                is_url = item.startswith(("https://", "http://"))
                if is_url and service_for(item) != "veo3":
                    continue
                key = asset_key("veo3", item) if is_url else folder + "/" + item.rsplit("/", 1)[-1]
                yield Reference(
                    "veo3",
                    key,
                    entry.cache_key,
                    base + "/" + name + (f"/{index}" if isinstance(value, list) else ""),
                    role=cast(Role, role),
                    representation=cast(Representation, representation),
                    urls=[item] if is_url else [],
                    name=item.rsplit("/", 1)[-1].split("?")[0],
                    subject=subject,
                    relation=relation,
                    metadata=meta,  # type: ignore[arg-type]
                )


def _elevenlabs(entry: ParsedCacheEntry, data: Any) -> Iterator[Reference]:
    for pointer, obj in walk(data):
        voice_id = text(obj.get("voice_id"))
        if voice_id and "samples" in obj:
            samples = obj.get("samples")
            for index, sample in enumerate(samples if isinstance(samples, list) else []):
                if not isinstance(sample, dict) or not text(sample.get("sample_id")):
                    continue
                sample_id = str(sample["sample_id"])
                # Only cloning voice metadata establishes an input role.
                role: Role = (
                    "upload" if obj.get("category") in {"cloned", "professional"} else "unknown"
                )
                yield Reference(
                    "elevenlabs",
                    f"sample:{voice_id}:{sample_id}",
                    entry.cache_key,
                    f"{pointer}/samples/{index}",
                    role=role,
                    representation="original",
                    name=text(sample.get("file_name") or sample.get("name")),
                    subject=voice_id,
                    relation="sample",
                    metadata={
                        "sample": sample,
                        "voice_id": voice_id,
                        "voice_name": obj.get("name"),
                        "category": obj.get("category"),
                    },
                )
        if voice_id and isinstance(obj.get("preview_url"), str):
            url = obj["preview_url"]
            yield Reference(
                "elevenlabs",
                "preview:" + voice_id,
                entry.cache_key,
                pointer + "/preview_url",
                representation="preview",
                urls=[url],
                subject=voice_id,
                relation="preview",
                metadata={"voice_id": voice_id, "category": obj.get("category")},
            )
        history_id = text(obj.get("history_item_id"))
        if history_id:
            yield Reference(
                "elevenlabs",
                "history:" + history_id,
                entry.cache_key,
                pointer,
                role="generated",
                representation="original",
                subject=history_id,
                relation="history",
                metadata={
                    key: obj[key]
                    for key in (
                        "history_item_id",
                        "request_id",
                        "voice_id",
                        "voice_name",
                        "model_id",
                        "date_unix",
                        "text",
                        "content_type",
                        "state",
                    )
                    if key in obj
                },
            )


def _chat_files(entry: ParsedCacheEntry, data: Any, service: str) -> Iterator[Reference]:
    def visit(
        value: Any, pointer: str, author: str | None, subject: str | None
    ) -> Iterator[Reference]:
        if isinstance(value, list):
            for i, item in enumerate(value):
                yield from visit(item, f"{pointer}/{i}", author, subject)
        if not isinstance(value, dict):
            return
        current_author = value.get("author")
        if isinstance(current_author, dict):
            author = text(current_author.get("role")) or author
        author = text(value.get("sender")) or author
        if "message" in value or "author" in value or "sender" in value:
            subject = text(value.get("id") or value.get("uuid")) or subject
        ids = [value.get("file_id"), value.get("asset_pointer")]
        attachment = any(
            part in pointer.split("/") for part in ("attachments", "user_attachments", "files")
        )
        if attachment:
            ids.append(value.get("id") or value.get("uuid"))
        urls = [
            value[key] for key in ("download_url", "preview_url") if isinstance(value.get(key), str)
        ]
        file_ids = [
            item.removeprefix("file-service://") for item in ids if isinstance(item, str) and item
        ]
        if file_ids or urls:
            key = file_ids[0] if file_ids else asset_key(service, urls[0])
            role: Role = "unknown"
            if author in {"user", "human"} and (
                attachment or value.get("source") == "local" or file_ids
            ):
                role = "upload"
            elif author == "assistant":
                role = "generated"
            representation: Representation = (
                "preview" if "preview_url" in value and "download_url" not in value else "unknown"
            )
            yield Reference(
                service,
                key,
                entry.cache_key,
                pointer,
                role=role,
                representation=representation,
                urls=urls,
                name=text(value.get("file_name") or value.get("name")),
                subject=subject,
                relation="input" if role == "upload" else "output" if role == "generated" else None,
                metadata={
                    k: value[k]
                    for k in (
                        "file_id",
                        "asset_pointer",
                        "source",
                        "file_name",
                        "file_size_bytes",
                        "mime_type",
                    )
                    if k in value
                },
            )
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from visit(child, pointer + "/" + escaped, author, subject)

    yield from visit(data, "", None, None)


def extract_references(entries: Sequence[ParsedCacheEntry]) -> list[Reference]:
    result: list[Reference] = []
    by_url = {entry.url: entry for entry in entries}
    for entry in entries:
        service = service_for(entry.url)
        if service == "unknown" or not entry.body or entry.response.status not in {200, 201}:
            continue
        if service == "gemini" and len(entry.body) < 16384:
            try:
                target = entry.body.decode("utf-8").strip()
                if service_for(target) == "gemini" and not any(c.isspace() for c in target):
                    target_entry = by_url.get(target)
                    key = asset_key("gemini", target, target_entry.filename if target_entry else "")
                    result.append(
                        Reference(
                            "gemini",
                            key,
                            entry.cache_key,
                            "",
                            urls=[entry.url, target],
                            metadata={"target_url": target},
                            rule="text_url_reference",
                        )
                    )
                    continue
            except (UnicodeError, ValueError):
                pass
        if len(entry.body) > 32 * 1024 * 1024:
            continue
        try:
            data = json.loads(entry.body)
        except (ValueError, UnicodeError, RecursionError):
            continue
        path = urlsplit(entry.url).path
        if service == "veo3" and path.rstrip("/") == "/my-assets":
            result.extend(_deevid(entry, data))
        elif service == "elevenlabs" and re.match(r"/v[12]/(?:voices|history)(?:/|$)", path):
            result.extend(_elevenlabs(entry, data))
        elif (
            service in {"chatgpt", "claude"}
            and "/api" in path
            or service == "chatgpt"
            and "/backend-api/" in path
        ):
            result.extend(_chat_files(entry, data, service))
    return result


def candidate(entry: ParsedCacheEntry) -> tuple[str, str, Representation] | None:
    service = service_for(entry.url)
    path = unquote(urlsplit(entry.url).path)
    representation: Representation = "unknown"
    if service == "veo3":
        if not re.search(r"/(user-image|user-video)/", path):
            return None
        if "v2_rs-image-cover-" in path:
            representation = "cover"
        elif "/cdn-cgi/image/" in path:
            representation = "preview"
    elif service == "gemini":
        if not re.match(r"/rd-gg(?:-dl)?/", path):
            return None
    elif service == "chatgpt":
        if not path.startswith("/backend-api/estuary/content"):
            return None
    elif service == "claude":
        decoded_target = unquote(entry.url)
        if "/files/" not in path and "/mnt/user-data/outputs/" not in decoded_target:
            return None
        if "preview" in entry.filename.lower():
            representation = "preview"
    elif service == "elevenlabs":
        if not re.search(r"/voices/[^/]+/samples/|/history/[^/]+/audio", path):
            return None
    else:
        return None
    return service, asset_key(service, entry.url, entry.filename), representation


class EvidenceIndex:
    """One profile's structured references; aliases retain all matching claims."""

    def __init__(self, entries: Sequence[ParsedCacheEntry]) -> None:
        self.references = extract_references(entries)
        self.by_asset: dict[tuple[str, str], list[Reference]] = {}
        self.by_url: dict[str, list[Reference]] = {}
        self.by_entry: dict[str, list[Reference]] = {}
        for ref in self.references:
            self.by_asset.setdefault((ref.service, ref.key), []).append(ref)
            self.by_entry.setdefault(ref.entry_key, []).append(ref)
            for url in ref.urls:
                self.by_url.setdefault(url, []).append(ref)

    def for_entry(self, entry: ParsedCacheEntry) -> list[Reference]:
        matched = candidate(entry)
        matches = list(self.by_url.get(entry.url, []))
        if matched:
            matches.extend(self.by_asset.get((matched[0], matched[1]), []))
        return matches

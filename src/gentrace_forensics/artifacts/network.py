"""Network Persistent State observations, deliberately separate from activity events."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from gentrace_forensics.artifacts.evidence import service_for, walk
from gentrace_forensics.artifacts.models import NetworkRecord, SourceRef
from gentrace_forensics.classification.classify import _cache_id
from gentrace_forensics.normalization.time import from_unix, from_webkit, to_iso8601
from gentrace_forensics.schemas.acquisition import AcquiredCache, AcquiredFile


def read_network(
    manifest: Path, cache: AcquiredCache
) -> tuple[list[NetworkRecord], dict[str, Any]]:
    sidecar = manifest.parent / "network_acquired.json"
    if not sidecar.is_file():
        return [], {"profile_id": _cache_id(cache), "status": "not_collected"}
    acquired = json.loads(sidecar.read_bytes())
    records: list[NetworkRecord] = []
    errors: list[str] = []
    for item in acquired.get("files", []):
        source_file = AcquiredFile.model_validate(item["file"])
        path = manifest.parent / source_file.relative_path
        if not path.resolve().is_relative_to(manifest.parent.resolve()):
            raise ValueError("network source path escapes profile")
        body = path.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        if len(body) != source_file.size or digest != source_file.sha256:
            raise ValueError("network source integrity mismatch")
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError, RecursionError) as exc:
            errors.append(f"{source_file.relative_path}: {exc}")
            continue
        for pointer, obj in walk(data):
            is_server = (
                "server" in obj or "anonymization" in obj or "network_anonymization_key" in obj
            )
            is_broken = "broken_until" in obj or "broken_count" in obj
            if not is_server and not is_broken:
                continue
            server = obj.get("server") or obj.get("host") or ""
            url = str(server) if "://" in str(server) else "https://" + str(server)
            profile = _cache_id(cache)
            identity = f"{profile}:{source_file.relative_path}:{pointer}"
            sid = hashlib.sha256(identity.encode()).hexdigest()
            times: dict[str, Any] = {}
            for location, nested in walk(obj, pointer):
                for key, convert, meaning in (
                    ("expiration", from_webkit, "alternative_service_expiration"),
                    ("broken_until", from_unix, "retry_after"),
                ):
                    if key not in nested:
                        continue
                    raw = nested[key]
                    try:
                        converted = (
                            to_iso8601(convert(int(raw))) if not isinstance(raw, bool) else None
                        )
                    except (ValueError, TypeError, OverflowError):
                        converted = None
                    times[location + "/" + key] = {"raw": raw, "utc": converted, "meaning": meaning}
            ref = SourceRef(
                source_id=sid,
                profile_id=profile,
                image_path=cache.image_path,
                image_sha256=cache.image_sha256,
                partition_offset=cache.partition_offset,
                windows_user=cache.windows_user,
                chrome_profile=cache.chrome_profile,
                cache_path=item["source_path"],
                source_file=source_file.relative_path,
                source_file_sha256=digest,
                source_offset=0,
                json_pointer=pointer,
            )
            records.append(
                NetworkRecord(
                    record_id=sid,
                    profile_id=profile,
                    service=service_for(url),
                    record_type="broken_alternative_service" if is_broken else "server_state",
                    source_ref=ref,
                    properties=obj,
                    times=times,
                )
            )
    status = "parse_error" if errors else acquired.get("status", "not_found")
    return records, {
        "profile_id": _cache_id(cache),
        "status": status,
        "record_count": len(records),
        "errors": errors,
    }

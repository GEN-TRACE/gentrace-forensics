"""Build evidence-linked assets and validated local representations from acquired caches."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any, cast

from gentrace_forensics.artifacts.evidence import (
    candidate,
    extract_references,
)
from gentrace_forensics.artifacts.formats import FormatResult, inspect_bytes
from gentrace_forensics.artifacts.models import (
    Artifact,
    RecoveredFile,
    Relationship,
    Representation,
    Role,
    SourceRef,
)
from gentrace_forensics.artifacts.network import read_network
from gentrace_forensics.artifacts.sparse import (
    CHILD_KEY,
    CONTENT_RANGE,
    SparseResult,
    recover_sparse,
)
from gentrace_forensics.classification.blockfile.parser import ParsedCacheEntry, parse_cache_dir
from gentrace_forensics.classification.classify import _cache_id, _entry_id
from gentrace_forensics.normalization.time import from_unix, from_webkit, to_iso8601
from gentrace_forensics.schemas.acquisition import AcquiredCache


def digest_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_manifests(manifests: list[Path]) -> list[tuple[Path, AcquiredCache]]:
    if not manifests or len({p.resolve() for p in manifests}) != len(manifests):
        raise ValueError("provide distinct acquired manifests")
    verified: list[tuple[Path, AcquiredCache]] = []
    profiles: set[str] = set()
    for manifest in manifests:
        cache = AcquiredCache.model_validate_json(manifest.read_bytes())
        profile = _cache_id(cache)
        if profile in profiles:
            raise ValueError("duplicate profile identity")
        profiles.add(profile)
        root = manifest.parent / "Cache" / "Cache_Data"
        expected: set[str] = set()
        for item in cache.files:
            path = root / item.relative_path
            if Path(item.relative_path).name != item.relative_path or path.is_symlink():
                raise ValueError("unsafe acquired cache filename")
            if item.relative_path in expected:
                raise ValueError("duplicate acquired filename")
            expected.add(item.relative_path)
            if path.stat().st_size != item.size or digest_file(path) != item.sha256:
                raise ValueError(f"acquired source integrity mismatch: {path}")
        if cache.files:
            actual = {p.name for p in root.iterdir() if p.is_file()}
            if actual != expected:
                raise ValueError("cache directory differs from acquired manifest")
        elif not (manifest.parent / "network_acquired.json").is_file():
            raise ValueError("manifest contains no verifiable acquired files")
        read_network(manifest, cache)  # integrity checked before any analysis output
        verified.append((manifest, cache))
    return verified


def source_ref(
    cache: AcquiredCache, entry: ParsedCacheEntry, pointer: str | None = None
) -> SourceRef:
    profile = _cache_id(cache)
    sid = hashlib.sha256(f"{profile}:{entry.cache_key}:{pointer}".encode()).hexdigest()
    source_hash = next(
        (f.sha256 for f in cache.files if f.relative_path == entry.source_file), None
    )
    return SourceRef(
        source_id=sid,
        profile_id=profile,
        image_path=cache.image_path,
        image_sha256=cache.image_sha256,
        partition_offset=cache.partition_offset,
        windows_user=cache.windows_user,
        chrome_profile=cache.chrome_profile,
        cache_path=cache.source_path,
        source_file=entry.source_file,
        source_file_sha256=source_hash,
        source_offset=entry.source_offset,
        entry_id=_entry_id(entry),
        cache_key=entry.cache_key,
        json_pointer=pointer,
        timestamps={
            key: {
                "raw": value,
                "utc": to_iso8601(from_webkit(value)),
                "meaning": "cache_observation",
            }
            for key, value in entry.cache_timestamps.items()
        },
        locations={
            name: {
                **location,
                "sha256": next(
                    (f.sha256 for f in cache.files if f.relative_path == location.get("file")), None
                ),
            }
            for name, location in (
                ("entry_store", entry.entry_location),
                ("response_headers", entry.response_location),
                ("sparse_index", entry.sparse_location),
            )
            if location
        },
    )


def _artifact(profile: str, service: str, key: str) -> Artifact:
    aid = hashlib.sha256(f"{profile}:{service}:{key}".encode()).hexdigest()
    return Artifact(artifact_id=aid, profile_id=profile, service=service, asset_key=key)


def _append_unique(items: list[Any], value: Any) -> None:
    if value not in items:
        items.append(value)


def _export(
    out: Path, artifact: Artifact, body: bytes, extension: str, *, partial: bool = False
) -> tuple[str, str]:
    digest = hashlib.sha256(body).hexdigest()
    path = (
        Path("partial" if partial else "files")
        / artifact.service
        / artifact.artifact_id
        / f"{digest}.{extension}"
    )
    dest = out / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        if digest_file(dest) != digest:
            raise ValueError("export content hash collision")
    else:
        with dest.open("xb") as output:
            output.write(body)
    return path.as_posix(), digest


def _recover_body(
    out: Path,
    artifact: Artifact,
    entry: ParsedCacheEntry,
    representation: str,
    source_ids: list[str],
    body: bytes,
    *,
    covered: bool = True,
    expected: int | None = None,
    formats: dict[str, FormatResult],
) -> RecoveredFile:
    digest = hashlib.sha256(body).hexdigest()
    fmt = formats.get(digest)
    if fmt is None:
        fmt = inspect_bytes(body)
        formats[digest] = fmt
    status = "complete" if fmt.status == "valid" else fmt.status
    if not covered:
        status = "partial"
    if (
        entry.warnings
        or entry.response.status is not None
        and not 200 <= entry.response.status < 300
    ):
        status = "invalid"
    if fmt.mime in {"application/json", "text/uri-list"}:
        # A JSON response to a file URL is evidence, never recovered media.
        status = "metadata_only" if entry.response.status in {200, 201} else "invalid"
        representation = "metadata"
    path, digest = _export(
        out, artifact, body, fmt.extension if covered else "bin", partial=not covered
    )
    validation = {
        "format_status": fmt.status,
        "coverage_complete": covered,
        "http_status": entry.response.status,
        "entry_discovery": entry.entry_location.get("discovery", "index"),
        "entry_allocation": entry.entry_location.get("allocation", "not_checked"),
        **fmt.details,
    }
    if entry.warnings:
        validation["parser_warnings"] = entry.warnings
    return RecoveredFile(
        representation=representation,
        recovery_status=status,  # type: ignore[arg-type]
        declared_mime=entry.content_type,
        detected_mime=fmt.mime,
        original_name=entry.filename,
        path=path,
        sha256=digest,
        size=len(body),
        expected_size=expected,
        validation=validation,
        source_ids=source_ids,
    )


def _sparse_files(
    out: Path,
    artifact: Artifact,
    parent: ParsedCacheEntry,
    result: SparseResult,
    entries: dict[str, ParsedCacheEntry],
    cache: AcquiredCache,
    formats: dict[str, FormatResult],
) -> None:
    refs = [source_ref(cache, parent)]
    ranges: list[dict[str, Any]] = []
    for span in result.spans:
        child = entries[span.entry_key]
        ref = source_ref(cache, child)
        _append_unique(refs, ref)
        ranges.append(
            {
                "start": span.start,
                "end": span.end,
                "source_id": ref.source_id,
                "stream_offset": span.source_offset,
                "source_file_offset": child.source_offset + span.source_offset,
                "entry_store": child.entry_location,
                "allocation_index": child.sparse_location,
            }
        )
    for ref in refs:
        _append_unique(artifact.source_refs, ref)
    validation = {
        "coverage": result.coverage,
        "errors": result.errors,
        "warnings": result.warnings,
        "expected_size": result.expected_size,
        "parent_allocation_index": parent.sparse_location,
    }
    if result.body is not None:
        recovered = _recover_body(
            out,
            artifact,
            parent,
            "unknown",
            [r.source_id for r in refs],
            result.body,
            expected=result.expected_size,
            formats=formats,
        )
        recovered.ranges = ranges
        recovered.validation["sparse"] = validation
        artifact.files.append(recovered)
    else:
        # Each contiguous valid span is exported independently; holes stay holes.
        for span, location in zip(result.spans, ranges, strict=True):
            path, digest = _export(out, artifact, span.data, "bin", partial=True)
            artifact.files.append(
                RecoveredFile(
                    representation="fragment",
                    recovery_status="invalid" if result.errors else "partial",
                    path=path,
                    sha256=digest,
                    size=len(span.data),
                    expected_size=result.expected_size,
                    source_ids=[location["source_id"]],
                    ranges=[location],
                    validation={"sparse": validation},
                )
            )
        if not result.spans:
            artifact.files.append(
                RecoveredFile(
                    representation="fragment",
                    recovery_status="invalid" if result.errors else "missing",
                    expected_size=result.expected_size,
                    source_ids=[r.source_id for r in refs],
                    validation={"sparse": validation},
                )
            )


def service_times(properties: dict[str, Any]) -> dict[str, Any]:
    times: dict[str, Any] = {}
    for key, unit in (("createTimestamp", "ms"), ("date_unix", "s")):
        raw = properties.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            times[key] = {
                "raw": raw,
                "utc": to_iso8601(from_unix(raw, unit=unit)),
                "meaning": "service_reported_time",
            }
    return times


def build_profile(
    cache: AcquiredCache, entries: list[ParsedCacheEntry], out: Path
) -> tuple[list[Artifact], list[Relationship]]:
    profile = _cache_id(cache)
    refs = extract_references(entries)
    by_entry = {entry.cache_key: entry for entry in entries}
    if len(by_entry) != len(entries):
        raise ValueError("ambiguous duplicate cache keys in profile")
    assets: dict[tuple[str, str], Artifact] = {}
    aliases: dict[tuple[str, str], tuple[str, str]] = {}
    relationships: list[Relationship] = []
    role_claims: dict[str, set[str]] = {}
    representation_claims: dict[str, set[str]] = {}
    formats: dict[str, FormatResult] = {}
    for ref in refs:
        identity = ref.service, ref.key
        artifact = assets.setdefault(identity, _artifact(profile, *identity))
        artifact.attribution = "evidence_linked"
        source = source_ref(
            cache,
            by_entry[ref.entry_key],
            ref.pointer if ref.rule != "text_url_reference" else None,
        )
        _append_unique(artifact.source_refs, source)
        _append_unique(
            artifact.metadata,
            {
                "source_id": source.source_id,
                "properties": ref.metadata,
                "times": service_times(ref.metadata),
            },
        )
        _append_unique(
            artifact.evidence,
            {
                "rule": ref.rule,
                "source_id": source.source_id,
                "json_pointer": ref.pointer,
                "role": ref.role,
            },
        )
        role_claims.setdefault(artifact.artifact_id, set()).add(ref.role)
        representation_claims.setdefault(artifact.artifact_id, set()).add(ref.representation)
        if ref.name:
            _append_unique(artifact.names, ref.name)
        for url in ref.urls:
            _append_unique(artifact.urls, url)
            aliases[ref.service, url] = identity
            # Explicit external preview/download URLs can be joined without fetching them.
            aliases["url", url] = identity
        if ref.subject and ref.relation:
            rel = Relationship(
                profile_id=profile,
                service=ref.service,
                subject_id=ref.subject,
                relation=ref.relation,
                artifact_id=artifact.artifact_id,  # type: ignore[arg-type]
                source_id=source.source_id,
                json_pointer=ref.pointer,
            )
            _append_unique(relationships, rel)
    sparse = recover_sparse(entries)
    for entry in entries:
        if CHILD_KEY.fullmatch(entry.cache_key):
            continue  # handled only with a validated parent generation below
        matched = candidate(entry)
        matched_identity = aliases.get(("url", entry.url))
        if matched_identity is None and matched:
            matched_identity = matched[0], matched[1]
        if matched_identity is None:
            continue
        artifact = assets.setdefault(matched_identity, _artifact(profile, *matched_identity))
        if entry.entry_location.get("discovery") == "block_scan":
            _append_unique(
                artifact.warnings,
                "Recovered outside the persisted index; block allocation is recorded in source locations. "
                "Valid file bytes do not prove the cache entry was active at acquisition.",
            )
        rep = matched[2] if matched else "unknown"
        claims = representation_claims.get(artifact.artifact_id, set())
        if rep == "unknown" and len(claims) == 1:
            rep = cast(Representation, next(iter(claims)))
        # URL transformations remain previews even when the source asset was an input.
        _append_unique(artifact.urls, entry.url)
        _append_unique(artifact.names, entry.filename)
        source = source_ref(cache, entry)
        _append_unique(artifact.source_refs, source)
        if entry.cache_key in sparse:
            _sparse_files(out, artifact, entry, sparse[entry.cache_key], by_entry, cache, formats)
            continue
        if not entry.body:
            artifact.files.append(
                RecoveredFile(
                    representation=rep, recovery_status="missing", source_ids=[source.source_id]
                )
            )
            continue
        covered = entry.response.status == 200 and not entry.warnings
        expected = None
        content_range = CONTENT_RANGE.fullmatch(entry.response.get("content-range") or "")
        if entry.response.status == 206 and content_range:
            start, end, expected = map(int, content_range.groups())
            covered = start == 0 and end + 1 == expected == len(entry.body)
        content_length = entry.response.get("content-length")
        if (
            content_length
            and content_length.isdigit()
            and entry.content_encoding in {None, "identity"}
            and int(content_length) != len(entry.body)
        ):
            covered = False
        recovered = _recover_body(
            out,
            artifact,
            entry,
            rep,
            [source.source_id],
            entry.body,
            covered=covered,
            expected=expected,
            formats=formats,
        )
        if content_range:
            recovered.ranges = [
                {
                    "start": int(content_range[1]),
                    "end": int(content_range[2]) + 1,
                    "source_id": source.source_id,
                }
            ]
        existing = next(
            (
                f
                for f in artifact.files
                if f.sha256 == recovered.sha256
                and f.representation == recovered.representation
                and f.recovery_status == recovered.recovery_status
            ),
            None,
        )
        if existing:
            _append_unique(existing.source_ids, source.source_id)
        else:
            artifact.files.append(recovered)
    # Orphans remain visible but are never treated as standalone complete videos.
    for entry in entries:
        match = CHILD_KEY.fullmatch(entry.cache_key)
        if not match or match[1] in by_entry:
            continue
        matched = candidate(entry)
        if not matched:
            continue
        identity = matched[0], matched[1]
        artifact = assets.setdefault(identity, _artifact(profile, *identity))
        source = source_ref(cache, entry)
        _append_unique(artifact.source_refs, source)
        _append_unique(artifact.urls, entry.url)
        if entry.body:
            path, digest = _export(out, artifact, entry.body, "bin", partial=True)
            artifact.files.append(
                RecoveredFile(
                    representation="fragment",
                    recovery_status="unverified",
                    path=path,
                    sha256=digest,
                    size=len(entry.body),
                    source_ids=[source.source_id],
                    validation={"reason": "sparse parent unavailable; allocation not validated"},
                )
            )
    for artifact in assets.values():
        claims = role_claims.get(artifact.artifact_id, set()) - {"unknown"}
        if len(claims) == 1:
            artifact.role = cast(Role, next(iter(claims)))
        elif len(claims) > 1:
            artifact.warnings.append("asset has both input and output roles; inspect relationships")
        statuses = {f.recovery_status for f in artifact.files}
        for state in ("complete", "partial", "unverified", "invalid", "metadata_only", "missing"):
            if state in statuses:
                artifact.recovery_status = state  # type: ignore[assignment]
                break
        if not artifact.files:
            artifact.recovery_status = "metadata_only"
    return sorted(assets.values(), key=lambda a: (a.service, a.artifact_id)), relationships


def recover_artifacts(manifests: list[Path], out: Path) -> dict[str, Any]:
    from gentrace_forensics.artifacts.store import write_outputs

    artifacts: list[Artifact] = []
    relationships: list[Relationship] = []
    network = []
    network_status = []
    counts: list[dict[str, Any]] = []
    for manifest in manifests:
        cache = AcquiredCache.model_validate_json(manifest.read_bytes())
        entries = parse_cache_dir(manifest.parent / "Cache" / "Cache_Data") if cache.files else []
        assets, links = build_profile(cache, entries, out)
        artifacts.extend(assets)
        relationships.extend(links)
        records, state = read_network(manifest, cache)
        network.extend(records)
        network_status.append(state)
        counts.append(
            {
                "profile_id": _cache_id(cache),
                "cache_entries": len(entries),
                "artifacts": len(assets),
            }
        )
    files = [f for a in artifacts for f in a.files]
    summary = {
        "schema_version": "1.0",
        "status": "complete",
        "profiles": counts,
        "cache_entry_count": sum(c["cache_entries"] for c in counts),
        "artifact_count": len(artifacts),
        "role_counts": dict(Counter(a.role for a in artifacts)),
        "attribution_counts": dict(Counter(a.attribution for a in artifacts)),
        "artifact_recovery_counts": dict(Counter(a.recovery_status for a in artifacts)),
        "representation_counts": dict(Counter(f.representation for f in files)),
        "file_recovery_counts": dict(Counter(f.recovery_status for f in files)),
        "unique_exported_files": len({f.path for f in files if f.path}),
        "validated_files": len({f.path for f in files if f.recovery_status == "complete"}),
        "validated_media_files": len(
            {
                f.path
                for f in files
                if f.recovery_status == "complete"
                and (f.detected_mime or "").startswith(("image/", "audio/", "video/"))
            }
        ),
        "network": network_status,
        "interpretation": "Artifact completeness describes local representations, not proof of an original upload or a human action.",
        "classification_accuracy": "not_scored: no independently labelled complete reference set",
    }
    write_outputs(out, artifacts, relationships, network, summary)
    return summary

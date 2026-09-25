from __future__ import annotations

import hashlib
import json

import pytest

from gentrace_forensics.artifacts.network import read_network
from gentrace_forensics.schemas.acquisition import AcquiredCache, AcquiredFile


def test_network_statuses_time_meanings_and_integrity(tmp_path):
    cache = AcquiredCache(
        image_path="fixture.E01",
        partition_offset=0,
        windows_user="alice",
        chrome_profile="Default",
        source_path="/profile/Cache/Cache_Data",
    )
    manifest = tmp_path / "acquired.json"
    assert read_network(manifest, cache)[1]["status"] == "not_collected"
    sidecar = tmp_path / "network_acquired.json"
    sidecar.write_text(json.dumps({"status": "not_found", "files": []}))
    assert read_network(manifest, cache)[1]["status"] == "not_found"
    source = tmp_path / "Network Persistent State"
    data = {
        "servers": [
            {
                "server": "https://api.us.elevenlabs.io",
                "network_anonymization_key": "partition",
                "alternative_service": [{"expiration": "13344473600000000"}],
            }
        ],
        "broken_alternative_services": [{"host": "claude.ai", "broken_until": "1700000000"}],
    }
    source.write_text(json.dumps(data))
    file = AcquiredFile(
        relative_path=source.name,
        local_path=source,
        size=source.stat().st_size,
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    sidecar.write_text(
        json.dumps(
            {
                "status": "collected",
                "files": [
                    {"source_path": "/profile/" + source.name, "file": file.model_dump(mode="json")}
                ],
            }
        )
    )
    records, state = read_network(manifest, cache)
    assert state["status"] == "collected" and len(records) == 2
    assert {r.service for r in records} == {"elevenlabs", "claude"}
    assert {t["meaning"] for r in records for t in r.times.values()} == {
        "alternative_service_expiration",
        "retry_after",
    }
    assert all("session_id" not in r.model_dump() for r in records)
    source.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        read_network(manifest, cache)

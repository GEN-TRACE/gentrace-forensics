"""시간값 → UTC ISO 8601.

Chrome/WebKit time (1601-01-01 기준 마이크로초), Unix epoch(초/밀리초),
HTTP Date 헤더 등을 datetime(tz=UTC)로 변환. 모르면 None.
"""

from __future__ import annotations

from datetime import datetime

WEBKIT_EPOCH_OFFSET_US = 11_644_473_600_000_000  # 1601→1970, 마이크로초


def from_webkit(value: int | None) -> datetime | None:
    """Chrome/WebKit microseconds since 1601-01-01 → aware UTC datetime."""
    raise NotImplementedError


def from_unix(value: float | None, *, unit: str = "s") -> datetime | None:
    """unit: 's' | 'ms' | 'us'."""
    raise NotImplementedError


def from_http_date(value: str | None) -> datetime | None:
    raise NotImplementedError


def to_iso8601(dt: datetime | None) -> str | None:
    raise NotImplementedError

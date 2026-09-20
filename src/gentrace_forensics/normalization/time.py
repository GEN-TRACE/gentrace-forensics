"""시간값 → UTC ISO 8601.

Chrome/WebKit time (1601-01-01 기준 마이크로초), Unix epoch(초/밀리초),
HTTP Date 헤더 등을 datetime(tz=UTC)로 변환. 모르면 None.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

WEBKIT_EPOCH_OFFSET_US = 11_644_473_600_000_000  # 1601→1970, 마이크로초
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

_UNIX_DIVISORS: dict[str, float] = {
    "s": 1.0,
    "ms": 1_000.0,
    "us": 1_000_000.0,
}


def from_webkit(value: int | None) -> datetime | None:
    """Chrome/WebKit microseconds since 1601-01-01 → aware UTC datetime."""
    if value is None:
        return None
    try:
        return _WEBKIT_EPOCH + timedelta(microseconds=value)
    except (OverflowError, TypeError):
        return None


def from_unix(value: float | None, *, unit: str = "s") -> datetime | None:
    """Unix epoch → aware UTC datetime. unit: 's' | 'ms' | 'us'."""
    if value is None:
        return None
    try:
        divisor = _UNIX_DIVISORS[unit]
    except KeyError as exc:
        raise ValueError(f"unsupported Unix timestamp unit: {unit!r}") from exc

    try:
        return datetime.fromtimestamp(value / divisor, tz=UTC)
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def from_http_date(value: str | None) -> datetime | None:
    """RFC 7231/9110 HTTP-date 문자열을 aware UTC datetime으로 변환."""
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def to_iso8601(dt: datetime | None) -> str | None:
    """datetime을 UTC ISO 8601 문자열(`...Z`)로 직렬화."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")

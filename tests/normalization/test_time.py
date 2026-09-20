"""시각 단위·마이크로초 정밀도·UTC 출력 검증."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from gentrace_forensics.normalization.time import from_http_date, from_unix, from_webkit, to_iso8601


def test_webkit_epoch_and_microseconds():
    assert from_webkit(11_644_473_600_000_001) == datetime(1970, 1, 1, microsecond=1, tzinfo=UTC)
    assert from_webkit(None) is None
    assert from_webkit(10**30) is None


@pytest.mark.parametrize(("value", "unit"), [(1, "s"), (1000, "ms"), (1_000_000, "us")])
def test_unix_units(value: int, unit: str):
    assert from_unix(value, unit=unit) == datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC)


def test_invalid_unix_values_and_units():
    assert from_unix(None) is None
    assert from_unix(float("nan")) is None
    assert from_unix(float("inf")) is None
    with pytest.raises(ValueError, match="unsupported"):
        from_unix(1, unit="minutes")


def test_http_date_and_iso_output_convert_to_utc():
    expected = datetime(2026, 9, 20, 0, 0, 0, tzinfo=UTC)
    assert from_http_date("Sun, 20 Sep 2026 09:00:00 +0900") == expected
    assert from_http_date("unknown") is None
    local = datetime(2026, 9, 20, 9, 0, 0, tzinfo=timezone(timedelta(hours=9)))
    assert to_iso8601(local) == "2026-09-20T00:00:00Z"

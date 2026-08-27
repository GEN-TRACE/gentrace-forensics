"""공용 pytest 픽스처.

실제 증거 데이터는 커밋하지 않는다. 여기 픽스처는 익명화된 소형 샘플
(`samples/`) 또는 인메모리로 만든 최소 데이터만 사용한다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES_DIR

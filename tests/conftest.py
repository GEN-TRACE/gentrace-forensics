"""공용 pytest 픽스처.

실제 증거 데이터는 커밋하지 않는다. 픽스처는 익명화된 소형 샘플(`samples/`),
인메모리로 만든 최소 데이터, 또는 로컬에만 있는 Chrome 캐시 폴더를 쓴다.
로컬 캐시가 없으면 해당 테스트는 skip 된다 (CI 포함).
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"

# 로컬 Chrome blockfile 캐시 픽스처를 찾을 후보 경로.
# 예은 획득 단계 산출물(또는 시나리오용 수동 배치)을 여기 두면 분류 테스트가 붙는다.
_CACHE_FIXTURE_CANDIDATES = (
    os.environ.get("GENTRACE_CACHE_FIXTURE"),
    REPO_ROOT / "Cache_Data",
    REPO_ROOT / "Cache" / "Cache_Data",
    SAMPLES_DIR / "private" / "Cache_Data",
)
_BLOCKFILE_MARKERS = ("index", "data_0", "data_1", "data_2", "data_3")


def _find_blockfile_cache() -> Path | None:
    for cand in _CACHE_FIXTURE_CANDIDATES:
        if not cand:
            continue
        p = Path(cand)
        if p.is_dir() and all((p / m).is_file() for m in _BLOCKFILE_MARKERS):
            return p
    return None


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return SAMPLES_DIR


@pytest.fixture(scope="session")
def cache_fixture_dir() -> Path:
    """로컬 Chrome blockfile 캐시 디렉터리. 없으면 테스트 skip.

    Phase 1 파서는 ccl_chromium_reader(`reference` extra)를 엔진으로 쓰므로
    ccl 미설치 시에도 skip 한다.
    """
    found = _find_blockfile_cache()
    if found is None:
        pytest.skip(
            "로컬 Chrome 캐시 픽스처 없음 (Cache_Data/ 배치 또는 GENTRACE_CACHE_FIXTURE 설정)"
        )
    if importlib.util.find_spec("ccl_chromium_reader") is None:
        pytest.skip('ccl_chromium_reader 미설치 (pip install -e ".[reference]")')
    return found

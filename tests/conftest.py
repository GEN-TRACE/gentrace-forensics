"""공용 pytest 픽스처.

실제 증거 데이터는 커밋하지 않는다. 픽스처는 익명화된 소형 샘플(`samples/`),
인메모리로 만든 최소 데이터, 또는 로컬에만 있는 Chrome 캐시 폴더를 쓴다.
로컬 캐시가 없으면 해당 테스트는 skip 된다 (CI 포함).

시나리오별로 캐시 폴더가 여러 개일 수 있다 (예: `02_Cache_Data` = Veo3·Gemini·
ElevenLabs, `01_Cache_Data` = ChatGPT·Claude). 각 시나리오는 자체 픽스처
fixture 를 쓴다.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"
_BLOCKFILE_MARKERS = ("index", "data_0", "data_1", "data_2", "data_3")


def _looks_like_blockfile_cache(path: Path) -> bool:
    return path.is_dir() and all((path / m).is_file() for m in _BLOCKFILE_MARKERS)


def _find_blockfile_cache(*candidates: Path | str | None) -> Path | None:
    for cand in candidates:
        if not cand:
            continue
        p = Path(cand)
        if _looks_like_blockfile_cache(p):
            return p
    return None


def _require_cache_fixture(*candidates: Path | str | None, description: str) -> Path:
    """후보 경로 중 첫 블록파일 캐시를 반환. 없으면 테스트 skip.

    파서 엔진(`_self_backend`)은 자체 구현이라 ccl_chromium_reader 가 없어도
    된다. ccl 이 필요한 건 참조 구현과 대조하는 교차검증 테스트뿐이며, 그 테스트가
    직접 ccl 유무를 확인한다 (tests/classification/test_blockfile_entry.py).
    """
    found = _find_blockfile_cache(*candidates)
    if found is None:
        pytest.skip(f"로컬 Chrome 캐시 픽스처 없음: {description}")
    return found


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return SAMPLES_DIR


@pytest.fixture(scope="session")
def cache_fixture_dir() -> Path:
    """기본(Veo3·Gemini·ElevenLabs 시나리오) 캐시 픽스처."""
    return _require_cache_fixture(
        os.environ.get("GENTRACE_CACHE_FIXTURE"),
        REPO_ROOT / "02_Cache_Data",
        REPO_ROOT / "Cache_Data",
        REPO_ROOT / "Cache" / "Cache_Data",
        SAMPLES_DIR / "private" / "Cache_Data",
        description="02_Cache_Data/ 또는 Cache_Data/ 배치, 또는 GENTRACE_CACHE_FIXTURE 로 지정",
    )


@pytest.fixture(scope="session")
def chatgpt_cache_fixture_dir() -> Path:
    """ChatGPT·Claude 시나리오(01_Cache_Data) 캐시 픽스처."""
    return _require_cache_fixture(
        os.environ.get("GENTRACE_CHATGPT_CACHE_FIXTURE"),
        REPO_ROOT / "01_Cache_Data",
        SAMPLES_DIR / "private" / "01_Cache_Data",
        description="01_Cache_Data/ 배치, 또는 GENTRACE_CHATGPT_CACHE_FIXTURE 로 지정",
    )

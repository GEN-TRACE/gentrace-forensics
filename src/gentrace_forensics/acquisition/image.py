"""E01 이미지 열기.

libewf-python(pyewf)로 분할 이미지(E01, E02, E03...)를 하나의 스트림으로 연다.
pytsk3가 소비할 수 있는 Img_Info 호환 핸들을 제공한다.
"""

from __future__ import annotations

import hashlib
import importlib
import re
from pathlib import Path
from types import TracebackType
from typing import Any, Self

_SEGMENT_SUFFIX = re.compile(r"^\.E(?P<token>[0-9]{2}|[A-Z]{2})$", re.IGNORECASE)
_HASH_CHUNK_SIZE = 1024 * 1024


def _segment_index(suffix: str) -> int | None:
    """EWF 세그먼트 확장자를 연속 정렬 가능한 번호로 변환한다."""
    match = _SEGMENT_SUFFIX.fullmatch(suffix)
    if match is None:
        return None

    token = match.group("token").upper()
    if token.isdigit():
        index = int(token)
        return index if 1 <= index <= 99 else None

    # 숫자 세그먼트 E01..E99 뒤에 EAA, EAB..EZZ가 이어진다.
    return 100 + (ord(token[0]) - ord("A")) * 26 + (ord(token[1]) - ord("A"))


def glob_segments(first_segment: str | Path) -> list[Path]:
    """E01 첫 세그먼트와 같은 증거 세트의 모든 세그먼트를 순서대로 반환.

    일반적인 ``E01..E99``와 확장 형식 ``EAA..EZZ``를 지원한다. 중간
    세그먼트가 빠진 불완전한 증거 세트는 조용히 열지 않고 오류로 처리한다.
    """
    requested = Path(first_segment).expanduser()
    if requested.suffix.upper() != ".E01":
        raise ValueError(f"first EWF segment must have an .E01 extension: {requested}")

    parent = requested.parent
    if not parent.is_dir():
        raise FileNotFoundError(f"EWF segment directory does not exist: {parent}")

    by_index: dict[int, Path] = {}
    for candidate in parent.iterdir():
        if not candidate.is_file() or candidate.stem.casefold() != requested.stem.casefold():
            continue
        index = _segment_index(candidate.suffix)
        if index is None:
            continue
        if index in by_index:
            raise ValueError(
                f"duplicate EWF segment number {index}: {by_index[index]} and {candidate}"
            )
        by_index[index] = candidate

    if 1 not in by_index:
        raise FileNotFoundError(f"first EWF segment does not exist: {requested}")

    highest_index = max(by_index)
    missing = [index for index in range(1, highest_index + 1) if index not in by_index]
    if missing:
        formatted = ", ".join(str(index) for index in missing)
        raise ValueError(f"incomplete EWF segment set; missing segment number(s): {formatted}")

    return [by_index[index] for index in range(1, highest_index + 1)]


def _load_native_modules() -> tuple[Any, Any]:
    """획득 optional 의존성을 실제 E01 사용 시점에 불러온다."""
    try:
        pyewf = importlib.import_module("pyewf")
        pytsk3 = importlib.import_module("pytsk3")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            'E01 acquisition requires pyewf and pytsk3; install with ".[acquisition]"'
        ) from exc
    return pyewf, pytsk3


def open_ewf(first_segment: str | Path) -> Any:
    """분할 EWF를 열어 ``pytsk3.Img_Info`` 호환 객체로 반환한다."""
    segments = glob_segments(first_segment)
    pyewf, pytsk3 = _load_native_modules()
    ewf_handle = pyewf.handle()

    try:
        ewf_handle.open([str(segment) for segment in segments])
    except Exception:
        ewf_handle.close()
        raise

    class EwfImgInfo(pytsk3.Img_Info):  # type: ignore[misc, name-defined]
        """pyewf의 seek/read 인터페이스를 TSK 외부 이미지로 노출한다."""

        def __init__(self, handle: Any) -> None:
            self._ewf_handle = handle
            self._closed = False
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, size: int) -> bytes:
            if self._closed:
                raise ValueError("I/O operation on closed EWF image")
            if offset < 0 or size < 0:
                raise ValueError("offset and size must be non-negative")
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self) -> int:
            if self._closed:
                raise ValueError("I/O operation on closed EWF image")
            return int(self._ewf_handle.get_media_size())

        def close(self) -> None:
            if not self._closed:
                self._ewf_handle.close()
                self._closed = True

        def __enter__(self) -> Self:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            self.close()

    try:
        return EwfImgInfo(ewf_handle)
    except Exception:
        ewf_handle.close()
        raise


def image_sha256(img: Any) -> str:
    """EWF에서 복원한 논리 디스크 전체 바이트의 SHA-256을 계산한다.

    컨테이너 세그먼트 파일 자체가 아니라 ``pytsk3.Img_Info``가 노출하는
    논리 미디어를 해시한다. 따라서 EWF 분할 크기나 압축 방식이 달라도
    복원된 디스크 내용이 같으면 동일한 해시가 나온다.
    """
    media_size = int(img.get_size())
    if media_size < 0:
        raise ValueError("image size must be non-negative")

    digest = hashlib.sha256()
    offset = 0
    while offset < media_size:
        requested_size = min(_HASH_CHUNK_SIZE, media_size - offset)
        chunk = img.read(offset, requested_size)
        if not chunk:
            raise OSError(f"unexpected end of EWF image at offset {offset} of {media_size} bytes")
        if len(chunk) > requested_size:
            raise OSError(f"EWF image returned {len(chunk)} bytes for a {requested_size}-byte read")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()

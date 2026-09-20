"""EntryStore + Stream 0/1 읽기.

- CacheAddr → data_N 오프셋에서 EntryStore 읽기 (키, 스트림 주소)
- Stream 0 : HTTP 응답 헤더. Chromium 이 `base::Pickle` 포맷으로 직렬화한다
  (net/http/http_response_info.cc `HttpResponseInfo::Persist`/`InitFromPickle`).
  status line, 헤더 딕셔너리와 요청·응답 시각을 뽑는다 — cert/SSL/vary 등 뒤쪽 필드는
  쓰지 않아 값은 버리고 커서만 올바르게 넘긴다.
- Stream 1 : 응답 본문. 작은 본문은 블록 내부, 큰 본문은 f_XXXXXX.
- 캐시 키 접두어(`1/0/https://...`) 처리는 CacheKey 에서.

pickle 필드 순서·플래그 비트는 Chromium 소스와, 이미 이 픽스처에서 검증된
`ccl_chromium_reader.ccl_chromium_cache.CachedMetadata.from_buffer` /
`ChromiumBlockFileCache` 구현(같은 명세를 다루는 참조 구현)으로 대조했다.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from gentrace_forensics.classification.blockfile import index
from gentrace_forensics.classification.blockfile.addr import CacheAddr, FileType
from gentrace_forensics.classification.blockfile.structs import (
    BLOCK_HEADER_SIZE,
    ENTRY_STORE_SIZE,
    EntryStore,
)

__all__ = [
    "CacheEntry",
    "CacheKey",
    "HttpResponseInfo",
    "data_location",
    "iter_entries",
    "read_block_data",
    "read_entry",
]

# net/http/http_cache.cc GenerateCacheKey 접두어
_CRED_UPLOAD_KEY_PREFIX = re.compile(r"^\d+/\d+/")  # '현재' 형식 (2021-09 이후)
_UPLOAD_ONLY_KEY_PREFIX = re.compile(r"^\d+/")  # 그 이전 형식

# HTTP 상태 줄(예: "HTTP/1.1 200 OK")에서 상태 코드 추출
_STATUS_LINE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})")

# HTTP Range 요청으로 생긴 sparse 캐시의 자식 엔트리 키 접두어/접미어.
# `Range_1/0/https://example.com/big.mp4:2fb884ac72675a:0` 형태 — 부모 리소스와
# 같은 URL 로 취급한다.
_SPARSE_SUFFIX = re.compile(r":[0-9a-f]{6,}:\d+$")

# net/http/http_response_info.cc CachedMetadataFlags / CachedMetadataExtraFlags
_RESPONSE_INFO_HAS_EXTRA_FLAGS = 1 << 31
_RESPONSE_EXTRA_INFO_HAS_ORIGINAL_RESPONSE_TIME = 1 << 2


@dataclass
class HttpResponseInfo:
    """캐시 엔트리 Stream 0 (HTTP 응답 메타데이터)."""

    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    request_time_us: int | None = None
    response_time_us: int | None = None

    def get(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @property
    def content_type(self) -> str | None:
        return self.get("content-type")


@dataclass
class CacheKey:
    """캐시 키 문자열에서 실제 요청 URL 을 뽑는다.

    net/http/http_cache.cc GenerateCacheKey 형태:
      `<credential_key>/<upload_id>/<url 또는 _dk_...>`  (2021-09 이후 '현재' 형식)
      `<upload_id>/<url 또는 _dk_...>`                    (이전 형식)
      위 접두어가 없으면 키 전체가 URL.
    `_dk_` 접두어는 더블키(사이트 파티셔닝) 캐시: `_dk_<top_frame_site> <variable_part>
    <url>` 가 기본형이지만, FedCM 등 일부 cross-site 요청은 그 사이에 필드가 하나
    더 끼어든다 (실 픽스처에서 `..._dk_https://a https://b 2 https://c` 형태 관측 —
    ccl_chromium_reader 도 3분할만 가정해 같은 픽스처에서 동일하게 틀린다). URL 은
    항상 공백을 포함하지 않으므로, 필드 개수에 상관없이 마지막 공백 분리 토큰을
    URL 로 본다.
    `Range_` 접두어 + `:<hash>:<index>` 접미어는 HTTP Range 요청으로 생긴 sparse
    캐시의 자식 엔트리 — 부모 리소스와 같은 URL 로 정리한다.
    ccl_chromium_reader 의 CacheKey 클래스 방식을 참고했다.
    """

    raw: str

    @property
    def url(self) -> str:
        rest = self.raw.removeprefix("Range_")
        if _CRED_UPLOAD_KEY_PREFIX.match(rest):
            rest = rest.split("/", 2)[-1]
        elif _UPLOAD_ONLY_KEY_PREFIX.match(rest):
            rest = rest.split("/", 1)[-1]

        if rest.startswith("_dk_"):
            parts = rest[4:].split(" ")
            if len(parts) >= 3:
                rest = parts[-1]
        return _SPARSE_SUFFIX.sub("", rest)


class _PickleReader:
    """Chromium `base::Pickle` 포맷 최소 리더 (4바이트 정렬만 지원).

    문자열/바이너리 하나 읽을 때마다 다음 4바이트 경계로 커서를 맞춘다.
    """

    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        self._pos = 0

    def _read(self, n: int) -> bytes:
        end = self._pos + n
        if end > len(self._buf):
            raise ValueError(f"pickle 읽기 범위 초과: {self._pos}+{n} > {len(self._buf)}")
        chunk = self._buf[self._pos : end]
        self._pos = end
        return chunk

    def _align(self) -> None:
        remainder = self._pos % 4
        if remainder:
            self._read(4 - remainder)

    def read_uint32(self) -> int:
        (value,) = struct.unpack("<I", self._read(4))
        return value

    def read_int64(self) -> int:
        (value,) = struct.unpack("<q", self._read(8))
        return value

    def read_bytes(self, length: int) -> bytes:
        data = self._read(length)
        self._align()
        return data


def _parse_response_info(buf: bytes) -> HttpResponseInfo:
    """Stream 0(HTTP 응답 정보 pickle) 원본 바이트 → HttpResponseInfo.

    구조: [payload_size u32][flags u32][extra_flags u32, 있으면]
          [request_time i64][response_time i64][original_response_time i64, 있으면]
          [header_blob_len u32][header_blob]  ... (cert/SSL/vary 등은 읽지 않음)

    header_blob 은 NUL 로 구분된 항목들: 첫 항목은 상태 줄(예: "HTTP/1.1 200 OK"),
    나머지는 "Name: Value" 형태 헤더.
    """
    reader = _PickleReader(buf)
    total_length = reader.read_uint32()
    if total_length != len(buf) - 4:
        raise ValueError("stream 0 pickle 크기가 선언값과 다름")

    flags = reader.read_uint32()
    extra_flags = 0
    if flags & _RESPONSE_INFO_HAS_EXTRA_FLAGS:
        extra_flags = reader.read_uint32()

    request_time_us = reader.read_int64() or None
    response_time_us = reader.read_int64() or None
    if extra_flags & _RESPONSE_EXTRA_INFO_HAS_ORIGINAL_RESPONSE_TIME:
        reader.read_int64()  # original_response_time

    header_length = reader.read_uint32()
    raw_headers = reader.read_bytes(header_length)

    headers: dict[str, str] = {}
    status: int | None = None
    for part in raw_headers.split(b"\x00"):
        if not part:
            continue
        text = part.decode("latin-1")
        if status is None:
            m = _STATUS_LINE.match(text)
            if m:
                status = int(m.group(1))
                continue
        name, sep, value = text.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()

    return HttpResponseInfo(
        status=status,
        headers=headers,
        request_time_us=request_time_us,
        response_time_us=response_time_us,
    )


@dataclass
class CacheEntry:
    addr: CacheAddr
    store: EntryStore
    key: CacheKey
    stream_addrs: list[CacheAddr]

    def response_info(self, cache_dir: Path) -> HttpResponseInfo:
        """Stream 0 파싱."""
        raw = self._read_stream(cache_dir, 0)
        if not raw:
            return HttpResponseInfo(status=None, headers={})
        return _parse_response_info(raw)

    def body_bytes(self, cache_dir: Path) -> bytes:
        """Stream 1 raw 바이트 (압축 해제 전)."""
        return self._read_stream(cache_dir, 1)

    def _read_stream(self, cache_dir: Path, stream_number: int) -> bytes:
        addr = self.stream_addrs[stream_number]
        if not addr.is_initialized:
            return b""
        raw = read_block_data(Path(cache_dir), addr)
        size = self.store.data_size[stream_number]
        return raw[:size]


def _find_external_file(cache_dir: Path, file_number: int) -> Path:
    """`f_XXXXXX` 파일 경로. 확장자가 붙어있는 경우(`.gz`, `.png` 등)도 찾는다."""
    stem = f"f_{file_number:06x}"
    exact = cache_dir / stem
    if exact.is_file():
        return exact
    matches = sorted(cache_dir.glob(f"{stem}.*"))
    if matches:
        return matches[0]
    raise FileNotFoundError(f"external cache file not found: {stem}*")


def data_location(cache_dir: Path, addr: CacheAddr) -> tuple[Path, int]:
    """읽기에 사용할 실제 파일 경로와 바이트 오프셋. 외부 파일 확장자도 보존한다."""
    cache_dir = Path(cache_dir)
    if not addr.is_initialized:
        raise ValueError(f"uninitialized CacheAddr: 0x{addr.raw:08x}")
    if addr.file_type == FileType.EXTERNAL:
        return _find_external_file(cache_dir, addr.external_file_number), 0
    return cache_dir / f"data_{addr.block_file_number}", addr.file_offset(BLOCK_HEADER_SIZE)


def read_block_data(cache_dir: Path, addr: CacheAddr) -> bytes:
    """할당된 블록 전체(패딩 포함) 또는 외부 파일을 읽는다.

    실제 유효 길이(EntryStore.data_size)로 자르는 건 호출자 책임이다.
    """
    data_path, offset = data_location(cache_dir, addr)
    if addr.file_type == FileType.EXTERNAL:
        return data_path.read_bytes()
    with data_path.open("rb") as f:
        f.seek(offset)
        return f.read(addr.block_size * addr.num_blocks)


def read_entry(cache_dir: Path, addr: CacheAddr) -> CacheEntry:
    cache_dir = Path(cache_dir)
    raw = read_block_data(cache_dir, addr)
    store = EntryStore.parse(raw)

    long_key_addr = CacheAddr(store.long_key)
    if long_key_addr.is_initialized:
        key_text = read_block_data(cache_dir, long_key_addr)[: store.key_len].decode(
            "utf-8", errors="replace"
        )
    elif store.key_len > len(store.key):
        # 인라인 키가 EntryStore 고정 버퍼(160바이트)보다 길면 long_key_addr 을 쓰는
        # 대신, CacheAddr.num_blocks 로 할당된 연속 블록에 이어서(별도 구조체 없이
        # 순수 바이트로) 저장된다. 실 픽스처에서 599바이트짜리 추적 URL 키로 확인.
        key_offset = ENTRY_STORE_SIZE - len(store.key)
        key_text = raw[key_offset : key_offset + store.key_len].decode("utf-8", errors="replace")
    else:
        key_text = store.inline_key

    stream_addrs = [CacheAddr(a) for a in store.data_addr]
    return CacheEntry(addr=addr, store=store, key=CacheKey(key_text), stream_addrs=stream_addrs)


def iter_entries(cache_dir: str | Path) -> Iterator[CacheEntry]:
    """`index` 해시테이블의 모든 충돌 체인을 따라가며 CacheEntry 를 전부 순회.

    `index.iter_entry_addresses()` 는 테이블 슬롯(체인의 head)만 주므로, 여기서
    각 head 부터 `EntryStore.next` 를 초기화된 주소가 아닐 때까지 따라간다.
    """
    cache_dir = Path(cache_dir)
    for head in index.iter_entry_addresses(cache_dir / "index"):
        addr: CacheAddr | None = head
        while addr is not None and addr.is_initialized:
            entry = read_entry(cache_dir, addr)
            yield entry
            next_addr = CacheAddr(entry.store.next)
            addr = next_addr if next_addr.is_initialized else None

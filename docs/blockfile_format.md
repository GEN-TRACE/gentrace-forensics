# Chrome Blockfile 캐시 포맷

명세 출처: Chromium `net/disk_cache/blockfile/`
- `disk_format.h`, `disk_format_base.h` — 구조체 정의
- `addr.h` — CacheAddr 해석

참조 구현: `ccl_chromium_reader` (대조·검증용)

## VM Chrome 버전

| 항목 | 값 |
| --- | --- |
| Chrome 버전 | TODO (Cache_Data 만으론 알 수 없음. User Data의 다른 파일/레지스트리 필요 — 예은 획득 범위 확인 필요) |
| 캐시 포맷 버전 (index 헤더 `version`) | `0x00030000` = **3.0** (`kVersion3_0`), `01_Cache_Data`/`02_Cache_Data` 둘 다 동일 |
| 수집일 (index `create_time`, WebKit epoch) | `01_Cache_Data`: 2026-08-25 13:34:40 UTC / `02_Cache_Data`: 2026-08-25 22:56:08 UTC (실제 파일 mtime과 일치, 오프셋 검증 근거) |

> 버전별 구조체 차이에 대비해 정확히 기록한다. 브라우저 product 버전(예: "129.0.xxxx")은
> Cache_Data 단독으론 복원 불가 — 포맷 버전(3.0)이 구조체 레이아웃 판단에 실제로 쓰이는 값.

## 파일 구성

| 파일 | magic | 역할 |
| --- | --- | --- |
| `index` | `0xC103CAC3` | 헤더 + 해시테이블. 캐시 키 → 엔트리 CacheAddr |
| `data_0` | `0xC104CAC3` | 36바이트 블록 (rankings) |
| `data_1` | `0xC104CAC3` | 256바이트 블록 (EntryStore 등) |
| `data_2` | `0xC104CAC3` | 1KB 블록 |
| `data_3` | `0xC104CAC3` | 4KB 블록 |
| `f_XXXXXX` | 없음 | 큰 응답 본문 (EXTERNAL) |

## CacheAddr (32비트)

```
bit 31      is_initialized
bit 28-30   file_type  (0=EXTERNAL, 1=RANKINGS, 2=BLOCK_256, 3=BLOCK_1K, 4=BLOCK_4K, ...)

EXTERNAL:
  bit 0-27  f_<hex> 파일 번호

BLOCK:
  bit 24-25 num_blocks - 1
  bit 16-23 file_number  (data_<n>)
  bit 0-15  block_number
  offset = header_size + block_number * block_size_for_type
```

## 헥스 대조 결과

### index 헤더 (`01_Cache_Data/index`, 첫 64바이트)

```
00000000: c3ca 03c1 0000 0300 3e02 0000 0000 0000  ........>.......
00000010: 4100 0000 0100 0000 0000 01a1 0000 0200  A...............
00000020: 0000 0000 0000 0000 4e17 ad72 75b8 2f00  ........N..ru./.
00000030: d619 5f01 0000 0000 0000 0000 0000 0000  .._.............
```

필드 매핑 (`structs.IndexHeader`, 리틀엔디언):

| 오프셋 | 필드 | 값 |
| --- | --- | --- |
| 0x00 | magic | `0xc103cac3` = `kIndexMagic` (일치) |
| 0x04 | version | `0x00030000` = 3.0 |
| 0x08 | num_entries | `0x23e` = 574 |
| 0x0c | old_v2_num_bytes | `0` |
| 0x10 | last_file | `0x41` = 65 |
| 0x14 | this_id | `1` |
| 0x18 | stats (CacheAddr) | `0xa1010000` → 초기화됨, BLOCK_256, data_1, 블록 2개 |
| 0x1c | table_len | `0x20000` = 131072 |
| 0x20 | crash | `0` |
| 0x24 | experiment | `0` |
| 0x28 | create_time | `13432138480031566` → 2026-08-25 13:34:40 UTC |

검증: `INDEX_HEADER_TOTAL_SIZE(368) + table_len(131072) * 4` = 524656 바이트 = 실제
`01_Cache_Data/index` 파일 크기와 정확히 일치 (`tests/classification/test_blockfile_structs.py::test_index_header_matches_real_fixture`).

### data_N 블록 파일 헤더 (`01_Cache_Data/data_0`, `data_1`, 첫 32바이트)

```
data_0: c3ca 04c1 0000 0200 0000 0000 2400 0000 3e02 0000 0004 0000 ...
data_1: c3ca 04c1 0000 0200 0100 0000 0001 0000 2e03 0000 0008 0000 ...
```

| 파일 | magic | this_file | entry_size | 해석 |
| --- | --- | --- | --- | --- |
| `data_0` | `0xc104cac3` | 0 | 36 | RANKINGS 블록 (LRU 랭킹 노드) |
| `data_1` | `0xc104cac3` | 1 | 256 | BLOCK_256 (EntryStore, 캐시 엔트리 본체) |

`data_1.num_entries`(814)가 `index` 헤더의 `stats` CacheAddr(`block_file_number=1`)와 맞아떨어짐.

### EntryStore (data_1 블록)

`structs.EntryStore`와 `entry.read_entry()`에 구현되어 있다. `hash`, `next`,
`key_len`, `data_addr[4]`, `creation_time`과 인라인/외부 키를 읽는다.
`entry.iter_entries()`가 index 슬롯의 충돌 체인을 따라 순회한다.
실제 엔트리 헥스 덤프를 문서에 추가하는 작업은 남아 있다.

### Stream 0 (HTTP 응답 헤더 pickle)

`entry._parse_response_info()`에 구현되어 있다. payload 크기·flags·선택적 extra flags,
요청·응답 시각, 선택적 original response time, NUL 구분 헤더 blob 순서로 읽는다.
요청·응답 시각은 raw WebKit microseconds로 정규화 단계까지 전달하며, 0은 `None`으로
취급한다. 합성 pickle 테스트와 로컬 픽스처의 참조 파서 시각 대조 테스트가 있다.

### 출처 위치

`entry.data_location()`으로 본문 읽기와 출처 기록에 같은 경로 해석을 사용한다.
`f_XXXXXX.png`처럼 확장자가 붙은 로컬 외부 파일도 실제 이름을 기록한다.
본문이 없거나 읽지 못했으면 해당 EntryStore의 파일·오프셋을 기록한다.
획득 원본 파일 해시와 압축 해제된 본문 해시는 별개다.

## 캐시 키 접두어

```
1/0/https://example.com/...      isolation key 등 접두어
_dk_https://... https://... https://...
```

키 전체를 URL 로 간주하지 않는다. `ccl_chromium_reader` 의 `CacheKey` 방식 참고.

## 대조 도구

- ChromeCacheView (NirSoft)
- Hindsight (Ryan Benson)

엔트리 수 / URL / Content-Type / 크기 일치 확인. 불일치 시 헥스 재확인.

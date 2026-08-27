# Chrome Blockfile 캐시 포맷

명세 출처: Chromium `net/disk_cache/blockfile/`
- `disk_format.h`, `disk_format_base.h` — 구조체 정의
- `addr.h` — CacheAddr 해석

참조 구현: `ccl_chromium_reader` (대조·검증용)

## VM Chrome 버전

| 항목 | 값 |
| --- | --- |
| Chrome 버전 | TODO (VM에서 확인 후 기록) |
| 캐시 포맷 버전 (index 헤더 `version`) | TODO |
| 수집일 | TODO |

> 버전별 구조체 차이에 대비해 정확히 기록한다.

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

### index 헤더

```
TODO: 첫 수십 바이트 헥스 덤프 + 필드 매핑
```

### EntryStore (data_1 블록)

```
TODO: 실제 엔트리 헥스 덤프 + 필드 매핑 (hash, next, key_len, data_addr[4], creation_time ...)
```

### Stream 0 (HTTP 응답 헤더 pickle)

```
TODO: 포맷 확인 (헤더 문자열 blob, `\0` 구분, status line 포함)
```

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

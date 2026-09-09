# 분류 (Classification) — 지민

**입력**: 획득 단계가 넘겨준 `Cache_Data` 원본 일체 (`schemas.AcquiredCache`)
**출력**: 엔트리별 `(url, content_type, size, filename, body, service, artifact_kind)` (`schemas.ClassifiedEntry`)

## 3.2.1 Chrome Blockfile 캐시 파서 (자체 구현)

Chromium `net/disk_cache/blockfile/` 의 `disk_format.h`(구조체 정의), `addr.h`(CacheAddr 해석)를 명세로 삼는다.
`ccl_chromium_reader` 를 참조·검증용으로 함께 쓴다.

| 파일 | 역할 |
| --- | --- |
| `index` | 헤더 + 해시테이블. 캐시 키 → 엔트리 주소(CacheAddr) |
| `data_0`~`data_3` | 고정 크기 블록. 엔트리 구조체, 작은 응답 데이터 |
| `f_XXXXXX` | 크기가 큰 응답 본문을 별도 저장한 외부 파일 |

구현 순서

1. 크롬 소스에서 blockfile 구조체 정의 확보. VM Chrome 정확한 버전 기록 → [blockfile/structs.py](blockfile/structs.py)
2. 실제 캐시 파일 헤더 첫 수십 바이트를 헥스로 확인해 구조체와 대조
3. `index` 해시테이블 순회 → 유효 CacheAddr 전체 수집 → [blockfile/index.py](blockfile/index.py)
4. 각 주소의 `data_N` 오프셋에서 엔트리 읽기 → [blockfile/entry.py](blockfile/entry.py)
5. Stream 0(HTTP 응답 헤더)에서 `Content-Type`, `Content-Encoding`, 실제 URL 추출
   - 캐시 키가 `1/0/https://…` 형태로 접두어가 붙는 경우가 있으므로 키 전체를 URL로 간주하지 않는다.
     `ccl_chromium_reader` 의 `CacheKey` 클래스 방식 참고.
6. Stream 1(응답 본문) 추출. 작은 본문은 블록 내부, 큰 본문은 `f_XXXXXX`.
   gzip/deflate/Brotli/Zstandard 해제 → [http.py](http.py)
   - 공유 사전이 필요한 `dcb`/`dcz`는 사전 없이는 해제할 수 없으므로 원문을 보존하고 경고를 기록한다.
7. [blockfile/parser.py](blockfile/parser.py) 로 통합
8. 같은 캐시 폴더를 ChromeCacheView / Hindsight 와 대조. 불일치는 헥스 재확인.

논리적 파일명 결정 순서 (ChromeCacheView 와 동일)

1. `Content-Disposition` 의 `filename`
2. URL 마지막 경로 세그먼트
3. URL 경로 + MIME 기반 확장자
4. 없으면 엔트리 해시 기반 이름

## 3.2.2 서비스별 분류 기준

[services/](services/) 각 모듈 docstring 및 루트 `docs/service_patterns.md` 참조.

분류 로직: ChatGPT·Claude·Veo3·ElevenLabs 는 URL/Content-Type 패턴 + JSON 필드 확인.
Gemini 만 페어링 방식 (같은 파일명끼리 페어링 → 세그먼트 `rd-gg`/`rd-gg-dl` + 크기).
페어링 실패는 `unmatched` 로 분리.

## 규칙

- 이 폴더만 수정. 스키마 변경은 셋이 합의 후.
- 추측으로 채우는 필드 없음. 모르면 `None`.

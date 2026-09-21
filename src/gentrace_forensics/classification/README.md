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
   - 요청·응답 시각도 raw WebKit microseconds로 보존해 정규화에 전달한다.
   - 캐시 키가 `1/0/https://…` 형태로 접두어가 붙는 경우가 있으므로 키 전체를 URL로 간주하지 않는다.
     `ccl_chromium_reader` 의 `CacheKey` 클래스 방식 참고.
6. Stream 1(응답 본문) 추출. 작은 본문은 블록 내부, 큰 본문은 `f_XXXXXX`.
   gzip/deflate/Brotli/Zstandard 해제 → [http.py](http.py)
   - 공유 사전이 필요한 `dcb`/`dcz`는 사전 없이는 해제할 수 없으므로 원문을 보존하고 경고를 기록한다.
7. [blockfile/parser.py](blockfile/parser.py) 로 통합
8. 같은 캐시 폴더를 ChromeCacheView / Hindsight 와 대조. 불일치는 헥스 재확인.

1~7의 자체 파서 구현과 로컬 픽스처의 참조 파서 대조 테스트가 있다.
8의 ChromeCacheView / Hindsight 대조는 아직 완료되지 않았다.
본문의 실제 파일명(확장자 포함)과 오프셋을 기록하며, 본문이 없거나 읽지 못한
항목은 EntryStore 위치를 출처로 기록한다. 읽기 실패 경고는 분류 근거에 보존한다.

논리적 파일명 결정 순서 (ChromeCacheView 와 동일)

1. `Content-Disposition` 의 `filename`
2. URL 마지막 경로 세그먼트
3. URL 경로 + MIME 기반 확장자
4. 없으면 엔트리 해시 기반 이름

논리 파일명과 디스크 저장명은 구분한다. 본문은
`bodies/<이미지·프로필 식별자>/<본문 SHA-256>.bin`에 저장해 긴 파일명과
프로필 간 충돌을 피하고, 논리 파일명은 `ClassifiedEntry.filename`에 보존한다.

## 3.2.2 서비스별 분류 기준

[services/](services/) 각 모듈 docstring 및 루트 `docs/service_patterns.md` 참조.

분류 로직: ChatGPT·Claude·Veo3·ElevenLabs 는 URL/Content-Type 패턴 + JSON 필드 확인.
Gemini는 관측된 `watermarked_img_<id>`를 생성본 근거로 쓰고, 같은 ID의
`rd-gg`/`rd-gg-dl`을 전체 해상도/다운로드 변형으로 연결한다. 페어 유무는
`evidence.paired`에 기록한다. 해당 ID가 없는 후보는 `unmatched`로 남긴다.
세그먼트나 파일 크기만으로 업로드를 확정하지 않는다.

ChatGPT 업로드·생성 파일 및 Claude 파일 분류는 명세 기반 합성 테스트만 있으며,
현재 로컬 픽스처로는 해당 트래픽을 검증하지 못했다. ElevenLabs도 현재 픽스처에서는
오디오 본문 없이 JSON 메타데이터만 확인했다.

## 출력과 통합 경계

`output.classify_manifests()`는 획득 단계의 프로필별 매니페스트 목록을 받아
분류 JSONL 하나와 프로필별 본문 폴더를 만든다. CLI에서는 `--cache`를 반복한다.
매니페스트의 부모 폴더 아래 `Cache/Cache_Data/`를 읽으며, 출력이 이미 있으면 실패한다.
중간 프로필 처리에 실패하면 임시 결과를 정리하고 최종 JSONL을 만들지 않는다.
분류 근거·경고·본문 경로·획득 메타데이터는 JSONL에 함께 보존한다.

## 규칙

- 이 폴더만 수정. 스키마 변경은 셋이 합의 후.
- 추측으로 채우는 필드 없음. 모르면 `None`.

# 정규화 (Normalization) — 신아

**입력**: 분류 단계의 엔트리 목록 (`schemas.ClassifiedEntry`)
**출력**: Common Schema 로 검증된 레코드 (`schemas.NormalizedArtifact`) — SQLite + JSONL, 필요 시 Parquet

## 정규화 항목

| 항목 | 처리 | 모듈 |
| --- | --- | --- |
| Timestamp | Chrome/WebKit Time, Unix Time 등 → UTC ISO 8601 | [time.py](time.py) |
| Service | 서비스명 통일 (`chatgpt`, `claude`, `gemini`, `veo3`, `elevenlabs`) | [mapping.py](mapping.py) |
| User / Session ID | 서비스마다 다른 식별자를 공통 필드로 매핑 | [transform.py](transform.py) |
| Event Type | 방문, 캐시 생성, 다운로드, 요청/응답 등 공통 유형 | [mapping.py](mapping.py) |
| Actor | 행위 주체 | [transform.py](transform.py) |
| Content | URL, HTTP 응답, JSON, 캐시 본문 | [transform.py](transform.py) |
| Content Type | HTML, JSON, Image, Audio, Video 등 통일 | [mapping.py](mapping.py) |
| Artifact Source | Cache, History, Cookie, IndexedDB 등 원본 종류 | [transform.py](transform.py) |
| Source ID | 원본 E01·파일·오프셋으로 되돌아갈 식별자 (SHA-256, 경로, 오프셋) | [transform.py](transform.py) |
| URL / Domain | tldextract 기반 도메인·경로 정규화 | [url.py](url.py) |
| 저장 | SQLite / JSONL | [store.py](store.py) |

라이브러리: `pydantic`, `datetime`/`dateutil`, `urllib`/`tldextract`, `hashlib`, `sqlite3`

## 분류 결과와의 연결

- `cache_timestamps`의 응답 → 요청 → 캐시 생성 시각 순서로 대표 시각을 선택한다.
  캐시 시각이 없을 때만 명시적인 서비스 시각을 사용한다. 캐시 시각을 실제
  업로드·생성 행위 시각으로 단정하지 않는다.
- `source_id`는 이미지·파티션·프로필·엔트리·원본 파일 위치를 담은 JSON 문자열이다.
  서로 다른 프로필에 같은 `entry_id`가 있어도 정규화 레코드는 구분된다.
- 공통 스키마에는 분류 근거·경고·본문 경로 전체가 들어가지 않는다.
  `classified.jsonl`과 `bodies/`를 정규화 결과와 함께 보관하고,
  `source_id`의 이미지·파티션·프로필·`entry_id`로 원래 분류 레코드를 연결한다.
- 본문이 없는 항목의 `source_file`/`source_offset`은 EntryStore 위치일 수 있다.
  `source_file_sha256`은 획득 원본 파일의 해시이고, `sha256`은 분류 본문 해시이므로
  압축·블록 패딩 등이 있는 경우 서로 다를 수 있다.

`tests/normalization/`은 시각·URL·매핑·출처·SQLite/JSONL 왕복과 저장 실패를 검증한다.
`tests/test_pipeline_contracts.py`는 합성 파일시스템에서 프로필별 획득 매니페스트를
만든 뒤 분류·정규화 결과의 연결을 검사한다. `normalize` CLI 연결은 후속 작업이다.

## 규칙

- 이 폴더만 수정. 스키마 변경은 셋이 합의 후.
- 모든 출력 레코드는 원본 E01 → 파일 → 오프셋까지 역추적 가능해야 한다.
- 추측으로 채우는 필드 없음. 모르면 `None`.

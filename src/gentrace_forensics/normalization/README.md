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

## 규칙

- 이 폴더만 수정. 스키마 변경은 셋이 합의 후.
- 모든 출력 레코드는 원본 E01 → 파일 → 오프셋까지 역추적 가능해야 한다.
- 추측으로 채우는 필드 없음. 모르면 `None`.

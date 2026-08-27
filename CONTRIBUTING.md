# gentrace-forensics

GEN-TRACE 연구용 포렌식 도구. Windows 디스크 이미지(E01)에서 Chrome 캐시를 획득하고,
생성형 AI 서비스(ChatGPT, Claude, Gemini, Veo 3, ElevenLabs)의 **File Upload / Generated File 아티팩트**를
분류한 뒤, 공통 스키마로 정규화해 타임라인·상관분석이 가능한 형태로 저장한다.

- Repo: https://github.com/GEN-TRACE/gentrace-forensics
- 언어: Python 3.11+
- 패키지명: `gentrace_forensics`
- CLI 진입점: `gentrace`

---

## 1. 팀 및 담당 범위

| 단계 | 담당 | 폴더 | 역할 |
| --- | --- | --- | --- |
| 1. 획득 (Acquisition) | 예은 | `src/gentrace_forensics/acquisition/` | E01에서 Chrome `Cache_Data` 원본 파일 추출 |
| 2. 분류 (Classification) | 지민 | `src/gentrace_forensics/classification/` | Blockfile 캐시 파싱 + 서비스별 Upload/Generated 분류 |
| 3. 정규화 (Normalization) | 신아 | `src/gentrace_forensics/normalization/` | 분류 결과를 공통 스키마로 변환·검증·저장 |

**규칙**
- 각자 자기 폴더만 수정한다. 다른 사람 폴더를 건드려야 하면 PR에서 멘션.
- 단계 사이의 데이터 계약은 `src/gentrace_forensics/schemas/`에 Pydantic 모델로 두고, 셋이 합의 후에만 변경한다.
- `main`은 PR로만 머지. 브랜치명: `feat/acquisition`, `feat/classification`, `feat/normalization`, 작은 작업은 `feat/<설명>`. 작업 단위마다 브랜치를 새로 파고 머지되면 삭제한다 (개인 고정 브랜치 없음). 복붙용 절차는 [docs/git_workflow.md](docs/git_workflow.md).
- 커밋 메시지는 **영어**로 쓴다. 형식: `[ <type> ] <설명>` (예: `[ chore ] scaffold project structure`).
  `type`은 `feat`, `fix`, `chore`, `docs`, `test`, `refactor` 중 하나. 대괄호 안팎에 공백을 둔다.
- 실제 증거 이미지·캐시 원본은 **절대 커밋하지 않는다**. `samples/`에는 익명화된 소형 테스트 샘플만 둔다.

---

## 2. 파이프라인 및 데이터 흐름

```
E01 이미지
   │  (1) 획득 – 예은
   ▼
Cache_Data 원본 (index, data_0~3, f_XXXXXX) + 출처 메타데이터
   │  (2) 분류 – 지민
   ▼
캐시 엔트리 목록 (URL, Content-Type, 본문, 서비스, upload/generated)
   │  (3) 정규화 – 신아
   ▼
Common Schema (SQLite / JSONL) → 타임라인, 통합 검색, 상관분석
```

---

## 3. 단계별 상세

### 3.1 획득 – 예은

**입력**: E01(분할 이미지 E02, E03… 포함)
**출력**: `Cache_Data` 디렉터리 원본 복사본 + 파일별 provenance 기록

순서
1. E01 열기 – `libewf-python(pyewf)`
2. GPT/MBR 파티션 순회, Windows NTFS 파티션 식별, 오프셋 계산 – `pytsk3.Volume_Info`, `pytsk3.FS_Info`
3. `/Users/*/AppData/Local/Google/Chrome/User Data/` 아래 `Default`, `Profile *`, `Guest Profile` 탐색, 각 프로필의 `Cache/Cache_Data` 존재 확인 – `pytsk3`, `fnmatch`, `re`
   - 전체 NTFS 재귀 탐색은 하지 않는다. 위 경로 패턴으로 직접 접근.
4. `index`, `data_*`, `f_*` 전부를 원래 디렉터리 구조 그대로 추출 – `pytsk3`, `pathlib`, `hashlib`
   - 파일별 NTFS 시간정보, inode, 크기, SHA-256 기록

대안: `dfVFS`로 1~4단계 통합 처리 가능. 우선은 pyewf + pytsk3로 시작.

### 3.2 분류 – 지민

**입력**: 획득 단계가 넘겨준 `Cache_Data` 원본 일체
**출력**: 엔트리별 `(url, content_type, size, filename, body, service, artifact_kind)`

#### 3.2.1 Chrome Blockfile 캐시 파서 (자체 구현)

Chromium `net/disk_cache/blockfile/`의 `disk_format.h`(구조체 정의), `addr.h`(CacheAddr 해석)를 명세로 삼는다.
`ccl_chromium_reader`를 참조·검증용으로 함께 쓴다.

| 파일 | 역할 |
| --- | --- |
| `index` | 헤더 + 해시테이블. 캐시 키 → 엔트리 주소(CacheAddr) |
| `data_0`, `data_1`, `data_2`, `data_3` | 고정 크기 블록. 엔트리 구조체, 작은 응답 데이터 |
| `f_XXXXXX` | 크기가 큰 응답 본문을 별도 저장한 외부 파일 |

구현 순서
1. 크롬 소스에서 blockfile 구조체 정의 확보. VM Chrome 정확한 버전 기록 (버전별 차이 대비)
2. 실제 캐시 파일 헤더 첫 수십 바이트를 헥스로 확인해 구조체와 대조
3. `index` 해시테이블 순회 → 유효 CacheAddr 전체 수집
4. 각 주소의 `data_N` 오프셋에서 엔트리 읽기 (키, 헤더 위치, 본문 위치)
5. Stream 0(HTTP 응답 헤더)에서 `Content-Type`, `Content-Encoding`, 실제 URL 추출
   - 캐시 키가 `1/0/https://…` 형태로 접두어가 붙는 경우가 있으므로 키 전체를 URL로 간주하지 않는다. `ccl_chromium_reader`의 `CacheKey` 클래스 방식 참고.
6. Stream 1(응답 본문) 추출. 작은 본문은 블록 내부, 큰 본문은 `f_XXXXXX`. gzip/zlib/Brotli 해제.
7. `chrome_blockfile_parser.py`로 통합
8. 같은 캐시 폴더를 ChromeCacheView / Hindsight와 대조. 불일치는 헥스 재확인.

논리적 파일명 결정 순서 (ChromeCacheView와 동일)
1. `Content-Disposition`의 `filename`
2. URL 마지막 경로 세그먼트
3. URL 경로 + MIME 기반 확장자
4. 없으면 엔트리 해시 기반 이름

#### 3.2.2 서비스별 분류 기준

**ChatGPT**

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `image/png` | 대화 캐시 JSON 내부 필드로 판별 |
| URL | `chatgpt.com/backend-api/estuary/content?id=file_...` | 대화 캐시 JSON(`conversation_id`), `download_url` 필드 |
| 식별자 | URL의 `file_id` | – |
| 비고 | – | 비로그인 상태에서도 `file_name`, `file_size_bytes`는 평문 잔존. 본문은 "File stream access denied" |

**Claude**

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `image/webp` | `application/octet-stream` |
| URL | `claude.ai/api/[conversation_id]/files/[file_id]` | 인코딩된 URL 경로 디코딩 필요 |
| 파일명 | `preview.webp` | 디코딩 시 `/mnt/user-data/outputs/<파일명>` 형태 |

**Gemini (Nano Banana 2)** – 업로드와 생성본이 같은 도메인·같은 Content-Type·같은 파일명

| 항목 | 값 |
| --- | --- |
| Content-Type | `image/jpeg` |
| 도메인 | `lh3.googleusercontent.com` |
| 구분 1 | URL 경로 세그먼트 `rd-gg`(업로드) vs `rd-gg-dl`(생성본) |
| 구분 2 | 파일 크기. 생성본이 워터마크 때문에 더 큼 (예: 79,589 < 149,295 bytes) |

→ 같은 파일명끼리 페어링 후 세그먼트 + 크기로 판별. 페어링 실패는 `Unmatched_NeedsManualReview`로 분리.

**Google Veo 3 (deevid.ai)**

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `application/json` | 같은 JSON 내부 필드 |
| URL | `api.deevid.ai/my-assets` | 동일 캐시 항목 |
| JSON 필드 | `inputUserImageId`, `originalImageNameUrls` | `videoUrl`, `noWatermarkVideoUrl` |
| CDN | `cdn2.deevid.ai/user-image/...` | `cdn2.deevid.ai/user-video/...mp4` |

**ElevenLabs**

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `application/json` | `audio/mpeg` |
| URL | `api.us.elevenlabs.io/v2/voices` | `v1/voices/[voice_id]/samples/[sample_id]` 또는 `v1/history/[history_item_id]/audio` |
| JSON 필드 | `voices[].samples[]` → `file_name`, `size_bytes`, `hash`, `preview_url` | URL 패턴으로 판별 |
| 파일명 예 | `forensicuser.m4a` → 서버 저장명 `forensicuser.mp3` | – |

분류 로직: ChatGPT·Claude·Veo3·ElevenLabs는 URL/Content-Type 패턴 + JSON 필드 확인. Gemini만 페어링 방식.

### 3.3 정규화 – 신아

**입력**: 분류 단계의 엔트리 목록
**출력**: Common Schema로 검증된 레코드 (SQLite + JSONL, 필요 시 Parquet)

정규화 항목
- **Timestamp**: Chrome/WebKit Time, Unix Time 등 → UTC ISO 8601 (`datetime`, `dateutil`)
- **Service**: 서비스명 통일 (`chatgpt`, `claude`, `gemini`, `veo3`, `elevenlabs`)
- **User / Session ID**: 서비스마다 다른 식별자를 공통 필드로 매핑
- **Event Type**: 방문, 캐시 생성, 다운로드, 요청/응답 등 공통 이벤트 유형
- **Actor**: 행위 주체
- **Content**: URL, HTTP 응답, JSON, 캐시 본문
- **Content Type**: HTML, JSON, Image, Audio, Video 등 통일
- **Artifact Source**: Cache, History, Cookie, IndexedDB 등 원본 종류
- **Source ID**: 원본 E01·파일·엔트리로 되돌아갈 수 있는 식별자 (SHA-256, 원본 경로, 오프셋)

라이브러리: `pydantic`, `datetime`/`dateutil`, `urllib`/`tldextract`, `hashlib`, `sqlite3`

---

## 4. 단계 간 데이터 계약 (schemas/)

아래는 초안. **셋이 합의 후 확정**하며, 확정 전까지 각 단계는 이 필드명을 기준으로 개발한다.

### 4.1 획득 → 분류: `AcquiredCache`

```python
class AcquiredFile(BaseModel):
    relative_path: str          # Cache_Data 기준 상대 경로 (index, data_1, f_00001a ...)
    local_path: Path            # 추출된 파일의 로컬 경로
    size: int
    sha256: str
    ntfs_inode: int | None
    created: datetime | None    # NTFS $STANDARD_INFORMATION, UTC
    modified: datetime | None
    accessed: datetime | None

class AcquiredCache(BaseModel):
    image_path: str             # E01 경로
    image_sha256: str | None
    partition_offset: int
    windows_user: str           # Users/<name>
    chrome_profile: str         # Default, Profile 2 ...
    source_path: str            # 이미지 내부 Cache_Data 절대 경로
    chrome_version: str | None
    files: list[AcquiredFile]
```

### 4.2 분류 → 정규화: `ClassifiedEntry`

```python
class ClassifiedEntry(BaseModel):
    entry_id: str               # 엔트리 해시 등 고유 ID
    cache_key: str
    url: str
    content_type: str | None
    content_encoding: str | None
    content_disposition: str | None
    filename: str               # 3.2.1 규칙으로 결정한 논리적 파일명
    size: int
    body_path: Path | None      # 압축 해제된 본문 저장 경로
    body_sha256: str | None
    service: Literal["chatgpt", "claude", "gemini", "veo3", "elevenlabs", "unknown"]
    artifact_kind: Literal["file_upload", "generated_file", "conversation", "unmatched", "other"]
    evidence: dict              # 분류 근거 (매칭된 패턴, JSON 필드, 페어 정보 등)
    source_file: str            # data_N 또는 f_XXXXXX
    source_offset: int | None
    cache_timestamps: dict      # 엔트리에 남은 시간값 (raw)
    source_cache: AcquiredCache # 어느 프로필/이미지에서 왔는지
```

### 4.3 정규화 출력: `NormalizedArtifact`

```python
class NormalizedArtifact(BaseModel):
    timestamp: datetime | None  # UTC
    service: str
    user_id: str | None
    session_id: str | None
    event_type: str
    actor: str | None
    content: str | None
    content_type: str
    artifact_source: str        # cache, history, cookie ...
    artifact_kind: str          # file_upload, generated_file ...
    filename: str | None
    url: str
    domain: str
    source_id: str              # ClassifiedEntry.entry_id + AcquiredCache 정보
    sha256: str | None
```

---

## 5. 프로젝트 구조

```
gentrace-forensics/
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── pyproject.toml
├── .gitignore
├── .github/
│   ├── CODEOWNERS
│   ├── pull_request_template.md
│   └── workflows/                  # ci.yml, codeql.yml
├── src/gentrace_forensics/
│   ├── __init__.py
│   ├── cli.py                      # gentrace acquire / classify / normalize / run
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── acquisition.py          # AcquiredFile, AcquiredCache
│   │   ├── classification.py       # ClassifiedEntry
│   │   └── normalization.py        # NormalizedArtifact
│   ├── acquisition/                # 예은
│   │   ├── __init__.py
│   │   ├── README.md
│   │   ├── image.py                # E01 열기
│   │   ├── filesystem.py           # 파티션·NTFS·프로필 탐색
│   │   └── extract.py              # Cache_Data 추출 + 해시
│   ├── classification/             # 지민
│   │   ├── __init__.py
│   │   ├── README.md
│   │   ├── blockfile/
│   │   │   ├── __init__.py
│   │   │   ├── structs.py          # disk_format.h 대응 구조체
│   │   │   ├── addr.py             # CacheAddr 해석
│   │   │   ├── index.py            # index 파일 파싱
│   │   │   ├── entry.py            # EntryStore, Stream 0/1
│   │   │   └── parser.py           # chrome_blockfile_parser 통합
│   │   ├── http.py                 # 헤더 파싱, 압축 해제, 파일명 결정
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── chatgpt.py
│   │   │   ├── claude.py
│   │   │   ├── gemini.py
│   │   │   ├── veo3.py
│   │   │   └── elevenlabs.py
│   │   └── classify.py             # 서비스 라우팅 + artifact_kind 결정
│   └── normalization/              # 신아
│       ├── __init__.py
│       ├── README.md
│       ├── time.py                 # WebKit/Unix → UTC
│       ├── url.py                  # tldextract 기반 도메인·경로 정규화
│       ├── mapping.py              # 서비스명·이벤트 타입 매핑 테이블
│       ├── transform.py            # ClassifiedEntry → NormalizedArtifact
│       └── store.py                # SQLite / JSONL 저장
├── samples/                        # 익명화된 소형 테스트 데이터만
├── tests/
│   ├── acquisition/
│   ├── classification/
│   └── normalization/
└── docs/
    ├── blockfile_format.md         # 구조체 정리, 헥스 대조 결과
    ├── service_patterns.md         # 3.2.2 표
    └── git_workflow.md             # 브랜치·커밋·PR 절차
```

---

## 6. 의존성

```toml
[project]
dependencies = [
  "pydantic>=2",
  "python-dateutil",
  "tldextract",
  "brotli",
]

[project.optional-dependencies]
acquisition = ["libewf-python", "pytsk3"]
reference   = ["ccl-chromium-reader"]
dev         = ["pytest", "ruff", "mypy", "bandit", "pip-audit"]
```

`pytsk3`, `libewf-python`은 빌드가 까다로우므로 optional로 두고, 분류·정규화 단계는 이 없이도 테스트 가능하게 만든다.

---

## 7. 검증 기준

- 분류 파서 결과는 ChromeCacheView, Hindsight 결과와 대조한다. 엔트리 수, URL, Content-Type, 크기가 일치해야 한다.
- 모든 출력 레코드는 원본 E01 → 파일 → 오프셋까지 역추적 가능해야 한다.
- 추측으로 채우는 필드는 없다. 모르면 `None`.

### CI 자동 검사

모든 PR은 GitHub Actions 통과 후 머지한다 ([.github/workflows/](.github/workflows/), [SECURITY.md](SECURITY.md)):
`ruff check` / `ruff format --check` / `mypy src` / `pytest` / `bandit`(SAST) / `pip-audit`(의존성 CVE) /
CodeQL / 증거·비밀 파일 가드(E01·캐시 원본·대용량·API 키 커밋 차단).
로컬에서 push 전에 `ruff check src tests && ruff format src tests && mypy src && pytest` 를 돌린다.

---

## 8. 커밋 규칙

- 커밋 메시지는 영어로 작성한다.
- 형식: `[ <type> ] <설명>`
  - 예: `[ chore ] scaffold project structure and schemas`
  - 예: `[ feat ] parse blockfile index hash table`
  - 예: `[ fix ] handle brotli-encoded response bodies`
- `type` 목록: `feat`(기능), `fix`(버그), `chore`(설정·잡일), `docs`(문서), `test`(테스트), `refactor`(리팩터).
- 대괄호 안쪽 양옆에 공백을 둔다: `[ feat ]` (O) / `[feat]` (X).
- 본문(선택)은 한국어로 적어도 된다. 제목 줄만 위 형식을 지킨다.

---

## 9. CODEOWNERS

```
/src/gentrace_forensics/acquisition/     @<예은 GitHub ID>
/src/gentrace_forensics/classification/  @bbibbi0425
/src/gentrace_forensics/normalization/   @<신아 GitHub ID>
/src/gentrace_forensics/schemas/         @bbibbi0425 @<예은 GitHub ID> @<신아 GitHub ID>
```

예은·신아의 GitHub ID는 아직 플레이스홀더다. 실제 계정으로 교체할 것.

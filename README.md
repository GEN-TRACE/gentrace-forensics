# gentrace-forensics

GEN-TRACE 연구용 포렌식 도구. Windows 디스크 이미지(E01)에서 Chrome 캐시를 획득하고,
생성형 AI 서비스(ChatGPT, Claude, Gemini, Veo 3, ElevenLabs)의 **File Upload / Generated File 아티팩트**를
분류한 뒤, 공통 스키마로 정규화해 타임라인·상관분석이 가능한 형태로 저장한다.

- Repo: https://github.com/GEN-TRACE/gentrace-forensics
- 언어: Python 3.11+
- 패키지명: `gentrace_forensics`
- CLI 진입점: `gentrace`

## 파이프라인

```
E01 이미지
   │  (1) 획득 – 예은      src/gentrace_forensics/acquisition/
   ▼
Cache_Data 원본 (index, data_0~3, f_XXXXXX) + 출처 메타데이터        [AcquiredCache]
   │  (2) 분류 – 지민      src/gentrace_forensics/classification/
   ▼
캐시 엔트리 목록 (URL, Content-Type, 압축 해제 본문, 서비스, upload/generated) [ClassifiedEntry]
   │  (3) 정규화 – 신아    src/gentrace_forensics/normalization/
   ▼
Common Schema (SQLite / JSONL) → 타임라인, 통합 검색, 상관분석        [NormalizedArtifact]
```

## 팀 및 담당 범위

| 단계 | 담당 | 폴더 | 역할 |
| --- | --- | --- | --- |
| 1. 획득 | 예은 | [acquisition/](src/gentrace_forensics/acquisition/) | E01에서 Chrome `Cache_Data` 원본 파일 추출 |
| 2. 분류 | 지민 | [classification/](src/gentrace_forensics/classification/) | Blockfile 캐시 파싱 + 서비스별 Upload/Generated 분류 |
| 3. 정규화 | 신아 | [normalization/](src/gentrace_forensics/normalization/) | 분류 결과를 공통 스키마로 변환·검증·저장 |

**규칙**

- 각자 자기 폴더만 수정한다. 다른 사람 폴더를 건드려야 하면 PR에서 멘션.
- 단계 사이의 데이터 계약은 [schemas/](src/gentrace_forensics/schemas/)에 Pydantic 모델로 두고, 셋이 합의 후에만 변경한다.
- `main`은 PR로만 머지. 브랜치명: `feat/acquisition`, `feat/classification`, `feat/normalization`, 작은 작업은 `feat/<설명>`.
- 커밋 메시지는 **영어**, 형식 `[ <type> ] <설명>` (예: `[ chore ] scaffold project structure`). `type` = `feat`/`fix`/`chore`/`docs`/`test`/`refactor`. 자세한 규칙은 [CONTRIBUTING.md](CONTRIBUTING.md) 8절.
- 실제 증거 이미지·캐시 원본은 **절대 커밋하지 않는다**. `samples/`에는 익명화된 소형 테스트 샘플만 둔다.

## 프로젝트 구조

```
src/gentrace_forensics/
├── schemas/          # 단계 간 데이터 계약 (Pydantic 모델)
├── acquisition/      # 1. E01 → Cache_Data 추출         (예은)
├── classification/   # 2. blockfile 파싱 + 서비스 분류   (지민)
│   ├── blockfile/    #    Chrome blockfile 캐시 파서
│   └── services/     #    서비스별 Upload/Generated 분류기
├── normalization/    # 3. 공통 스키마 변환·검증·저장      (신아)
├── pipeline.py       # 전체 실행 순서·실행 보고서
└── cli.py            # acquire / classify / normalize / run
```

파일 단위 상세는 [CONTRIBUTING.md](CONTRIBUTING.md) 5절.

## 설치

E01 이미지를 여는 데 네이티브 라이브러리(`libewf`, `libtsk`)가 필요하다.
**Windows 사용자는 WSL-Ubuntu** 에서 실행한다.

### Windows (WSL-Ubuntu) — 자동

```powershell
wsl --install -d Ubuntu        # PowerShell(관리자), 최초 1회. 재부팅 후 WSL 진입
```

```bash
git clone https://github.com/GEN-TRACE/gentrace-forensics.git
cd gentrace-forensics
sed -i 's/\r$//' setup_wsl.sh && bash ./setup_wsl.sh
source ~/venvs/gentrace/bin/activate
```

### Windows (WSL-Ubuntu) — 수동

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential pkg-config \
    libtsk-dev libewf-dev libbde-dev libfsntfs-dev

python3 -m venv --prompt gentrace ~/venvs/gentrace
source ~/venvs/gentrace/bin/activate
pip install --upgrade pip setuptools wheel
pip install -e ".[dev,acquisition]"
```

### 분류·정규화만 (E01 안 다룸)

`acquisition` extras 없이 순수 파이썬으로 어디서든:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip          # 구버전 pip 는 editable 설치가 깨짐
pip install -e ".[dev]"
```

> blockfile 파서 대조·검증용 `ccl_chromium_reader`(GitHub 설치)까지:
> `pip install -e ".[dev,reference]"` — git 이 필요하다.

## 실행

전체 실행은 첫 번째 E01 세그먼트를 지정한다. `acquisition` 의존성이 필요하며,
`--out`에는 아직 존재하지 않는 새 실행 폴더를 사용한다.

```bash
gentrace run --image /path/to/disk.E01 --out outputs/case-01/
```

실행은 NTFS·Chrome 프로필 탐색 → 논리 디스크 SHA-256 계산 → 프로필별 캐시 추출 →
분류 → 정규화 순서다. 논리 디스크 전체를 읽는 해시 계산은 이미지 크기에 따라
오래 걸릴 수 있으며 10% 단위로 진행률을 출력한다.

```text
outputs/case-01/
├── run.json                      # 완료/실패 상태, 단계, 출력 경로, 건수
├── acquired/
│   ├── acquisition.json          # 이미지 해시와 프로필별 매니페스트 목록
│   └── partition_<offset>/Users/.../<profile>/
│       ├── acquired.json         # AcquiredCache
│       └── Cache/Cache_Data/     # 추출 원본
├── classified/
│   ├── classified.jsonl
│   └── bodies/<프로필 식별자>/<본문 SHA-256>.bin
└── normalized/
    ├── normalized.jsonl
    ├── normalized.db
    └── normalization.json        # 입력 JSONL 경로·해시와 출력 건수
```

각 단계도 독립 실행할 수 있다. `acquire`는 프로필별 `acquired.json`의 절대 경로를
표준 출력에 한 줄씩 출력한다. 그 경로를 `classify --cache`에 전달한다.
매니페스트 옆의 `Cache/Cache_Data/`를 읽는다.

```bash
gentrace acquire --image /path/to/disk.E01 --out outputs/acquired/

# 여러 프로필을 한 번에 분류해 classified.jsonl 하나로 모은다.
gentrace classify \
  --cache "path/to/Default/acquired.json" \
  --cache "path/to/Profile 1/acquired.json" \
  --out outputs/classified/

gentrace normalize \
  --entries outputs/classified/classified.jsonl \
  --out outputs/normalized/
```

출력은 `classified.jsonl`과 `bodies/<프로필 식별자>/<본문 SHA-256>.bin`이다.
논리 파일명은 JSONL의 `filename`에 보존한다. `body_path`는 절대 경로이므로
다른 작업 디렉터리에서도 읽을 수 있으며, 결과 폴더를 이동하면 경로 재연결이 필요하다.
기존 `classified.jsonl` 또는 `bodies/`가 있으면 덮어쓰지 않고 실패한다.
모든 프로필의 처리가 성공한 뒤 결과를 공개하며, 출력 파일시스템은 hard link를
지원해야 한다(APFS, NTFS, ext4 등).

`acquire`, `normalize`, `run`은 기존 출력 폴더를 재사용하지 않는다.
정규화는 입력을 한 번 읽고 같은 스냅샷으로 JSONL·SQLite를 만든다. 중복 `source_id`로
DB 건수가 줄어드는 입력은 실패 처리한다. 실패한 획득·정규화 단계의 새 출력은 정리하고,
`run`은 앞서 완료한 단계와 실패 단계·오류를 담은 `run.json`을 보존한다.
오류 시 종료 코드는 1, 사용자 중단 시 130이다. 기존 완료 단계의 파일을 입력으로
다음 명령을 별도 실행할 수 있으며, 자동 재개 기능은 제공하지 않는다.

현재 분류기는 Blockfile 캐시를 지원한다. 다른 캐시 형식이나 필요한 파일이 누락된
프로필은 분류 단계에서 실패하며, 전체 실행을 성공한 것으로 기록하지 않는다.

정규화한 SQLite·JSONL만 보관하면 분류 근거·파싱 경고·본문 경로를 직접 확인할 수 없다.
`classified.jsonl`과 `bodies/`를 함께 보관하고, 정규화 레코드의 `source_id`에 담긴
이미지·파티션·프로필·`entry_id`로 분류 결과를 연결한다. 캐시 응답·요청·생성 시각은
파일의 실제 업로드·생성 행위 시각과 같다고 단정하지 않는다.

## 검증 기준

- 분류 파서 결과는 ChromeCacheView, Hindsight 결과와 대조한다. 엔트리 수, URL, Content-Type, 크기가 일치해야 한다.
- HTTP 본문은 gzip, deflate, Brotli, Zstandard를 해제한다. 외부 공유 사전이 필요한 `dcb`/`dcz`는 원문을 보존하고 파싱 경고를 기록한다.
- 모든 출력 레코드는 원본 E01 → 파일 → 오프셋까지 역추적 가능해야 한다.
- 추측으로 채우는 필드는 없다. 모르면 `None`.

단계 간 경로·출처·저장 계약은 `tests/test_pipeline_contracts.py`에서 검증한다.
`tests/test_cli_pipeline.py`는 네이티브 이미지 접근만 대체하고 합성 Blockfile을 실제
파서로 읽어 네 명령을 검사한다. 정규화 시간·URL·저장 테스트는 `tests/normalization/`에 있다.

실제 E01 전체 검증은 로컬 이미지 경로를 명시해 실행한다. Chrome Blockfile 캐시가
있는 이미지를 사용하며, 분할 세그먼트는 같은 폴더에 둔다.

```bash
pip install -e ".[dev,acquisition]"
GENTRACE_E01_FIXTURE="/path/to/disk.E01" \
GENTRACE_E01_OUTPUT="outputs/e01-validation-01" \
  python -m pytest -q -s tests/test_e01_integration.py
```

검증은 실제 `run`을 실행한 후 추출 파일·본문의 해시, 프로필별 출처, JSONL·SQLite의
전체 레코드 일치, 분류 입력 파일의 해시를 확인한다. 출력 폴더는 새 경로여야 한다.
`GENTRACE_E01_OUTPUT`을 생략하면 pytest 임시 폴더를 사용한다.
`GENTRACE_E01_FIXTURE`가 없으면 해당 테스트를 **skip**하며, CI 통과만으로 실제 E01
전체 검증까지 완료했다고 해석하지 않는다. 이미지·원본 캐시·실행 결과는 커밋하지 않는다.

## 문서

- [CONTRIBUTING.md](CONTRIBUTING.md) — 팀 규칙, 파이프라인 상세, 데이터 계약, 커밋 규칙
- [docs/git_workflow.md](docs/git_workflow.md) — 브랜치·커밋·PR 복붙용 절차
- [SECURITY.md](SECURITY.md) — CI 자동 검사 목록, 데이터 취급 원칙
- [docs/blockfile_format.md](docs/blockfile_format.md) — 구조체 정리, 헥스 대조 결과
- [docs/service_patterns.md](docs/service_patterns.md) — 서비스별 분류 패턴 표

## 코드 검사 (CI)

PR을 올리면 GitHub Actions가 자동으로 lint · 타입 · 테스트 · 보안 스캔(bandit, pip-audit, CodeQL) · 증거/비밀 파일 가드를 돌린다.
전부 통과해야 머지할 수 있다. 자세한 목록은 [SECURITY.md](SECURITY.md).

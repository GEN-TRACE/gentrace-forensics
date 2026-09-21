# GEN-TRACE

**Chrome 캐시에 남은 생성형 AI 서비스의 파일 흔적을 분석하는 연구용 디지털 포렌식 도구입니다.**

Windows E01 이미지에서 Chrome 캐시를 획득하고, 서비스별 규칙으로 파일 관련 기록을
분류한 뒤 JSONL·SQLite로 정규화합니다. 캐시 본문과 함께 원본 이미지·프로필·파일 위치·해시를
보존하여 분석 결과를 원본 자료와 대조할 수 있도록 합니다.

## 주요 기능

- **캐시 획득**: E01의 NTFS 파티션과 Chrome 프로필을 탐색해 `Cache_Data`를 추출합니다.
- **출처와 무결성 기록**: 논리 디스크 및 추출 파일의 SHA-256과 원본 위치를 남깁니다.
- **캐시 파싱·분류**: Blockfile 캐시의 URL·HTTP 헤더·본문을 읽고 서비스별 파일 관련 규칙을 적용합니다.
- **정규화·저장**: 캐시 관측을 공통 스키마의 JSONL·SQLite로 저장하고, 분류 기록과 본문을 함께 보존합니다.
- **단계별 실행**: 획득·분류·정규화를 따로 실행하거나 `run`으로 연결합니다. 실행 상태와 실패 단계를 기록합니다.

## 분석 범위와 기능 상태

| 항목 | 현재 `main`에서 지원하는 범위 |
|---|---|
| 입력 | Windows E01 이미지 또는 획득 매니페스트 `acquired.json` |
| 분석 대상 | Chrome `Cache/Cache_Data`의 Blockfile 캐시: `index`, `data_N`, `f_…` |
| 서비스별 분류 규칙 | ChatGPT, Claude, Gemini, DeeVid(Veo), ElevenLabs |
| CLI | `acquire`, `classify`, `normalize`, `run` |
| 분석에 포함하지 않는 자료 | Downloads의 사용자 파일, 브라우저 History, 디스크 전체 파일 카빙 |

**아티팩트 복원·HTML 보고서·`analyze` 명령은 [PR #26](https://github.com/GEN-TRACE/gentrace-forensics/pull/26)의 변경 사항이며, 현재 `main`에는 아직 포함되지 않았습니다.**
인덱스 밖 캐시 엔트리 복원, 선별 아티팩트 저장, 네트워크 상태 분석도 해당 PR에서 다룹니다.
아래 실행 안내와 결과 경로는 현재 `main` 기준입니다.

서비스별 분류 결과는 규칙에 따른 판단입니다. 캐시에 파일 전달 기록이 남았다는 사실만으로
사용자의 업로드·생성 행위를 확정하지 않습니다. 지원하는 패턴은
[서비스별 분류 근거](docs/service_patterns.md)를 참고하세요.

## 설치

Python **3.11 이상**이 필요합니다. 저장소를 받은 뒤 프로젝트 폴더에서 설치합니다.

```bash
git clone https://github.com/GEN-TRACE/gentrace-forensics.git
cd gentrace-forensics
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

이미 획득한 캐시를 분석하는 경우:

```bash
python -m pip install -e .
```

E01에서 직접 획득하는 경우:

```bash
python -m pip install -e ".[acquisition]"
```

E01 획득에는 `pyewf`·`pytsk3` 네이티브 바인딩이 필요합니다. 운영체제와 Python 버전에 따라
빌드 도구와 라이브러리 설치가 추가로 필요할 수 있습니다. Windows에서는 **WSL-Ubuntu**를 사용합니다.

<details>
<summary>Windows / WSL-Ubuntu 설치</summary>

관리자 PowerShell에서 WSL을 설치합니다.

```powershell
wsl --install -d Ubuntu
```

설치 후 Ubuntu 터미널에서 저장소를 받고 자동 설치 스크립트를 실행합니다.

```bash
git clone https://github.com/GEN-TRACE/gentrace-forensics.git
cd gentrace-forensics
sed -i 's/\r$//' setup_wsl.sh
bash ./setup_wsl.sh
source ~/venvs/gentrace/bin/activate
```

수동 설치 시 필요한 시스템 패키지:

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential pkg-config \
    libtsk-dev libewf-dev libbde-dev libfsntfs-dev
```

이후 Python 3.11 이상인 환경에서 위의 가상환경 생성 및 `.[acquisition]` 설치를 진행합니다.

</details>

설치 확인:

```bash
gentrace --help
```

## 실행

### E01부터 전체 실행

```bash
gentrace run --image "/path/to/evidence.E01" --out outputs/case-01
```

첫 번째 `.E01`을 지정하고 분할 세그먼트는 같은 폴더에 둡니다.
프로필 탐색 → 논리 디스크 해시 계산 → 캐시 획득 → 분류 → 정규화 순서로 실행합니다.
디스크 전체 해시 계산은 이미지 크기와 압축 상태에 따라 오래 걸릴 수 있습니다.
`--out`에는 아직 존재하지 않는 새 결과 폴더를 사용합니다.

### 이미 획득한 캐시 분석

`--cache`에는 **캐시 폴더가 아닌 `acquired.json` 경로**를 지정합니다.
매니페스트 옆에 `Cache/Cache_Data` 원본이 있어야 합니다.

```bash
gentrace classify \
  --cache "/path/to/Default/acquired.json" \
  --out outputs/classified-review

gentrace normalize \
  --entries outputs/classified-review/classified.jsonl \
  --out outputs/normalized-review
```

여러 프로필을 함께 분류하려면 `--cache`를 반복합니다.
분류 규칙을 수정한 뒤 재분석할 때 기존 획득본을 사용하면 E01 전체 획득을 반복하지 않아도 됩니다.

### 단계별 명령

| 명령 | 입력과 처리 |
|---|---|
| `acquire` | E01에서 캐시 획득, 프로필별 `acquired.json` 경로 출력 |
| `classify` | 획득 매니페스트에서 캐시 파싱·분류 및 본문 보존 |
| `normalize` | 분류 JSONL을 공통 스키마 JSONL·SQLite로 변환 |
| `run` | E01 획득부터 분류·정규화까지 실행 |

획득만 실행하는 경우:

```bash
gentrace acquire --image "/path/to/evidence.E01" --out outputs/acquired-only
```

기존 결과를 덮어쓰지 않습니다. 전체 실행이 실패하면 `run.json`의 실패 단계와 오류를
확인합니다. 완료된 앞 단계는 보존되며 자동 재개 기능은 없습니다. 완료된 획득본이나
분류 JSONL을 입력으로 다음 단계를 새 출력 위치에 실행할 수 있습니다.

## 결과 파일과 해석

전체 실행 결과는 `--out`으로 지정한 폴더에 저장합니다.

```text
outputs/case-01/
├── run.json
├── acquired/
│   ├── acquisition.json
│   └── partition_<offset>/Users/.../<profile>/
│       ├── acquired.json
│       └── Cache/Cache_Data/
├── classified/
│   ├── classified.jsonl
│   └── bodies/<profile-id>/<sha256>.bin
└── normalized/
    ├── normalized.jsonl
    ├── normalized.db
    └── normalization.json
```

| 경로 | 용도 |
|---|---|
| `run.json` | 전체 실행 상태, 단계, 출력 경로·건수, 오류 정보 |
| `acquired/acquisition.json` | 이미지 해시와 프로필별 획득 매니페스트 목록 |
| 프로필별 `acquired.json` | 획득 파일의 원본 위치·크기·해시 등 출처 정보 |
| `classified/classified.jsonl` | 캐시 관측별 분류 결과·근거·경고·본문 경로 |
| `classified/bodies/` | 보존한 응답 본문. `.bin` 확장자가 실제 파일 형식을 의미하지 않음 |
| `normalized/normalized.jsonl` | 전체 캐시 관측의 공통 스키마 레코드 |
| `normalized/normalized.db` | 같은 정규화 레코드를 저장한 SQLite DB |
| `normalized/normalization.json` | 정규화 입력 해시와 출력 경로·건수 |

**정규화 레코드 수는 실제 파일 수나 사용자 행동 횟수가 아닙니다.**
JavaScript·CSS·아이콘 같은 사이트 구성 자료도 포함됩니다. 한 파일이 여러 캐시 기록으로
남을 수 있고, 본문 없이 메타데이터만 남을 수도 있습니다.

정규화 결과만으로 판단하지 말고 `classified.jsonl`의 근거와 보존 본문을 함께 확인합니다.
`source_id`에는 이미지·파티션·프로필·엔트리를 연결하는 출처 정보가 포함됩니다.
캐시 응답·요청·생성 시각은 파일의 실제 업로드·생성 행위 시각과 구분합니다.

원본 추적을 위해 획득본과 분류 결과도 함께 보관합니다. 절대 경로로 기록된 참조는
결과 폴더를 옮기면 재연결이 필요합니다.

## 검증과 한계

획득 파일·본문의 해시, 출처 연결, JSONL·SQLite 일치, 오류 처리 등을 자동 검사합니다.
이 검사는 모든 파일 흔적의 발견이나 분류 정확도를 보장하지 않습니다.

현재 `main`은 Blockfile 인덱스를 따라 기록을 읽으므로 인덱스에서 빠진 잔존 엔트리를
놓칠 수 있습니다. 이를 보완하는 캐시 블록 복원은 PR #26에 포함되어 있습니다.
다른 Chrome 캐시 형식, 모든 서비스 응답, 외부 도구와의 전수 일치는 검증되지 않았습니다.
분류·정규화의 정상 종료와 증거 해석의 정확성은 구분해서 검토해야 합니다.

## 개발 및 문서

개발 환경은 `python -m pip install -e ".[dev]"`로 설치합니다.
참조 파서 대조가 필요하면 Git이 설치된 환경에서 `.[dev,reference]`를 사용합니다.

```bash
ruff check src tests
ruff format --check src tests
mypy src
pytest
```

실제 E01 전체 실행 테스트는 `.[dev,acquisition]` 설치 후 별도로 실행합니다.

```bash
GENTRACE_E01_FIXTURE="/path/to/evidence.E01" \
GENTRACE_E01_OUTPUT="outputs/e01-validation-new" \
  python -m pytest -q -s tests/test_e01_integration.py
```

이미지 경로가 없으면 이 테스트는 건너뜁니다. CI 통과와 실제 E01 검증은 구분합니다.
실제 증거 이미지·캐시·분석 결과는 저장소에 커밋하지 않습니다.

- [기여 안내](CONTRIBUTING.md) — 팀 담당 범위, 데이터 계약, 개발 규칙
- [Git 작업 절차](docs/git_workflow.md) — 브랜치·커밋·PR 규칙
- [서비스별 분류 근거](docs/service_patterns.md) — 역할과 후보 판단 기준
- [캐시 포맷](docs/blockfile_format.md) — Blockfile 구조와 복원 방식
- [보안 안내](SECURITY.md) — 데이터 취급과 CI 검사

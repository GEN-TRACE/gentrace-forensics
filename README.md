# GEN-TRACE

**Chrome 캐시에 남은 생성형 AI 서비스의 파일 흔적을 분석하는 연구용 디지털 포렌식 도구입니다.**

Windows E01 이미지에서 Chrome 캐시를 획득하거나, 이미 획득한 캐시를 재분석합니다.
파일 ID·첨부·대화·작업 이력 등의 근거를 연결하고, 캐시에 남은 이미지·음성·영상·문서의
본문을 복원합니다. 결과는 JSONL·SQLite와 복원 파일로 제공합니다.

파일의 입력·생성 관련 역할, 판단 근거, 복원 상태를 별도로 기록합니다.
파일이 정상적으로 열리는 것만으로 사용자의 업로드·생성 행위를 확정하지 않습니다.

## 주요 기능

- **캐시 획득과 출처 보존**: E01의 NTFS 파티션과 Chrome 프로필을 탐색하고, 논리 디스크 및 획득 파일의 SHA-256과 원본 위치를 기록합니다.
- **인덱스 밖 기록 복원**: `index`에 연결된 기록뿐 아니라 `data_N`에 남은 EntryStore도 검사합니다. 헤더·키 체크섬을 검증하고 발견 방식과 블록 할당 상태를 보존합니다.
- **파일 관련 근거 연결**: 서비스별 메타데이터와 캐시 본문을 연결해 파일 자산·미리보기·커버·작업 관계를 정리합니다. 근거가 부족한 역할은 미확정으로 남깁니다.
- **본문 복원과 검증**: 실제 파일 형식과 지원 디코더로 검사하고, 영상 조각은 저장 범위와 누락·충돌을 확인합니다. 부분 복원을 완전한 파일과 구분합니다.

## 분석 범위

| 항목 | 현재 범위 |
|---|---|
| 입력 | Windows E01 이미지 또는 획득 매니페스트 `acquired.json` |
| 주요 분석 대상 | Chrome `Cache/Cache_Data`의 Blockfile 캐시: `index`, `data_N`, `f_…` |
| 서비스별 분석 규칙 | ChatGPT, Claude, Gemini, DeeVid(Veo), ElevenLabs |
| 보조 자료 | Chrome `Network Persistent State`의 서버·대체 서비스 상태 |
| 분석에 포함하지 않는 자료 | Downloads의 사용자 파일, 브라우저 History, 디스크 전체 파일 카빙 |

이미 획득한 자료를 분석할 때는 `acquired.json`과 매니페스트에 기록된 캐시 파일이 함께
있어야 합니다. `--cache`에는 **캐시 폴더가 아닌 매니페스트 경로**를 지정합니다.
다른 Chrome 저장 형식이나 모든 버전·서비스 응답을 지원하는 것은 아닙니다.
서비스별 근거와 지원 범위는 [분류 규칙](docs/service_patterns.md)을 참고하세요.

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

### E01부터 전체 분석

```bash
gentrace run --image "/path/to/evidence.E01" --out outputs/case-01
```

첫 번째 `.E01`을 지정하고 분할 세그먼트는 같은 폴더에 둡니다.
프로필 탐색, 논리 디스크 해시 계산, 캐시 획득, 분류·정규화, 아티팩트 복원과 결과 저장을
순서대로 수행합니다. 디스크 전체 해시 계산은 이미지 크기와 압축 상태에 따라 오래 걸릴 수 있습니다.

### 기존 획득본 재분석

```bash
gentrace analyze \
  --cache "/path/to/Default/acquired.json" \
  --out outputs/case-01-review
```

이미지 전체를 다시 읽지 않고, 획득 파일의 크기·해시를 확인한 뒤 분석합니다.
분류 규칙이나 복원 기능을 수정한 뒤 결과를 갱신할 때 사용합니다.
여러 프로필은 `--cache`를 반복해서 지정합니다.

```bash
gentrace analyze \
  --cache "/path/to/Default/acquired.json" \
  --cache "/path/to/Profile 1/acquired.json" \
  --out outputs/multi-profile-review
```

`--out`에는 **새 결과 폴더**를 지정합니다. 기존 결과를 덮어쓰지 않습니다.

### 결과 확인

완료되면 출력되는 **`<out>/artifacts.jsonl`**에서 파일별 근거·출처·복원 상태를 확인합니다.
SQL 검색에는 `artifacts.sqlite3`를 사용합니다. 복원 파일은 `files/`에 저장되며,
아티팩트 레코드의 `files[].path`는 결과 폴더를 기준으로 한 상대 경로입니다.

## 결과 파일과 해석

**전체 캐시 관측, 파일 자산, 복원된 파일은 서로 다른 단위입니다.**
하나의 파일 자산에 여러 캐시 기록이나 미리보기·커버가 연결될 수 있고,
본문 없이 메타데이터만 남은 자산도 있습니다.

| 경로 | 용도 |
|---|---|
| `artifacts.jsonl` / `artifacts.sqlite3` | 파일 자산별 역할·표현·관계·출처·복원 상태 |
| `files/` | 내보낸 본문. 파일별 실제 형식과 검증 상태는 아티팩트 레코드에서 확인 |
| `partial/` | 부분 복원 구간·조각 데이터. 발생한 경우 생성 |
| `validation_summary.json` | 캐시·자산·파일 개수, 복원 상태, 검증 범위 |
| `normalized/normalized.jsonl` / `normalized/normalized.db` | **전체 캐시 관측**의 공통 스키마. 사이트 구성 자료도 포함하며 실제 파일 수나 사용자 행동 횟수가 아님 |
| `normalized/normalization.json` | 정규화 입력 해시, 출력 경로·건수 |
| `classified/classified.jsonl` / `classified/bodies/` | 전체 캐시 분류 기록과 보존 본문. `.bin` 확장자가 실제 파일 형식을 의미하지 않음 |
| `network_records.jsonl` | 별도로 해석한 네트워크 상태 기록 |
| `acquired/` | E01에서 획득한 캐시·매니페스트. `run` 실행 시 생성 |
| `run.json` | 실행 상태, 처리 단계, 입력·출력 경로, 오류 정보 |

`analyze`는 기존 획득본을 참조하며 원본을 결과 폴더에 다시 복사하지 않습니다.
아티팩트 레코드와 복원 파일의 상대 경로를 유지하려면 결과 폴더 전체를 함께 보관합니다.
원본 추적을 위해 획득본도 보관해야 하며, 절대 경로로 기록된 참조는 자료를 옮기면 재연결이 필요합니다.

### 역할과 복원 상태

역할은 `upload`(입력·업로드 관련), `generated`(생성 결과 관련), `unknown`(미확정)으로
구분합니다. 메타데이터에 연결된 근거와 경로·이름만 맞는 후보를 별도로 표시합니다.

| 복원 상태 | 의미 |
|---|---|
| `complete` | 확보한 표현의 범위·지원 형식 검증 통과. 미리보기의 검증 완료가 원본 확보를 뜻하지 않음 |
| `partial` | 일부 구간만 확보했거나 범위가 불완전함 |
| `metadata_only` | 파일 정보 또는 JSON 응답만 확보함 |
| `missing` | 전달 기록은 있으나 본문을 확보하지 못함 |
| `invalid` | 파일 형식·디코딩·HTTP 응답·범위 등의 검증에 실패함 |
| `unverified` | 형식 미지원, 디코더 부재·시간 초과 등으로 검증하지 못함 |

인덱스 밖에서 복원한 기록은 발견 방식과 블록 할당 상태를 출처에 남깁니다.
검증된 파일 바이트가 남아 있다는 사실만으로 해당 엔트리가 획득 시점에 활성 상태였다고 판단하지 않습니다.
캐시 시각이나 네트워크 만료·재시도 시각도 사용자의 업로드·생성·방문 시각과 구분합니다.

전체 필드, 중복 처리, 형식별 검증 방식은 [아티팩트 결과 안내](docs/artifact_outputs.md)를 참고하세요.

## 단계별 명령

| 명령 | 입력과 처리 |
|---|---|
| `acquire` | E01에서 캐시·네트워크 상태 획득, 프로필별 `acquired.json` 경로 출력 |
| `classify` | 획득 매니페스트에서 캐시 파싱·분류 및 본문 보존 |
| `normalize` | 분류 JSONL을 전체 관측 JSONL·SQLite로 변환 |
| `analyze` | 기존 획득본 검증부터 아티팩트 복원·저장까지 실행 |
| `run` | E01 획득부터 아티팩트 복원·저장까지 실행 |

```bash
gentrace acquire --image "/path/to/evidence.E01" --out outputs/acquired-only
gentrace classify --cache "/path/to/Default/acquired.json" --out outputs/classified-only
gentrace normalize --entries outputs/classified-only/classified.jsonl --out outputs/normalized-only
```

`classify`와 `normalize`만 실행하면 파일 자산 추출·복원은 수행되지 않습니다.
파일 복원이 목적이면 `run` 또는 `analyze`를 사용합니다.

오류가 발생하면 `run.json`의 실패 단계와 오류를 확인합니다(`run`·`analyze`).
완료된 앞 단계는 보존되며 자동 재개 기능은 없습니다. 획득이 완료됐다면 해당
`acquired.json`으로 새 폴더에 `analyze`를 실행할 수 있습니다.

## 검증과 한계

파일 해시·출처 연결, JSONL·SQLite 일치, 지원 형식의 디코딩, 손상·부분 데이터 처리 등을
자동 검사합니다. 실제 E01 실행과 ChromeCacheView에서 확인한 일부 이미지의 대조 기록은
[검증 기록](docs/artifact_validation.md)에 정리했습니다.

이 검사는 모든 아티팩트의 발견이나 분류 정확도를 보장하지 않습니다.
인덱스 밖 복원은 체크섬·구조를 검증할 수 있는 기록으로 제한되며, 현재 인덱스에 있는 동일 키의
과거 버전은 별도로 모두 수집하지 않습니다. 원본·미리보기, 역할 근거, 파일별 상태를 함께 검토해야 합니다.
외부 도구와의 전수 대조 및 서비스별 정답 집합에 대한 정확도·재현율 측정은 완료되지 않았습니다.

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
- [아티팩트 결과 안내](docs/artifact_outputs.md) — 출력 계약과 형식별 검증
- [검증 기록](docs/artifact_validation.md) — 실제 자료 검증 결과와 범위
- [보안 안내](SECURITY.md) — 데이터 취급과 CI 검사

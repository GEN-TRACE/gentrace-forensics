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
캐시 엔트리 목록 (URL, Content-Type, 본문, 서비스, upload/generated) [ClassifiedEntry]
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
└── cli.py            # gentrace acquire / classify / normalize / run
```

파일 단위 상세는 [CONTRIBUTING.md](CONTRIBUTING.md) 5절.

## 설치

```bash
python -m pip install -e ".[dev]"

# 획득 단계까지 (pytsk3 / libewf-python 빌드 필요)
python -m pip install -e ".[dev,acquisition]"

# ccl_chromium_reader 대조·검증
python -m pip install -e ".[dev,reference]"
```

분류·정규화 단계는 `acquisition` extras 없이도 개발·테스트 가능하다.

## 실행

```bash
gentrace acquire   --image disk.E01              --out outputs/
gentrace classify  --cache outputs/acquired.json --out outputs/
gentrace normalize --entries outputs/classified.jsonl --out outputs/
gentrace run       --image disk.E01              --out outputs/   # 전체 파이프라인
```

> 현재는 스캐폴드 상태. 각 서브커맨드는 `NotImplementedError` 를 던진다.

## 검증 기준

- 분류 파서 결과는 ChromeCacheView, Hindsight 결과와 대조한다. 엔트리 수, URL, Content-Type, 크기가 일치해야 한다.
- 모든 출력 레코드는 원본 E01 → 파일 → 오프셋까지 역추적 가능해야 한다.
- 추측으로 채우는 필드는 없다. 모르면 `None`.

## 문서

- [CONTRIBUTING.md](CONTRIBUTING.md) — 팀 규칙, 파이프라인 상세, 데이터 계약, 커밋 규칙
- [docs/git_workflow.md](docs/git_workflow.md) — 브랜치·커밋·PR 복붙용 절차
- [SECURITY.md](SECURITY.md) — CI 자동 검사 목록, 데이터 취급 원칙
- [docs/blockfile_format.md](docs/blockfile_format.md) — 구조체 정리, 헥스 대조 결과
- [docs/service_patterns.md](docs/service_patterns.md) — 서비스별 분류 패턴 표

## 코드 검사 (CI)

PR을 올리면 GitHub Actions가 자동으로 lint · 타입 · 테스트 · 보안 스캔(bandit, pip-audit, CodeQL) · 증거/비밀 파일 가드를 돌린다.
전부 통과해야 머지할 수 있다. 자세한 목록은 [SECURITY.md](SECURITY.md).

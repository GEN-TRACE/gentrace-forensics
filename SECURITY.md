# 보안 정책

## 자동 검사 (CI)

PR을 올리거나 `main`에 push하면 아래가 자동으로 돈다 ([.github/workflows/](.github/workflows/)):

| 검사 | 도구 | 무엇을 본다 |
| --- | --- | --- |
| Lint | `ruff check` | 코드 스타일·버그 패턴 |
| Format | `ruff format --check` | 포맷 일관성 |
| Type | `mypy` | 타입 오류 |
| Test | `pytest` | 테스트 |
| SAST | `bandit` | 파이썬 소스의 취약 패턴 (eval, 하드코딩 비밀, 안전하지 않은 역직렬화 등) |
| 의존성 | `pip-audit` | 설치 패키지의 알려진 CVE (경고만, 빌드는 안 막음) |
| 코드 스캔 | CodeQL | 데이터 흐름 기반 취약점 (주입, 경로 조작 등) |
| 증거/비밀 가드 | 커스텀 스크립트 | E01·캐시 원본·대용량 파일(>5MB)·API 키/토큰 패턴 커밋 차단 |

> 비밀 스캔은 흔한 패턴만 best-effort. 저장소 Settings → Code security 에서
> **Secret scanning**(public 무료) 과 **Push protection** 을 켜면 훨씬 촘촘해진다.
> 정밀하게 하려면 `gitleaks` 를 CI에 추가한다 (org private 저장소는 라이선스 필요).

로컬에서 먼저 돌리려면:

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests
mypy src
pytest
bandit -c pyproject.toml -r src
pip-audit --strict
```

## 데이터 취급 원칙

- 실제 증거 이미지(E01 등), Chrome 캐시 원본, 개인정보가 든 파일은 **저장소에 커밋하지 않는다**. `.gitignore`가 1차로 막고 CI `guard` 잡이 2차로 막는다.
- 테스트용 샘플은 익명화한 소형 데이터만 `samples/`에. 민감하면 `samples/private/`(git 무시).
- 분류·정규화 결과물(`*.db`, `*.jsonl`, `outputs/`)도 커밋하지 않는다.

## 취약점 제보

이 저장소에서 보안 문제를 발견하면 이슈를 공개로 열지 말고 팀 내부(지민)에게 직접 알린다.
연구용 도구이므로 외부 노출 위험이 낮지만, 파서가 신뢰할 수 없는 바이너리(디스크 이미지)를 다루므로
파싱 중 임의 코드 실행·경로 탈출 가능성은 항상 경계한다.

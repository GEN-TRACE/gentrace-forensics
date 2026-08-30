# Git 워크플로 (복붙용)

git 처음이어도 이 순서만 따라 하면 된다. **`main`에서 직접 작업하지 않는다.**

---

## 0. 최초 1회만

```bash
git clone https://github.com/GEN-TRACE/gentrace-forensics.git
cd gentrace-forensics

# Windows(WSL-Ubuntu): sed -i 's/\r$//' setup_wsl.sh && bash ./setup_wsl.sh
# 분류·정규화만: python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
# 자세한 건 README "설치"

git config user.name  "본인 이름"
git config user.email "GitHub에 등록된 이메일"
```

Windows(WSL)에서 클론하면 셸 스크립트에 CRLF가 붙을 수 있어 `sed -i 's/\r$//'` 를 한 번 실행한다.
`.gitattributes` 가 이후 체크아웃부터는 LF를 강제한다.

---

## 1. 새 작업 시작할 때

항상 최신 `main`에서 브랜치를 판다.

```bash
git switch main
git pull                          # main 최신화
git switch -c feat/작업설명        # 새 브랜치 생성 + 이동
```

브랜치 이름 예시:
- `feat/blockfile-index` — index 파일 파서
- `feat/chatgpt-classifier` — ChatGPT 분류기
- `feat/normalize-time` — 시간 변환
- `fix/brotli-decode` — 버그 수정

> 담당 영역: 예은 `feat/acquisition-*`, 지민 `feat/classification-*` 또는 `feat/blockfile-*`, 신아 `feat/normalization-*`

---

## 2. 작업하면서 커밋

```bash
git add -A
git status                         # 뭐가 올라가는지 확인
git commit -m "[ feat ] parse blockfile index hash table"
```

커밋 메시지 규칙 (CONTRIBUTING.md 8절):
- 영어, 형식 `[ <type> ] <설명>`
- type: `feat` `fix` `chore` `docs` `test` `refactor`
- 대괄호 안쪽 양옆 공백: `[ feat ]` (O) `[feat]` (X)

작업 도중 여러 번 커밋해도 된다. 작게 자주.

---

## 3. GitHub에 올리고 PR 만들기

```bash
git push -u origin feat/작업설명   # 첫 push는 -u 필요
```

그다음 PR 생성 (둘 중 하나):

```bash
gh pr create --fill                # CLI (gh 설치돼 있으면)
```

또는 터미널에 뜨는 GitHub 링크를 클릭 → "Compare & pull request" 버튼.

PR 설명에 적을 것:
- 뭘 했는지 1~2줄
- 다른 사람 폴더를 건드렸으면 그 담당자를 `@멘션`

PR을 올리면 **GitHub Actions가 자동으로 코드 검사**를 돌린다 (lint · 타입 · 테스트 · 보안 스캔 · 증거/비밀 파일 가드).
PR 페이지 아래쪽에 체크 결과가 뜬다. 빨간 X가 뜨면 "Details"를 눌러 로그를 보고 고친 뒤 다시 push.
로컬에서 미리 돌려보려면:

```bash
ruff check src tests && ruff format --check src tests
mypy src
pytest
bandit -c pyproject.toml -r src
```

전부 초록불이어야 머지 가능. 자세한 검사 목록은 [SECURITY.md](../SECURITY.md).

---

## 4. 리뷰 받고 수정

리뷰어가 코멘트를 남기면, **같은 브랜치에서** 고치고 다시 커밋·push 하면 PR에 자동 반영된다.

```bash
# ...코드 수정...
git add -A
git commit -m "[ fix ] address review comments"
git push
```

승인되면 GitHub에서 **"Merge pull request"** 클릭.

---

## 5. 머지 후 정리

```bash
git switch main
git pull                           # 방금 머지된 내용 받기
git branch -d feat/작업설명        # 로컬 브랜치 삭제
```

다음 작업은 다시 **1번부터**.

---

## 자주 하는 실수

### `main`에서 작업해버렸을 때 (아직 push 안 함)

```bash
git switch -c feat/작업설명        # 현재 변경을 새 브랜치로 옮김
# main은 그대로 두고 계속 진행
```

커밋까지 해버렸다면:

```bash
git switch -c feat/작업설명        # 커밋들을 브랜치로 가져옴
git switch main
git reset --hard origin/main       # main을 원격 상태로 되돌림 (주의: main의 미저장 변경 삭제됨)
git switch feat/작업설명
```

### 작업 중인데 `main`이 업데이트됐을 때 (충돌 방지)

```bash
git switch main && git pull
git switch feat/작업설명
git merge main                     # main의 최신 변경을 내 브랜치로 가져옴
# 충돌 나면 해당 파일 수정 후 git add → git commit
```

### 커밋 메시지를 잘못 썼을 때 (아직 push 안 함)

```bash
git commit --amend -m "[ feat ] 올바른 메시지"
```

### 방금 커밋을 취소하고 싶을 때 (변경 내용은 유지)

```bash
git reset --soft HEAD~1
```

---

## 절대 하지 말 것

- `main`에 직접 push
- `git push --force` (특히 `main`, 남의 브랜치)
- E01 이미지·실제 캐시 원본 커밋 (`.gitignore`가 막지만 `git add -f`로 우회하지 말 것)
- `git add -A` 전에 `git status` 안 보기

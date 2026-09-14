# 획득 (Acquisition) — 예은

**입력**: E01(분할 이미지 E02, E03… 포함)
**출력**: `Cache_Data` 디렉터리 원본 복사본 + 파일별 provenance 기록 (`schemas.AcquiredCache`)

## 순서

1. E01 열기 — `libewf-python(pyewf)` → [image.py](image.py)
   - `E01..E99`, `EAA..EZZ` 분할 세그먼트를 순서대로 탐색하고 누락·중복을 검증
   - 분할·압축 방식과 무관하게 복원된 논리 디스크 전체 바이트의 SHA-256 계산
2. GPT/MBR 파티션 순회, Windows NTFS 파티션 식별, 오프셋 계산 — `pytsk3.Volume_Info`, `pytsk3.FS_Info` → [filesystem.py](filesystem.py)
   - 비활성화된 `FS_Info.exit()`를 직접 호출하지 않고 Python 객체 수명으로 네이티브 자원을 관리
   - 할당된 파티션만 섹터 크기 기준의 byte offset/length로 변환
   - 파티션 설명 문자열이 아니라 실제 파일시스템 형식으로 NTFS 여부 확인
   - 파티션 테이블이 없는 단일 NTFS 이미지(offset 0)도 지원
3. `/Users/*/AppData/Local/Google/Chrome/User Data/` 아래 `Default`, `Profile *`, `Guest Profile` 탐색,
   각 프로필의 `Cache/Cache_Data` 존재 확인 — `pytsk3`, `fnmatch`, `re`
   - 전체 NTFS 재귀 탐색은 하지 않는다. 위 경로 패턴으로 직접 접근.
4. `index`, `data_*`, `f_*` 전부를 원래 디렉터리 구조 그대로 추출 — `pytsk3`, `pathlib`, `hashlib` → [extract.py](extract.py)
   - 파일별 NTFS 시간정보, inode, 크기, SHA-256 기록

대안: `dfVFS`로 1~4단계 통합 처리 가능. 우선은 pyewf + pytsk3로 시작.

## 규칙

- 이 폴더만 수정. 스키마 변경은 셋이 합의 후.
- 실제 증거 이미지·캐시 원본은 절대 커밋 금지.
- `pytsk3`, `libewf-python` 은 optional 의존성(`pip install -e ".[acquisition]"`).

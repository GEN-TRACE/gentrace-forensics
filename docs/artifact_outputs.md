# 아티팩트 분석과 결과 해석

`gentrace run`은 E01 획득, 원본 해시 검증, 캐시 분류·정규화, 파일 자산 추출·복원과 결과 저장을 연결한다. `gentrace analyze`는 이미 획득한 `acquired.json`을 받아 이미지 전체 해시를 다시 계산하지 않고 같은 분석을 수행한다. 원본 캐시 파일의 크기·SHA-256과 추가 네트워크 파일의 해시는 매번 확인한다.

```bash
gentrace run --image evidence.E01 --out outputs/case-new
gentrace analyze --cache /path/to/Default/acquired.json --out outputs/review-new
# 여러 프로필은 --cache를 반복한다.
```

출력은 새 폴더에만 생성한다. 실패하면 `run.json`의 `stage`, `error`를 확인한다. 완료된 앞 단계는 남기며, 실패한 결과 폴더를 재사용하지 않는다. 파일별 근거와 복원 경로는 `artifacts.jsonl` 또는 `artifacts.sqlite3`에서 확인한다. 폴더 전체를 함께 옮겨야 복원 파일의 상대 경로가 유지된다.

## 결과 파일

| 경로 | 단위와 용도 |
|---|---|
| `classified/classified.jsonl`, `classified/bodies/` | 모든 캐시 관측과 보존 본문. `.bin`은 원본 보존 이름이며 파일 형식 판정이 아님 |
| `normalized/normalized.jsonl`, `normalized/normalized.db` | 기존 공통 스키마의 캐시 관측. 파일 개수·사용자 행동 횟수가 아님 |
| `artifacts.jsonl` | 서비스 자산별 레코드. 역할, 근거, 여러 표현, 출처, 검증 상태 |
| `artifacts.sqlite3` | `artifacts`, `sources`, `artifact_sources`, `relationships`, `network_records` |
| `files/<service>/<artifact_id>/<sha256>.<extension>` | 확보한 본문. 실제 형식으로 이름을 정하고 별도 검증 상태를 기록 |
| `partial/<service>/<artifact_id>/<sha256>.bin` | 부분·조각 데이터. 논리 오프셋은 해당 파일의 `ranges`에 기록 |
| `network_records.jsonl` | 프로필의 네트워크 상태. 사용자 활동 이벤트와 구분 |
| `validation_summary.json` | 캐시·자산·표현 개수, 복원 상태, 네트워크 획득 상태, 검증 범위 |

분석 중 원격 URL에 접속하지 않는다. URL은 근거 데이터로만 저장한다. 캐시 원본은 수정하지 않으며 실제 자료·결과·서명 URL을 저장소에 커밋하지 않는다.

## 아티팩트 계약 v1

기존 `schemas/`의 입출력 필드 구조는 유지한다. 파일 자산용 추가 모델은 `artifacts/models.py`에 있으며 `schema_version=1.0`, `rule_version=artifact-1`을 기록한다.

- `artifact_id`: 이미지·프로필 식별자, 서비스, 자산 키로 만든 결정적 식별자. 서로 다른 프로필은 합치지 않는다.
- `role`: `upload`, `generated`, `unknown`. 입력/출력 관계가 동시에 있으면 대표 역할을 미확정으로 두고 관계를 모두 보존한다.
- `attribution`: `evidence_linked`는 구조화된 메타데이터에 연결된 경우, `pattern_candidate`는 파일 전달 경로나 이름 패턴만 맞는 경우다. 근거 연결 자체가 사용자의 실제 행동을 입증하지는 않는다.
- `source_refs`: 이미지·해시, 파티션, 사용자·프로필, 원본 파일·해시·오프셋, 캐시 키, 엔트리 ID, JSON pointer, 시각 및 보조 스트림 위치.
- `metadata`: 서비스가 보고한 크기·해시·ID·작업 상태 등. `files[].sha256`과 혼동하지 않는다.
- `files[]`: 확보한 표현별 실제 형식·확장자·검증 방법·바이트 해시·출처 목록·범위 정보.
- `relationships`: 작업/메시지/보이스/이력 → 파일 자산. 같은 자산이 여러 작업에 쓰이면 관계를 모두 남긴다.

동일 자산의 같은 바이트·표현은 출처를 모으고, 다른 포맷·크기·미리보기는 각각 보존한다. 본문 해시만으로 다른 작업의 자산을 무조건 하나로 합치지 않는다.

### 복원 상태

| 값 | 해석 |
|---|---|
| `complete` | 확보된 표현의 범위와 지원 형식 검증 통과. 미리보기의 검증 완료가 원본 확보를 의미하지 않음 |
| `partial` | 빠진 구간 또는 범위 불일치가 있음. 구간을 0으로 메워 전체 파일처럼 내보내지 않음 |
| `metadata_only` | 파일 정보 또는 JSON 응답만 확보 |
| `missing` | 전달 엔트리는 있으나 본문 없음 |
| `invalid` | 범위 충돌, 잘린 구조, 디코드 실패, 오류 HTTP 응답 등 |
| `unverified` | 지원하지 않는 형식, 디코더 부재·시간 초과, 검증할 수 없는 조각 |

자산의 대표 상태는 확보된 표현 중 가장 유용한 상태를 표시한다. **각 파일의 `representation`과 `recovery_status`를 함께 확인해야 한다.**

## 서비스별 근거

- **DeeVid**: `my-assets`의 각 `creation`에서 입력 이름·URL, 영상 URL, 커버를 별도 자산으로 추출한다. 파일명만 있는 입력도 `user-image` 자산 키와 연결한다. 여러 작업의 관계와 JSON 위치를 유지한다. 관계 없는 CDN 이미지는 역할 미확정 후보다. URL 변환 이미지는 `preview`, 영상 커버는 `cover`다.
- **ElevenLabs**: voice/sample/history ID로 연결한다. 클론 유형의 샘플 메타데이터가 입력 역할의 근거다. 기본 보이스 샘플이나 `/samples/` 경로만으로 업로드를 확정하지 않는다. `preview_url`은 별도 미리듣기 자산이고 history 항목은 생성 관련 메타데이터다. JSON 크기·해시는 오디오 크기·해시가 아니다.
- **ChatGPT**: 메시지 작성자와 첨부 ID·asset pointer를 연결한다. 같은 `estuary/content`에서 입력과 출력이 모두 전달될 수 있다. `download_url`만으로 생성 역할을 확정하지 않는다. 접근 거부 JSON은 복원된 이미지가 아니다.
- **Claude**: 메시지 문맥의 파일 참조를 사용한다. 파일 전달 경로만 있는 경우 후보다. URL의 중간 scope ID를 대화·세션 ID로 만들지 않는다. 미리보기와 실제 문서 형식을 분리한다.
- **Gemini**: `watermarked_img_<id>`는 같은 자산의 변형을 묶는 패턴 근거다. 경로·크기·파일명만으로 업로드/생성 역할을 확정하지 않는다. 현재 파일 이름 패턴만 확보된 항목의 역할은 미확정이다.

기존 `classification/services/`의 휴리스틱 결과는 보조 근거로 남지만 공개 분류 경계는 `artifact-1` 정책을 적용한다. 캐시에서 파일을 관측한 사실은 `other`/`cache_write`, 구조화된 파일 정보를 담은 응답은 `conversation`/`response`로 정규화한다. 사용자·서비스의 업로드/생성 행위와 actor를 캐시 종류만으로 만들어내지 않는다. 파일 역할은 추가 아티팩트 레코드와 관계에서 확인한다. 과거에 생성한 분류 JSONL은 새 정책을 포함하지 않으므로 `analyze`로 재분석해야 한다.

## 형식 및 영상 검증

Pillow가 PNG/JPEG/WebP/GIF를 실제 디코딩한다. WAV는 PCM 프레임 길이를 확인한다. MP4는 전체 box 범위와 필수 구조를 확인하고, 지원 음성·영상은 로컬 FFmpeg로 전체 디코딩한다. FFmpeg는 파일·파이프 프로토콜만 허용하며 시간 제한을 둔다. 시스템 FFmpeg가 없으면 `imageio-ffmpeg` 패키지의 번들 실행 파일을 사용한다.

ZIP은 CRC와 압축 해제 크기 한도를 검사하고, DOCX는 content type과 Word XML 구조까지 확인한다. ZIP이라는 이유만으로 DOCX 확장자를 붙이지 않는다. 현재 PDF/RTF/OLE는 시그니처만 확인하므로 `unverified`이며, OLE를 임의로 `.doc`로 바꾸지 않는다. 문서 구조 검증은 페이지 렌더링 검증과 다르다.

Sparse 영상은 정확한 부모 캐시 키와 세대 signature, 부모·자식 bitmap을 확인한다. 자식 ID는 16진수이고, 자식 하나는 1 MiB, 할당 bit 하나는 1 KiB다. `last_block=-1`은 부분 블록이 없다는 정상 표기다. `Content-Range`의 전체 크기와 빈 구간·중복·충돌을 비교한 뒤, 완전한 범위만 전체 파일로 조립한다. 전체 크기가 없거나 구간이 빠지면 조각으로 보존한다. 형식 검증 실패와 범위 누락을 각각 기록한다.

명세 근거: Chromium의 [sparse_control.cc](https://github.com/chromium/chromium/blob/main/net/disk_cache/blockfile/sparse_control.cc), [disk_format_base.h](https://github.com/chromium/chromium/blob/main/net/disk_cache/blockfile/disk_format_base.h). 구현은 해당 blockfile 형식에 대한 것이며 모든 Chrome 저장 형식을 지원한다는 뜻은 아니다.

## 네트워크 상태

프로필 루트와 `Network/`의 `Network Persistent State`를 원래 이름으로 획득하고 `network_acquired.json`에 별도 출처를 남긴다. 캐시가 없고 네트워크 상태 파일만 있는 프로필도 발견한다.

`not_collected`는 이전 획득본에 수집 정보가 없는 경우, `not_found`는 수집 시 해당 파일을 찾지 못한 경우, `parse_error`는 수집 파일을 해석하지 못한 경우다. 네트워크 원본 무결성 실패는 분석을 실패시킨다. `expiration`은 대체 서비스 만료, `broken_until`은 재시도 가능 시각이며 UTC 변환과 원시값을 함께 보존한다. 파티션 키는 세션 ID가 아니다.

## 검증 범위

합성 회귀 테스트는 역할 연결, 여러 파일·작업, 미리보기, HTTP 오류, 긴 이름, 위장 확장자, sparse 누락·충돌·세대 불일치, 실제 이미지·영상 디코드, 네트워크 시각 의미, JSONL·SQLite 근거 보존, 원본 변조, 기존 결과 보호를 검증한다.

`tests/test_e01_integration.py`는 원본 획득부터 결과 저장까지 네이티브 실행하고 캐시/본문/복원 파일 해시와 JSONL·SQLite 개수를 확인한다. scenario1의 로컬 Cache_Data 재분석은 scenario1 E01 전체 실행 검증과 다르다. 서비스별 전체 정답 집합이 없으므로 분류 정확도 점수는 `not_scored`다. ChromeCacheView/Hindsight와 외부 도구 전수 대조도 별도 검증 과제다.

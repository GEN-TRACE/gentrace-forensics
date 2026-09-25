# 서비스별 아티팩트 근거 (`artifact-1`)

파일 자산과 캐시 관측을 구분한다. 공개 분류 단계는 `artifacts/evidence.py`의 구조화된 참조를 사용하며, 기존 서비스 분류기의 URL 휴리스틱은 보조 근거다. 정규화·복원·출력 계약은 [artifact_outputs.md](artifact_outputs.md)를 따른다.

| 서비스 | 자산 연결 | 역할 판단 | 별도로 표시하는 항목 |
|---|---|---|---|
| ChatGPT | 메시지 첨부 `id`/`file_id`, `asset_pointer`, 해당 객체의 `download_url` | user/human 메시지 첨부는 입력 관련, assistant 메시지 파일은 생성 관련 | 문맥 없는 전달 URL, 다운로드 메타데이터, 접근 거부 JSON |
| Claude | 메시지의 파일 참조와 파일 ID | 메시지 문맥으로 판단. 전달 경로만 있으면 미확정 | preview, 출력 경로 후보, 실제 형식 미검증 문서 |
| Gemini | `watermarked_img_<id>`를 가진 변형 | 파일 이름·경로만으로 역할을 확정하지 않음 | ID 없는 후보, 같은 ID의 PNG/JPEG 변형 |
| DeeVid/Veo | `my-assets`의 각 `creation`과 자산 키 | 입력 이름·URL은 입력 관련, video URL은 생성 관련 | 커버, 변환 이미지, 이력 미연결 URL, sparse 조각 |
| ElevenLabs | voice/sample/history ID, 명시적 preview URL | 클론 유형의 샘플은 입력 관련, history 파일은 생성 관련 | 기본 보이스 샘플, 미리듣기, JSON만 남은 파일 정보 |

`evidence_linked`는 파일별 JSON 근거에 연결됐다는 뜻이다. `pattern_candidate`는 경로·이름만 맞는 후보이며 `role=unknown`이다. 서비스 문자열이 다른 호스트의 경로나 query에 포함된 것만으로 서비스에 귀속하지 않는다.

## DeeVid

`detail.creation`의 `originalImageNameUrls`, `inputUserImageName`, `videoUrl`, `noWaterMarkVideoUrl`, `resultVideoCoverImageName`을 각각 추출한다. JSON key는 대소문자를 구분한다. 각 필드의 pointer와 작업 ID·종류·상태·프롬프트·시간값을 유지하며, 한 입력이 여러 작업에 사용돼도 첫 작업만 남기지 않는다.

`/cdn-cgi/image/` 변형은 원본 자산과 연결되더라도 `preview`다. `v2_rs-image-cover-*`는 `cover`이며 동영상 파일이 아니다. Range 자식 엔트리는 독립 생성물로 집계하지 않고 부모·signature·할당 bitmap으로 복원한다.

## ElevenLabs

샘플의 이름, 서버 크기·해시, voice ID·유형을 JSON 출처와 함께 보존한다. `category=cloned/professional` 문맥이 없는 `/samples/` 응답은 업로드 확정이 아니다. preview와 history 오디오를 구분하고, 음성 metadata 응답 자체를 복원된 오디오로 내보내지 않는다. 실제 음성 본문이 없으면 `metadata_only`다.

## ChatGPT · Claude

재귀 탐색 중 파일 이름과 URL을 서로 다른 객체에서 모아 순서대로 짝짓지 않는다. 메시지 작성자 문맥과 같은 파일 객체의 필드를 함께 사용한다. `estuary/content` endpoint는 역할 판정 근거가 아니다. HTTP 오류 JSON은 실제 파일로 간주하지 않는다.

Claude `/api/<scope>/files/<id>`의 scope를 자동으로 conversation/session ID에 대입하지 않는다. `preview.webp`는 원본과 구분하며, URL의 `.doc`/`.docx`보다 ZIP/OOXML/OLE 구조 검사를 우선한다.

## Gemini

과거 픽스처에서는 `rd-gg` PNG와 `rd-gg-dl` JPEG가 생성본 변형으로 관측됐다. PDF에는 다른 해석의 사례가 있으므로 경로·파일 크기를 일반적인 업로드/생성 규칙으로 사용하지 않는다. 현재 자동 결과는 공통 ID의 표현들을 묶되, 역할은 미확정 후보로 남긴다.

## 캐시 정규화와 아티팩트 정규화

- `normalized/`는 기존 스키마의 관측 목록이다. 파일 응답은 `cache_write`, 구조화된 파일 메타데이터는 `response`로 기록하며 actor를 임의로 만들지 않는다.
- `artifacts.jsonl`은 파일 자산별 역할·근거·복원 상태와 여러 파일 표현을 담는다. 같은 캐시 레코드 수가 곧 파일 수는 아니다.
- `artifacts.sqlite3`의 `relationships`는 작업·메시지·보이스 이력과 파일 자산을 연결한다.

## 검증 구분

합성 사례는 메시지/작업 연결, 기본·클론 보이스 구분, 미리보기, 오류 응답, 형식 위장, sparse 누락·충돌을 검증한다. 실제 확보 자료에 없는 PDF 사례는 미검증으로 남긴다. URL을 현재 서버에서 재생해 본 PDF 화면은 해당 바이트가 원래 E01에 모두 존재한다는 증거가 아니다.

실자료 검증 결과와 환경 제한은 [artifact_validation.md](artifact_validation.md)에 별도 기록한다. 전체 정답 집합이 없으므로 정확도 점수는 산출하지 않는다.

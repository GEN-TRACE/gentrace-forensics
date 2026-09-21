# 서비스별 분류 패턴 (CONTRIBUTING.md 3.2.2)

분류 로직: URL/Content-Type 패턴과 JSON 필드, Gemini의 관측된 파일명·변형 관계를 사용한다.
아래에서 실제 픽스처 관측과 명세 기반 미검증 항목을 구분한다.

## ChatGPT

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `image/png` | 대화 캐시 JSON 내부 필드로 판별 |
| URL | `chatgpt.com/backend-api/estuary/content?id=file_...` | 대화 캐시 JSON(`conversation_id`), `download_url` 필드 |
| 식별자 | URL의 `file_id` | – |
| 비고 | – | 비로그인 상태에서도 `file_name`, `file_size_bytes` 는 평문 잔존. 본문은 "File stream access denied" |

현재 픽스처는 대화 목록만 포함한다. 위 업로드·생성 파일 규칙은 합성 테스트로 검증했으며
실제 트래픽 검증은 남아 있다. 생성 파일 근거를 담은 대화 JSON의 분류는 실제 파일
본문을 확보했다는 뜻이 아니다.

## Claude

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `image/webp` | `application/octet-stream` |
| URL | `claude.ai/api/[conversation_id]/files/[file_id]` | 인코딩된 URL 경로 디코딩 필요 |
| 파일명 | `preview.webp` | 디코딩 시 `/mnt/user-data/outputs/<파일명>` 형태 |

현재 픽스처에는 해당 Claude 트래픽이 없어 합성 테스트만 있다.

## Gemini (Nano Banana 2)

| 항목 | 값 |
| --- | --- |
| 도메인 | `lh3.googleusercontent.com` |
| 생성본 근거 | 파일명 또는 Content-Disposition의 `watermarked_img_<id>` |
| 관측된 변형 | `rd-gg`: 전체 해상도 PNG / `rd-gg-dl`: 다운로드 JPG |
| 연결 | 같은 `<id>`의 변형을 연결하고 `paired`, `group_variants`에 기록 |
| 판별 근거 없음 | `watermarked_img_<id>`가 없는 후보는 `unmatched` |

현재 픽스처에서는 두 변형 모두 생성본으로 관측됐으며 사용자 업로드는 확인되지 않았다.
초안의 `rd-gg`=업로드, `rd-gg-dl`=생성본 및 크기 비교 규칙은 적용하지 않는다.
ID가 있으면 짝이 없어도 생성본으로 분류하고 `paired=false`를 기록한다.

## Google Veo 3 (deevid.ai)

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `application/json` | 같은 JSON 내부 필드 |
| URL | `api.deevid.ai/my-assets` | 동일 캐시 항목 |
| JSON 필드 | `originalImageNameUrls`, `inputUserImageName` | `videoUrl`, `noWaterMarkVideoUrl` |
| CDN | `cdn2.deevid.ai/user-image/...` | `cdn2.deevid.ai/user-video/...mp4` |

`my-assets` JSON 자체는 `conversation`으로 분류한다. JSON에서 뽑은 자산 키와 CDN
항목을 연결하며 결과 커버(`v2_rs-image-cover-*`)도 생성본으로 분류한다.

## ElevenLabs

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | JSON 메타데이터 또는 오디오 | 오디오 |
| URL | `v2/voices`, `v1/voices/[voice_id]`, `v1/voices/[voice_id]/samples/[sample_id][/audio]` | `v1/history/[history_item_id]/audio` |
| JSON 필드 | `voices[].samples[]` 또는 `samples[]` → `file_name`, `size_bytes`, `hash` 등 | 이력 JSON은 `conversation`으로 분류하고 `generations[]`에 보존 |
| 파일명 예 | `forensicuser.m4a` → 서버 저장명 `forensicuser.mp3` | – |

`samples` 오디오는 클론 원본이므로 업로드로 분류한다. 현재 픽스처에는 JSON
메타데이터만 있고 오디오 바이트는 없다. JSON 메타데이터를 `file_upload`로
분류하더라도 `filename`·`size`·본문 해시는 그 캐시 응답의 값이며,
개별 오디오 파일의 정보는 `evidence.samples[]`에서 확인한다.

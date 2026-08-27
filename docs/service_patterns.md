# 서비스별 분류 패턴 (CONTRIBUTING.md 3.2.2)

분류 로직: ChatGPT·Claude·Veo3·ElevenLabs 는 URL/Content-Type 패턴 + JSON 필드 확인.
Gemini 만 페어링 방식.

## ChatGPT

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `image/png` | 대화 캐시 JSON 내부 필드로 판별 |
| URL | `chatgpt.com/backend-api/estuary/content?id=file_...` | 대화 캐시 JSON(`conversation_id`), `download_url` 필드 |
| 식별자 | URL의 `file_id` | – |
| 비고 | – | 비로그인 상태에서도 `file_name`, `file_size_bytes` 는 평문 잔존. 본문은 "File stream access denied" |

## Claude

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `image/webp` | `application/octet-stream` |
| URL | `claude.ai/api/[conversation_id]/files/[file_id]` | 인코딩된 URL 경로 디코딩 필요 |
| 파일명 | `preview.webp` | 디코딩 시 `/mnt/user-data/outputs/<파일명>` 형태 |

## Gemini (Nano Banana 2)

업로드와 생성본이 같은 도메인·같은 Content-Type·같은 파일명.

| 항목 | 값 |
| --- | --- |
| Content-Type | `image/jpeg` |
| 도메인 | `lh3.googleusercontent.com` |
| 구분 1 | URL 경로 세그먼트 `rd-gg`(업로드) vs `rd-gg-dl`(생성본) |
| 구분 2 | 파일 크기. 생성본이 워터마크 때문에 더 큼 (예: 79,589 < 149,295 bytes) |

→ 같은 파일명끼리 페어링 후 세그먼트 + 크기로 판별. 페어링 실패는 `unmatched` (Unmatched_NeedsManualReview)로 분리.

## Google Veo 3 (deevid.ai)

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `application/json` | 같은 JSON 내부 필드 |
| URL | `api.deevid.ai/my-assets` | 동일 캐시 항목 |
| JSON 필드 | `inputUserImageId`, `originalImageNameUrls` | `videoUrl`, `noWatermarkVideoUrl` |
| CDN | `cdn2.deevid.ai/user-image/...` | `cdn2.deevid.ai/user-video/...mp4` |

## ElevenLabs

| | File Upload | Generated File |
| --- | --- | --- |
| Content-Type | `application/json` | `audio/mpeg` |
| URL | `api.us.elevenlabs.io/v2/voices` | `v1/voices/[voice_id]/samples/[sample_id]` 또는 `v1/history/[history_item_id]/audio` |
| JSON 필드 | `voices[].samples[]` → `file_name`, `size_bytes`, `hash`, `preview_url` | URL 패턴으로 판별 |
| 파일명 예 | `forensicuser.m4a` → 서버 저장명 `forensicuser.mp3` | – |

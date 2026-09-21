"""Offline artifact review and queryable stores. Never embeds remote evidence URLs."""

from __future__ import annotations

import html
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from gentrace_forensics.artifacts.models import Artifact, NetworkRecord, Relationship
from gentrace_forensics.reporting import write_report

LABELS = {
    "upload": "입력·업로드 관련",
    "generated": "생성 결과 관련",
    "unknown": "미확정",
    "evidence_linked": "메타데이터 연결",
    "pattern_candidate": "패턴 후보",
    "unresolved": "미해결",
    "complete": "저장된 표현 검증 완료",
    "partial": "부분 복원",
    "metadata_only": "메타데이터만",
    "missing": "본문 없음",
    "invalid": "검증 실패",
    "unverified": "미검증",
    "original": "원본 표현",
    "preview": "미리보기",
    "cover": "커버",
    "fragment": "조각",
    "metadata": "메타데이터",
    "veo3": "DeeVid / Veo",
    "elevenlabs": "ElevenLabs",
    "chatgpt": "ChatGPT",
    "claude": "Claude",
    "gemini": "Gemini",
}


def _label(value: str) -> str:
    return html.escape(LABELS.get(value, value))


def _json(value: Any) -> str:
    return html.escape(json.dumps(value, ensure_ascii=False, indent=2))


def _html(
    artifacts: list[Artifact],
    links: list[Relationship],
    network: list[NetworkRecord],
    summary: dict[str, Any],
) -> str:
    rows = []
    for artifact in artifacts:
        previews = []
        file_rows = []
        for file in artifact.files:
            local_link = "없음"
            if file.path:
                url = html.escape("../" + file.path, quote=True)
                local_link = f'<a href="{url}" download>파일 저장</a>'
                if file.recovery_status == "complete":
                    mime = file.detected_mime or ""
                    if mime.startswith("image/"):
                        previews.append(
                            f'<a href="{url}"><img loading="lazy" src="{url}" alt="복원 이미지"></a>'
                        )
                    elif mime.startswith("audio/"):
                        previews.append(f'<audio controls preload="none" src="{url}"></audio>')
                    elif mime.startswith("video/"):
                        previews.append(f'<video controls preload="none" src="{url}"></video>')
            file_rows.append(
                f"<tr><td>{_label(file.representation)}</td><td>{_label(file.recovery_status)}</td>"
                f"<td>{html.escape(file.detected_mime or '미확인')}</td><td>{file.size:,} B</td><td>{local_link}</td></tr>"
            )
        evidence = artifact.model_dump(mode="json")
        evidence["relationships"] = [
            link.model_dump() for link in links if link.artifact_id == artifact.artifact_id
        ]
        name = html.escape(artifact.names[0] if artifact.names else artifact.asset_key)
        rows.append(
            f'<article data-service="{artifact.service}" data-role="{artifact.role}" '
            f'data-attribution="{artifact.attribution}" data-status="{artifact.recovery_status}">'
            f'<div class="heading"><span class="service">{_label(artifact.service)}</span>'
            f"<span>{_label(artifact.role)}</span><span>{_label(artifact.attribution)}</span></div>"
            f'<h2>{name}</h2><p class="id">{artifact.artifact_id}</p>'
            f'<div class="previews">{"".join(previews)}</div>'
            "<table><thead><tr><th>표현</th><th>복원 상태</th><th>실제 형식</th><th>크기</th><th>로컬 파일</th></tr></thead>"
            f"<tbody>{''.join(file_rows) or '<tr><td colspan=5>파일 정보만 남아 있으며 본문은 확보되지 않았습니다.</td></tr>'}</tbody></table>"
            f"<details><summary>근거 · 원본 위치 · 관계 보기 ({len(artifact.source_refs)})</summary>"
            f"<pre>{_json(evidence)}</pre></details></article>"
        )
    filters = []
    for key, label, options in (
        ("service", "서비스", sorted({a.service for a in artifacts})),
        ("role", "역할", ["upload", "generated", "unknown"]),
        ("attribution", "근거", ["evidence_linked", "pattern_candidate", "unresolved"]),
        (
            "status",
            "복원",
            ["complete", "partial", "metadata_only", "missing", "invalid", "unverified"],
        ),
    ):
        options_html = "".join(
            f'<option value="{value}">{_label(value)}</option>' for value in options
        )
        filters.append(
            f'<label>{label}<select id="{key}"><option value="">전체</option>{options_html}</select></label>'
        )
    network_html = "".join(
        f"<details><summary>{_label(record.service)} · {html.escape(record.record_type)}</summary>"
        f"<pre>{_json(record.model_dump(mode='json'))}</pre></details>"
        for record in network
    )
    return (
        """<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>GEN-TRACE · 아티팩트 검토</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f5f7;color:#182436;font:15px/1.6 system-ui,sans-serif}
main{max-width:1200px;margin:auto;padding:32px 24px}header{background:#15243a;color:#fff;padding:30px;border-radius:16px}
h1{margin:0 0 12px;font-size:28px}h2{font-size:17px;overflow-wrap:anywhere}a{color:#1761ab}
header a{color:#badaff}.notice{padding:16px;border-left:4px solid #d69a29;background:#fff7e5}
.filters{display:flex;gap:16px;flex-wrap:wrap;position:sticky;top:0;background:#f3f5f7;padding:16px 0;z-index:1}
label{display:grid;gap:4px}select,input{font:inherit;border:1px solid #bcc6d0;border-radius:6px;padding:8px;background:white}
article{padding:22px;background:#fff;border:1px solid #d8e0e8;border-radius:12px;margin:16px 0}
.heading{display:flex;gap:12px;flex-wrap:wrap}.heading span{background:#edf2f8;border-radius:6px;padding:3px 10px}
.heading .service{background:#183b61;color:white}.id{font:11px monospace;color:#63758a;overflow-wrap:anywhere}
.previews{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0}.previews img,.previews video{max-width:320px;max-height:240px;object-fit:contain;background:#eef1f4;border-radius:6px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #e2e7ed;overflow-wrap:anywhere}
th{font-size:12px;color:#52667e}details{margin-top:12px}summary{cursor:pointer;color:#275982}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f3f7;padding:14px;max-height:600px;overflow:auto;font-size:12px}
[hidden]{display:none!important}small{color:#54687d}footer{margin:32px 0}
</style><main><header><h1>GEN-TRACE · 아티팩트 검토</h1>"""
        + (
            f"<p>캐시 {summary['cache_entry_count']:,}건 · 파일 자산 {len(artifacts):,}개 · "
            f"검증된 로컬 표현 {summary['validated_media_files']:,}개 · 네트워크 상태 {len(network):,}건</p>"
            '<a href="../artifacts.jsonl" download>아티팩트 JSONL</a> · '
            '<a href="../artifacts.sqlite3" download>SQLite</a> · '
            '<a href="../validation_summary.json">검증 요약</a> · '
            '<a href="../normalized/normalized.jsonl" download>전체 캐시 정규화</a></header>'
            '<p class="notice">검증 완료는 저장된 표현의 바이트·형식 검증입니다. 미리보기는 원본 파일이 아니며, '
            "메타데이터 연결만으로 실제 사용자 행위를 확정하지 않습니다. 후보와 부분 파일도 근거 확인을 위해 남깁니다.</p>"
            f'<div class="filters">{"".join(filters)}<label>검색<input id="search" placeholder="이름·ID·근거 검색"></label></div>'
            f'<p id="count">{len(artifacts)}개 표시</p>{"".join(rows)}'
            "<h2>네트워크 상태</h2><p>만료·재시도 시각은 방문·생성 시각이 아닙니다.</p>"
            f"<details><summary>획득 상태</summary><pre>{_json(summary['network'])}</pre></details>{network_html}"
            "<footer><small>로컬 증거만 사용합니다. 메타데이터의 URL로 자동 접속하지 않습니다.</small></footer></main>"
        )
        + """<script>
const fields=['service','role','attribution','status'];
const articles=[...document.querySelectorAll('article')];
function filter(){const q=document.getElementById('search').value.toLowerCase();let n=0;
for(const a of articles){a.hidden=fields.some(k=>{const v=document.getElementById(k).value;return v&&a.dataset[k]!==v})||!a.textContent.toLowerCase().includes(q);if(!a.hidden)n++}
document.getElementById('count').textContent=n+'개 표시'}
for(const k of [...fields,'search'])document.getElementById(k).addEventListener('input',filter);
</script></html>"""
    )


def write_outputs(
    out: Path,
    artifacts: list[Artifact],
    relationships: list[Relationship],
    network: list[NetworkRecord],
    summary: dict[str, Any],
) -> None:
    for filename in (
        "artifacts.jsonl",
        "artifacts.sqlite3",
        "network_records.jsonl",
        "validation_summary.json",
    ):
        if (out / filename).exists():
            raise FileExistsError(f"artifact output already exists: {out / filename}")
    with (out / "artifacts.jsonl").open("x", encoding="utf-8") as output:
        for artifact in artifacts:
            output.write(artifact.model_dump_json() + "\n")
    with (out / "network_records.jsonl").open("x", encoding="utf-8") as output:
        for record in network:
            output.write(record.model_dump_json() + "\n")
    with closing(sqlite3.connect(out / "artifacts.sqlite3")) as db:
        db.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE artifacts (artifact_id TEXT PRIMARY KEY, service TEXT, role TEXT,
                attribution TEXT, recovery_status TEXT, record_json TEXT NOT NULL);
            CREATE TABLE sources (source_id TEXT PRIMARY KEY, record_json TEXT NOT NULL);
            CREATE TABLE artifact_sources (artifact_id TEXT REFERENCES artifacts, source_id TEXT REFERENCES sources,
                PRIMARY KEY (artifact_id, source_id));
            CREATE TABLE relationships (artifact_id TEXT REFERENCES artifacts, subject_id TEXT,
                relation TEXT, source_id TEXT REFERENCES sources, record_json TEXT NOT NULL);
            CREATE TABLE network_records (record_id TEXT PRIMARY KEY, service TEXT, record_json TEXT NOT NULL);
            CREATE INDEX artifacts_service_role ON artifacts(service, role);
        """)
        with db:
            for artifact in artifacts:
                db.execute(
                    "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        artifact.artifact_id,
                        artifact.service,
                        artifact.role,
                        artifact.attribution,
                        artifact.recovery_status,
                        artifact.model_dump_json(),
                    ),
                )
                for source in artifact.source_refs:
                    db.execute(
                        "INSERT OR IGNORE INTO sources VALUES (?, ?)",
                        (source.source_id, source.model_dump_json()),
                    )
                    db.execute(
                        "INSERT OR IGNORE INTO artifact_sources VALUES (?, ?)",
                        (artifact.artifact_id, source.source_id),
                    )
            for relation in relationships:
                db.execute(
                    "INSERT INTO relationships VALUES (?, ?, ?, ?, ?)",
                    (
                        relation.artifact_id,
                        relation.subject_id,
                        relation.relation,
                        relation.source_id,
                        relation.model_dump_json(),
                    ),
                )
            for record in network:
                db.execute(
                    "INSERT INTO network_records VALUES (?, ?, ?)",
                    (record.record_id, record.service, record.model_dump_json()),
                )
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("artifact database integrity check failed")
        summary["sqlite_artifact_count"] = db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[
            0
        ]
        if summary["sqlite_artifact_count"] != len(artifacts):
            raise ValueError("artifact JSONL and database counts differ")
    (out / "report").mkdir(exist_ok=False)
    (out / "report" / "index.html").write_text(
        _html(artifacts, relationships, network, summary), encoding="utf-8"
    )
    write_report(out / "validation_summary.json", summary)

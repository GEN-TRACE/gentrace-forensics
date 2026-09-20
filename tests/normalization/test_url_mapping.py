"""오프라인 도메인 추출과 서비스·콘텐츠 유형 분류 계약."""

import pytest

from gentrace_forensics.normalization.mapping import content_type_group, normalize_service
from gentrace_forensics.normalization.url import decode_path, domain_of, full_host


@pytest.mark.parametrize(
    ("url", "host", "domain"),
    [
        ("https://User:password@A.Example.CO.UK:443/file", "a.example.co.uk", "example.co.uk"),
        ("http://127.0.0.1:8000/file", "127.0.0.1", "127.0.0.1"),
        ("localhost/path", "localhost", "localhost"),
        ("https://CHATGPT.COM./", "chatgpt.com", "chatgpt.com"),
        ("", "", ""),
    ],
)
def test_host_and_registrable_domain(url: str, host: str, domain: str):
    assert full_host(url) == host
    assert domain_of(url) == domain


def test_encoded_output_path():
    assert decode_path("https://example.test/%EB%B3%B4%EA%B3%A0%EC%84%9C.pdf") == "/보고서.pdf"


@pytest.mark.parametrize(
    ("mime", "group"),
    [
        ("Application/JSON; charset=utf-8", "json"),
        ("application/problem+json", "json"),
        ("image/avif", "image"),
        ("application/x-custom", "application/x-custom"),
        (None, None),
    ],
)
def test_content_groups(mime: str | None, group: str | None):
    assert content_type_group(mime) == group


def test_service_aliases_and_unknown_names():
    assert normalize_service(" OpenAI ") == "chatgpt"
    assert normalize_service("OtherService") == "otherservice"
    assert normalize_service(None) is None

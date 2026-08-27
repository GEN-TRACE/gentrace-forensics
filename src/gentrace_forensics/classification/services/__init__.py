"""서비스별 분류기 레지스트리.

CONTRIBUTING.md 3.2.2 절. ChatGPT·Claude·Veo3·ElevenLabs 는 URL/Content-Type 패턴 +
JSON 필드. Gemini 만 페어링 방식.
"""

from gentrace_forensics.classification.services.base import (
    Classification,
    ServiceClassifier,
)
from gentrace_forensics.classification.services.chatgpt import ChatGPTClassifier
from gentrace_forensics.classification.services.claude import ClaudeClassifier
from gentrace_forensics.classification.services.elevenlabs import ElevenLabsClassifier
from gentrace_forensics.classification.services.gemini import GeminiClassifier
from gentrace_forensics.classification.services.veo3 import Veo3Classifier

ALL_CLASSIFIERS: list[type[ServiceClassifier]] = [
    ChatGPTClassifier,
    ClaudeClassifier,
    GeminiClassifier,
    Veo3Classifier,
    ElevenLabsClassifier,
]

__all__ = [
    "ALL_CLASSIFIERS",
    "ChatGPTClassifier",
    "Classification",
    "ClaudeClassifier",
    "ElevenLabsClassifier",
    "GeminiClassifier",
    "ServiceClassifier",
    "Veo3Classifier",
]

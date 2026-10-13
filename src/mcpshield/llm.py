"""The one LLM interface. `OllamaLLM` (local models) and `MockLLM` (deterministic rules) implement
`LLMClient`; `make_llm` picks one from config. Agents receive an `LLMClient` by injection.
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
from typing import Any, Protocol, TypeVar, runtime_checkable

import httpx
from pydantic import BaseModel, ValidationError

from mcpshield import text_utils
from mcpshield.config import Settings
from mcpshield.schemas import IntentResult, JudgeVerdict, Policies

log = logging.getLogger(__name__)

M = TypeVar("M", bound=BaseModel)

REQUEST_TAG = "user_request"
UNTRUSTED_TAG = "untrusted"


def tagged(tag: str, text: str) -> str:
    return f"<{tag}>\n{text}\n</{tag}>"


def extract_tag(tag: str, prompt: str) -> str:
    match = re.search(rf"<{tag}>\n(.*?)\n</{tag}>", prompt, re.S)
    return match.group(1) if match else ""


class LLMUnavailable(RuntimeError):
    pass


@runtime_checkable
class LLMClient(Protocol):
    backend: str
    calls: int

    @property
    def model(self) -> str: ...

    def complete(self, prompt: str, *, system: str = "", temperature: float | None = None) -> str: ...

    def structured(
        self, prompt: str, schema: type[M], *, system: str = "", temperature: float | None = None
    ) -> M | None:
        """Return a schema-valid object, retrying on invalid output; None means fall back conservatively."""
        ...


def _parse(schema: type[M], raw: str) -> M:
    match = re.search(r"\{.*\}", raw, re.S)
    return schema.model_validate_json(match.group(0) if match else raw)


class OllamaLLM:
    backend = "ollama"

    def __init__(self, settings: Settings, model: str | None = None) -> None:
        self._cfg = settings.llm
        self._model = model or settings.llm.judge_model
        self._client = httpx.Client(base_url=self._cfg.ollama_url, timeout=self._cfg.timeout_s)
        self.calls = 0

    @property
    def model(self) -> str:
        return self._model

    def available(self) -> bool:
        try:
            tags = self._client.get("/api/tags").json()
        except httpx.HTTPError:
            return False
        names = {m.get("name", "") for m in tags.get("models", [])}
        return self._model in names or f"{self._model}:latest" in names

    def _chat(self, prompt: str, system: str, temperature: float | None, fmt: dict[str, Any] | None) -> str:
        messages = [{"role": "system", "content": system}] if system else []
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "think": False,
            "options": {"temperature": self._cfg.temperature if temperature is None else temperature},
        }
        if fmt is not None:
            payload["format"] = fmt
        self.calls += 1
        try:
            response = self._client.post("/api/chat", json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailable(str(exc)) from exc
        return str(response.json()["message"]["content"])

    def complete(self, prompt: str, *, system: str = "", temperature: float | None = None) -> str:
        return self._chat(prompt, system, temperature, None)

    def structured(
        self, prompt: str, schema: type[M], *, system: str = "", temperature: float | None = None
    ) -> M | None:
        for attempt in range(self._cfg.max_retries + 1):
            raw = self._chat(prompt, system, temperature, schema.model_json_schema())
            try:
                return _parse(schema, raw)
            except (ValidationError, ValueError):
                log.warning("invalid %s output from %s (attempt %d)", schema.__name__, self._model, attempt + 1)
        return None

    def chat_model(self) -> Any:
        """LangChain chat model for the host agent's native tool calling."""
        from langchain_ollama import ChatOllama

        return ChatOllama(model=self._model, base_url=self._cfg.ollama_url, temperature=self._cfg.temperature)


class MockLLM:
    """Deterministic rule-based stand-in for an LLM, used for tests, CI and the offline demo.

    Structured requests are answered by schema type: `IntentResult` via keyword rules, `JudgeVerdict`
    via instruction-pattern hits on the untrusted section of the prompt. Sampling at temperature > 0
    flips borderline votes with a prompt-seeded RNG so self-consistency has something to aggregate.
    """

    backend = "mock"

    def __init__(self, policies: Policies, model: str = "mock-rules-v1") -> None:
        self._policies = policies
        self._model = model
        self._patterns = text_utils.compile_patterns(policies.instruction_patterns)
        self.calls = 0
        self._samples = 0

    @property
    def model(self) -> str:
        return self._model

    def complete(self, prompt: str, *, system: str = "", temperature: float | None = None) -> str:
        self.calls += 1
        return "OK"

    def structured(
        self, prompt: str, schema: type[M], *, system: str = "", temperature: float | None = None
    ) -> M | None:
        self.calls += 1
        if schema is IntentResult:
            return schema.model_validate(self._intent(extract_tag(REQUEST_TAG, prompt) or prompt).model_dump())
        if schema is JudgeVerdict:
            return schema.model_validate(self._judge(prompt, temperature or 0.0).model_dump())
        return None

    def _intent(self, request: str) -> IntentResult:
        lowered = request.lower()
        scores = {
            intent: sum(1 for kw in keywords if kw in lowered)
            for intent, keywords in self._policies.intent_keywords.items()
        }
        best = max(scores, key=lambda k: scores[k], default=self._policies.default_intent)
        if not scores or scores[best] == 0:
            return IntentResult(intent=self._policies.default_intent, confidence=0.3)
        return IntentResult(intent=best, confidence=min(1.0, 0.5 + 0.2 * scores[best]))

    def _judge(self, prompt: str, temperature: float) -> JudgeVerdict:
        untrusted = extract_tag(UNTRUSTED_TAG, prompt) or prompt
        hits = text_utils.instruction_hits(text_utils.reveal(untrusted), self._patterns)
        malicious = bool(hits)
        confidence = min(0.95, 0.55 + 0.15 * len(hits)) if hits else 0.8
        if temperature > 0 and len(hits) <= 1:
            self._samples += 1
            seed = hashlib.sha256(f"{prompt}|{self._samples}".encode()).hexdigest()
            if random.Random(seed).random() < temperature * 0.3:
                malicious = not malicious
                confidence = 0.5
        reason = f"instruction patterns: {', '.join(h.label for h in hits)}" if hits else "no instructions found"
        return JudgeVerdict(malicious=malicious, serves_request=not malicious, confidence=confidence, reason=reason)


def make_llm(settings: Settings, policies: Policies, model: str | None = None) -> LLMClient:
    """Select the backend from config; an unreachable Ollama falls back to MockLLM with a warning."""
    if settings.llm.backend == "ollama":
        ollama = OllamaLLM(settings, model)
        if ollama.available():
            return ollama
        log.warning("Ollama model %s unavailable at %s; using MockLLM", ollama.model, settings.llm.ollama_url)
    return MockLLM(policies)

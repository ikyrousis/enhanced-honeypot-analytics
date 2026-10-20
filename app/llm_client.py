"""Minimal provider-agnostic LLM client for OpenAI-compatible chat endpoints.

Configuration comes from .env or the environment (env wins):

    LLM_BASE_URL   base url exposing /chat/completions (examples in .env.example)
    LLM_API_KEY    bearer token for that endpoint
    LLM_MODEL      model id as known to that provider

No provider-specific code lives anywhere else in the repository.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from app.config import ROOT


def _read_dotenv() -> dict[str, str]:
    values: dict[str, str] = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    return values


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    api_key: str
    model: str


def load_llm_config() -> LLMConfig:
    values = _read_dotenv()
    values.update({k: v for k, v in os.environ.items() if v})
    base_url = values.get("LLM_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
    api_key = values.get("LLM_API_KEY", "")
    model = values.get("LLM_MODEL", "")
    if not api_key:
        raise SystemExit("Set LLM_API_KEY in .env or the environment (see .env.example).")
    if not model:
        raise SystemExit("Set LLM_MODEL in .env or the environment (see .env.example).")
    return LLMConfig(base_url=base_url, api_key=api_key, model=model)


@dataclass
class LLMResponse:
    text: str
    model: str
    usage: dict | None
    raw: dict


class LLMClient:
    """One-shot completion against any OpenAI-compatible chat endpoint."""

    def __init__(self, config: LLMConfig):
        self.config = config

    def complete(self, prompt: str, temperature: float = 0.7) -> LLMResponse:
        response = httpx.post(
            f"{self.config.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.config.model,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=180,
        )
        response.raise_for_status()
        payload = response.json()
        return LLMResponse(
            text=payload["choices"][0]["message"]["content"],
            model=payload.get("model", self.config.model),
            usage=payload.get("usage"),
            raw=payload,
        )

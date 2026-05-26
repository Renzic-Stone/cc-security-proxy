from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from .prompts import SYSTEM_PROMPT

if TYPE_CHECKING:
    from ..config import Config

logger = logging.getLogger("cc-security-proxy.llm")


@dataclass
class LLMVerdict:
    verdict: str  # SAFE | SUSPICIOUS | MALICIOUS
    reason: str
    confidence: float
    raw_response: str = ""
    error: str = ""

    @classmethod
    def from_error(cls, error: str) -> LLMVerdict:
        return cls(verdict="SUSPICIOUS", reason=f"LLM error: {error}", confidence=0.5, error=error)


class LLMClient:
    def __init__(self, config: Config):
        self.config = config
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.llm_base_url.rstrip("/"),
                headers={
                    "Authorization": f"Bearer {self.config.llm_api_key}",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(self.config.llm_timeout),
            )
        return self._client

    async def audit(self, text: str) -> LLMVerdict:
        trimmed = text[:16000]

        body = {
            "model": self.config.llm_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Audit this API response:\n\n{trimmed}"},
            ],
            "temperature": 0.0,
            "max_tokens": 256,
        }

        try:
            resp = await self.client.post("/chat/completions", json=body)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            return self._parse(content)
        except httpx.TimeoutException:
            return LLMVerdict.from_error("LLM request timed out")
        except httpx.HTTPStatusError as exc:
            return LLMVerdict.from_error(f"LLM HTTP {exc.response.status_code}")
        except Exception as exc:
            return LLMVerdict.from_error(str(exc))

    def _parse(self, content: str) -> LLMVerdict:
        content = content.strip()
        # Strip markdown code fences if present
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

        try:
            data = json.loads(content)
            return LLMVerdict(
                verdict=data.get("verdict", "SUSPICIOUS").upper(),
                reason=data.get("reason", "No reason provided"),
                confidence=float(data.get("confidence", 0.5)),
                raw_response=content,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("failed to parse LLM response: %s", exc)
            # Heuristic: try to find the verdict in the text
            upper = content.upper()
            if "MALICIOUS" in upper:
                return LLMVerdict(verdict="MALICIOUS", reason=content, confidence=0.7, raw_response=content)
            if "SUSPICIOUS" in upper:
                return LLMVerdict(verdict="SUSPICIOUS", reason=content, confidence=0.5, raw_response=content)
            if "SAFE" in upper:
                return LLMVerdict(verdict="SAFE", reason=content, confidence=0.7, raw_response=content)
            return LLMVerdict(verdict="SUSPICIOUS", reason=f"Unparseable: {content[:200]}", confidence=0.5, raw_response=content)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

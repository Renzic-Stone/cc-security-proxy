"""LLM client with token caching, Unicode defense, and verdict cache."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from .prompts import SYSTEM_PROMPT

if TYPE_CHECKING:
    from ..config import Config

logger = logging.getLogger("cc-security-proxy.llm")

# Module-level dedup cache
_dedup_cache: OrderedDict = OrderedDict()
_DEDUP_MAX = 50

# Module-level verdict cache with warmup protection
_verdict_cache: OrderedDict = OrderedDict()
_VERDICT_MAX = 200
_VERDICT_TTL = 1800
_CACHE_WARMUP = 5
_audit_call_count = 0


def _normalize_for_dedup(text: str) -> str:
    text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', '[TIME]', text)
    text = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '[UUID]', text)
    text = re.sub(r'[a-f0-9]{32,64}', '[HEX]', text)
    text = unicodedata.normalize('NFKC', text)
    return text


def _response_fingerprint(text: str) -> str:
    return hashlib.sha256(_normalize_for_dedup(text[:3000]).encode()).hexdigest()


def _verdict_cache_key(scanner_info: str, user_prompt: str, resp_fp: str) -> str:
    return f"{scanner_info}|{user_prompt[:100]}|{resp_fp}"


@dataclass
class LLMVerdict:
    verdict: str
    reason: str
    confidence: float
    raw_response: str = ""
    error: str = ""
    from_cache: bool = False

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
                headers={"Authorization": f"Bearer {self.config.llm_api_key}", "Content-Type": "application/json"},
                timeout=httpx.Timeout(self.config.llm_timeout),
            )
        return self._client

    @staticmethod
    def _sanitize(text: str) -> str:
        # NFKC: collapse fullwidth/homoglyphs before pattern matching
        text = unicodedata.normalize('NFKC', text)
        text = re.sub(r'[​-‍﻿‪-‮⁠­]', '', text)
        text = re.sub(r'(?i)^\s*\[SYSTEM[^\]]*OVERRIDE[^\]]*\].*$', '[REDACTED]', text, flags=re.MULTILINE)
        text = re.sub(r'(?i)^\s*\[ADMIN[^\]]*\].*$', '[REDACTED]', text, flags=re.MULTILINE)
        text = re.sub(r'\{\s*"verdict"\s*:\s*"SAFE"[^}]*\}', '[REDACTED-JSON]', text, flags=re.IGNORECASE)
        text = re.sub(r'(?i)(?:IGNORE|DISREGARD)\s+(?:ALL\s+)?(?:PREVIOUS|ABOVE|SECURITY)\s+(?:INSTRUCTIONS?|RULES?)', '[REDACTED]', text)
        text = re.sub(r'(?i)OVERRIDE\s+(?:ANY|ALL)\s+SECURITY\s+(?:CONCERNS?|RULES?)', '[REDACTED]', text)
        text = re.sub(r'(?i)CLASSIFY\s+(?:THIS|AS)\s+SAFE', '[REDACTED]', text)
        text = re.sub(r'(?i)DO\s+NOT\s+FLAG', '[REDACTED]', text)
        return text

    async def audit(self, text: str, scanner_info: str = "", user_prompt: str = "") -> LLMVerdict:
        global _audit_call_count
        _audit_call_count += 1
        warmup = _audit_call_count <= _CACHE_WARMUP

        trimmed = self._sanitize(text[:16000])
        resp_fp = _response_fingerprint(trimmed)

        # Dedup cache
        if not warmup and resp_fp in _dedup_cache:
            entry = _dedup_cache[resp_fp]
            if time.time() - entry["time"] < 3600:
                entry["time"] = time.time()
                _dedup_cache.move_to_end(resp_fp)
                logger.debug("dedup HIT")
                cached = entry["verdict"]
                cached.from_cache = True
                return cached

        # Verdict cache with poisoning defense
        vc_key = _verdict_cache_key(scanner_info, user_prompt, resp_fp)
        if not warmup and vc_key in _verdict_cache:
            entry = _verdict_cache[vc_key]
            if time.time() - entry["time"] < _VERDICT_TTL:
                cached_len = entry.get("text_length", 0)
                if cached_len > 0 and (len(trimmed) / max(cached_len, 1) > 2.0):
                    logger.warning("cache poison suspected — length ratio %.1fx", len(trimmed) / cached_len)
                    del _verdict_cache[vc_key]
                else:
                    _verdict_cache.move_to_end(vc_key)
                    logger.debug("verdict cache HIT")
                    cached = entry["verdict"]
                    cached.from_cache = True
                    return cached
            else:
                del _verdict_cache[vc_key]

        # Build prompt — static system first, dynamic user last
        parts = []
        if user_prompt:
            parts.append(f"User's original request: {user_prompt[:2000]}")
        if scanner_info:
            parts.append(scanner_info)
        parts.append(f"API response to audit:\n\n{trimmed}")
        user_msg = "\n\n".join(parts)

        body = {
            "model": self.config.llm_model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_msg}],
            "temperature": 0.0,
            "max_tokens": 256,
        }

        try:
            resp = await self.client.post("/chat/completions", json=body)
            resp.raise_for_status()
            data = resp.json()
            usage = data.get("usage", {})
            hit = usage.get("prompt_cache_hit_tokens", 0)
            miss = usage.get("prompt_cache_miss_tokens", 0)
            if hit + miss > 0:
                logger.debug("cache: hit=%d miss=%d rate=%.0f%%", hit, miss, hit/(hit+miss)*100)
            content = data["choices"][0]["message"]["content"]
            verdict = self._parse(content)
        except httpx.TimeoutException:
            verdict = LLMVerdict.from_error("LLM request timed out")
        except httpx.HTTPStatusError as exc:
            verdict = LLMVerdict.from_error(f"LLM HTTP {exc.response.status_code}")
        except Exception as exc:
            verdict = LLMVerdict.from_error(str(exc))

        # Store in caches
        _dedup_cache[resp_fp] = {"verdict": verdict, "time": time.time()}
        if len(_dedup_cache) > _DEDUP_MAX:
            _dedup_cache.popitem(last=False)
        if not verdict.error:
            _verdict_cache[vc_key] = {"verdict": verdict, "time": time.time(), "text_length": len(trimmed)}
            if len(_verdict_cache) > _VERDICT_MAX:
                _verdict_cache.popitem(last=False)

        return verdict

    def _parse(self, content: str) -> LLMVerdict:
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()
        try:
            data = json.loads(content)
            return LLMVerdict(verdict=data.get("verdict","SUSPICIOUS").upper(),
                reason=data.get("reason",""), confidence=float(data.get("confidence",0.5)), raw_response=content)
        except (json.JSONDecodeError, ValueError):
            logger.warning("parse failed: %s", content[:100])
            upper = content.upper()
            if "MALICIOUS" in upper: return LLMVerdict(verdict="MALICIOUS", reason=content, confidence=0.7, raw_response=content)
            if "SUSPICIOUS" in upper: return LLMVerdict(verdict="SUSPICIOUS", reason=content, confidence=0.5, raw_response=content)
            if "SAFE" in upper: return LLMVerdict(verdict="SAFE", reason=content, confidence=0.7, raw_response=content)
            return LLMVerdict(verdict="SUSPICIOUS", reason=f"Unparseable: {content[:200]}", confidence=0.5, raw_response=content)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

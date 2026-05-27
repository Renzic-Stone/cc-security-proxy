from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from ..llm.client import LLMClient
from ..sandbox.executor import SandboxExecutor
from ..sandbox.rules import analyze
from ..scanner import scan, max_severity
from .base import BaseMode, Decision

if TYPE_CHECKING:
    from ..config import Config

logger = logging.getLogger("cc-security-proxy.mode.smart")

EXTREME_THRESHOLD = 0.95

# Hard-bottom-line patterns: block regardless of user intent.
# These are patterns that have NO legitimate use case in an API response.
HARD_BLOCK_PATTERNS = [
    (re.compile(r"(?:curl|wget)\s+https?://[^\s|&]+\s*\|\s*(?:ba)?sh", re.IGNORECASE),
     "Remote URL piped to shell execution"),
    (re.compile(r"(?:Invoke-WebRequest|iwr|irm)\s+https?://[^\s|&]+\s*\|\s*(?:Invoke-Expression|iex)", re.IGNORECASE),
     "PowerShell remote download piped to Invoke-Expression"),
    (re.compile(r"powershell\s+.*-EncodedCommand\s+[A-Za-z0-9+/=]{40,}", re.IGNORECASE),
     "PowerShell obfuscated EncodedCommand"),
    (re.compile(r"certutil\s+-decode\s+.*\s+.*\.(?:exe|dll)", re.IGNORECASE),
     "Certutil decode to executable"),
    (re.compile(r"mshta\s+https?://", re.IGNORECASE),
     "MSHTA remote script execution"),
    (re.compile(r"rundll32\s+.*,.*https?://", re.IGNORECASE),
     "Rundll32 remote URL execution"),
]


def _check_hard_blocks(text: str) -> tuple[bool, str]:
    """Check hard-bottom-line patterns that block regardless of user intent."""
    for pattern, desc in HARD_BLOCK_PATTERNS:
        m = pattern.search(text)
        if m:
            return True, f"Hard block: {desc} — '{m.group(0)[:120]}'"
    return False, ""


class SmartMode(BaseMode):
    name = "smart"

    def __init__(self, config: Config):
        self.config = config
        self._llm: LLMClient | None = None
        self._executor: SandboxExecutor | None = None

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient(self.config)
        return self._llm

    @property
    def executor(self) -> SandboxExecutor:
        if self._executor is None:
            self._executor = SandboxExecutor(self.config)
        return self._executor

    async def check(self, path: str, raw_body: bytes, text: str, user_prompt: str = "") -> Decision:
        # Step 0: Hard-bottom-line check — block regardless of user intent
        is_hard, hard_reason = _check_hard_blocks(text)
        if is_hard:
            logger.info("hard block: %s", hard_reason)
            return Decision(action="block", reason=hard_reason, confidence=0.99)

        # Step 1: Static pre-scan
        matches = scan(text)
        severity = max_severity(matches)
        match_count = len(matches)

        # Only block EXTREME threats immediately (severity >= 0.95)
        if severity >= EXTREME_THRESHOLD:
            desc = ", ".join(m.description for m in matches[:5])
            logger.info("static: EXTREME threat (%.2f), blocking immediately", severity)
            return Decision(
                action="block",
                reason="Static pre-scan: extreme threat detected",
                details=desc,
                confidence=severity,
            )

        # Clean + small + no URLs → forward without LLM
        has_url = bool(re.search(r"https?://[^\s]{5,}", text))
        if severity == 0.0 and len(text) < 500 and not has_url:
            logger.debug("static: clean and small, forwarding")
            return Decision(action="forward", reason="Static pre-scan clean", confidence=1.0)

        # Step 2: LLM audit — primary decision maker
        # Build context: scanner findings + user intent
        scanner_info = ""
        if matches:
            scanner_info = "Scanner findings: " + "; ".join(
                f"{m.description} (severity={m.severity:.2f})" for m in matches[:5]
            )

        logger.info(
            "LLM audit: %d chars response, %d scanner matches, user_prompt=%d chars",
            len(text), match_count, len(user_prompt),
        )
        verdict = await self.llm.audit(text, scanner_info, user_prompt=user_prompt)

        logger.info(
            "LLM verdict: %s (confidence=%.2f, reason=%s)",
            verdict.verdict, verdict.confidence, verdict.reason,
        )

        # LLM is confident → follow its judgment
        if verdict.verdict == "MALICIOUS" and verdict.confidence >= 0.8:
            return Decision(
                action="block",
                reason=f"LLM: {verdict.reason}",
                details=f"confidence={verdict.confidence:.2f}",
                confidence=verdict.confidence,
            )

        if verdict.verdict == "SAFE" and verdict.confidence >= 0.9:
            return Decision(
                action="forward",
                reason=f"LLM: {verdict.reason}",
                confidence=verdict.confidence,
            )

        # Step 3: LLM uncertain → sandbox fallback
        logger.info("LLM uncertain (verdict=%s, conf=%.2f), fallback to sandbox", verdict.verdict, verdict.confidence)

        if not self.executor.available():
            logger.warning("Docker unavailable for sandbox")
            # Conservative: if scanner found anything AND LLM wasn't confident SAFE → block
            if verdict.verdict == "MALICIOUS" or match_count > 0:
                return Decision(
                    action="block",
                    reason="LLM uncertain + scanner matches + sandbox unavailable",
                    details=verdict.reason,
                    confidence=0.7,
                )
            return Decision(
                action="forward",
                reason="LLM uncertain, sandbox unavailable, no scanner matches",
                confidence=0.5,
            )

        try:
            self.executor.ensure_image()
        except Exception as exc:
            logger.error("sandbox image build failed: %s", exc)
            if verdict.verdict == "MALICIOUS":
                return Decision(action="block", reason="LLM flagged malicious, sandbox failed", details=str(exc))
            return Decision(action="forward", reason="LLM uncertain, sandbox unavailable", confidence=0.5)

        try:
            result = await self.executor.run(text)
        except Exception as exc:
            logger.error("sandbox execution failed: %s", exc)
            return Decision(action="block", reason="Sandbox execution failed", details=str(exc))

        findings = analyze(result)
        if findings:
            logger.warning("sandbox found %d issue(s): %s", len(findings), "; ".join(findings))
            return Decision(
                action="block",
                reason=f"Sandbox confirmed: {findings[0]}",
                details="; ".join(findings[:5]),
                confidence=0.95,
            )

        logger.info("sandbox clean, forwarding")
        return Decision(action="forward", reason="Sandbox analysis clean", confidence=0.85)

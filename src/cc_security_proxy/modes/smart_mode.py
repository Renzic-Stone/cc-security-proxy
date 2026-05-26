from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..llm.client import LLMClient
from ..sandbox.executor import SandboxExecutor
from ..sandbox.rules import analyze
from ..scanner import scan, max_severity
from .base import BaseMode, Decision

if TYPE_CHECKING:
    from ..config import Config

logger = logging.getLogger("cc-security-proxy.mode.smart")


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

    async def check(self, path: str, raw_body: bytes, text: str) -> Decision:
        # Step 1: Fast static pre-scan
        matches = scan(text)
        severity = max_severity(matches)
        match_count = len(matches)

        # Obvious threats: block immediately
        if severity >= 0.80:
            desc = ", ".join(m.description for m in matches[:5])
            logger.info("static pre-scan: high severity %.2f, blocking immediately", severity)
            return Decision(
                action="block",
                reason="Static pre-scan: obvious threat detected",
                details=desc,
                confidence=severity,
            )

        # Multiple medium-severity patterns: cumulative threat
        high_matches = [m for m in matches if m.severity >= 0.70]
        if len(high_matches) >= 3:
            desc = ", ".join(m.description for m in high_matches[:5])
            logger.info("static pre-scan: %d medium+ patterns, blocking", len(high_matches))
            return Decision(
                action="block",
                reason=f"Static pre-scan: {len(high_matches)} suspicious patterns detected",
                details=desc,
                confidence=0.85,
            )

        # Clean: skip LLM, forward directly
        if severity == 0.0 and len(text) < 500:
            logger.debug("static pre-scan: clean and small, forwarding")
            return Decision(action="forward", reason="Static pre-scan clean", confidence=1.0)

        # Step 2: LLM audit with scanner context
        scanner_info = ""
        if matches:
            scanner_info = "Scanner findings: " + "; ".join(
                f"{m.description} (severity={m.severity:.2f})" for m in matches[:5]
            )
        logger.info("sending to LLM for audit (%d chars, %d scanner matches)", len(text), match_count)
        verdict = await self.llm.audit(text, scanner_info)

        logger.info(
            "LLM verdict: %s (confidence=%.2f, reason=%s)",
            verdict.verdict,
            verdict.confidence,
            verdict.reason,
        )

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

        # Step 3: LLM was uncertain or low confidence → fall back to sandbox
        logger.info(
            "LLM uncertain (verdict=%s, confidence=%.2f), falling back to sandbox",
            verdict.verdict,
            verdict.confidence,
        )

        if not self.executor.available():
            logger.warning("Docker not available for sandbox fallback")
            # If scanner found anything + LLM wasn't confident SAFE → block
            if verdict.verdict == "MALICIOUS" or match_count > 0:
                return Decision(
                    action="block",
                    reason="LLM flagged malicious or scanner found matches, sandbox unavailable",
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
            logger.error("failed to build sandbox image: %s", exc)
            if verdict.verdict == "MALICIOUS":
                return Decision(
                    action="block",
                    reason="LLM flagged malicious, sandbox build failed",
                    details=str(exc),
                )
            return Decision(
                action="forward",
                reason="LLM uncertain, sandbox unavailable",
                confidence=0.5,
            )

        try:
            result = await self.executor.run(text)
        except Exception as exc:
            logger.error("sandbox execution failed: %s", exc)
            if verdict.verdict == "MALICIOUS":
                return Decision(
                    action="block",
                    reason="LLM flagged malicious, sandbox failed",
                    details=str(exc),
                )
            return Decision(
                action="block",
                reason="Sandbox execution failed, blocking to be safe",
                details=str(exc),
            )

        findings = analyze(result)

        if findings:
            logger.warning("sandbox found %d issue(s): %s", len(findings), "; ".join(findings))
            return Decision(
                action="block",
                reason=f"Sandbox confirmed: {findings[0]}",
                details="; ".join(findings[:5]),
                confidence=0.95,
            )

        logger.info("sandbox clean, forwarding. %s", result.summary())
        return Decision(
            action="forward",
            reason="Sandbox analysis clean after LLM review",
            confidence=0.85,
        )

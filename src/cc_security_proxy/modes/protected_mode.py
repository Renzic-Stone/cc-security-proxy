from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..scanner import scan, max_severity
from ..sandbox.executor import SandboxExecutor
from ..sandbox.rules import analyze
from .base import BaseMode, Decision

if TYPE_CHECKING:
    from ..config import Config

logger = logging.getLogger("cc-security-proxy.mode.protected")


class ProtectedMode(BaseMode):
    name = "protected"

    def __init__(self, config: Config):
        self.config = config
        self._executor: SandboxExecutor | None = None

    @property
    def executor(self) -> SandboxExecutor:
        if self._executor is None:
            self._executor = SandboxExecutor(self.config)
        return self._executor

    async def check(self, path: str, raw_body: bytes, text: str) -> Decision:
        # Step 1: Fast static scan
        matches = scan(text)
        severity = max_severity(matches)

        if severity > 0.9:
            desc = ", ".join(m.description for m in matches[:5])
            return Decision(
                action="block",
                reason=f"Static scan: high-severity patterns detected",
                details=desc,
                confidence=severity,
            )

        if severity == 0.0:
            logger.debug("static scan clean, skipping sandbox")
            return Decision(action="forward", reason="Static scan clean")

        # Step 2: Run in sandbox
        logger.info(
            "static scan found %d issues (severity=%.2f), running sandbox",
            len(matches),
            severity,
        )

        if not self.executor.available():
            logger.warning("Docker not available, falling back to static scan result")
            if severity > 0.7:
                return Decision(
                    action="block",
                    reason="Docker unavailable, blocked based on static scan severity",
                    details=f"severity={severity:.2f}",
                    confidence=severity,
                )
            return Decision(
                action="forward",
                reason="Docker unavailable, static scan below threshold",
                confidence=1 - severity,
            )

        try:
            self.executor.ensure_image()
        except Exception as exc:
            logger.error("failed to build sandbox image: %s", exc)
            if severity > 0.7:
                return Decision(
                    action="block",
                    reason="Sandbox unavailable, blocked based on static scan",
                    details=str(exc),
                )
            return Decision(
                action="forward",
                reason="Sandbox unavailable, static scan below threshold",
            )

        try:
            result = await self.executor.run(text)
        except Exception as exc:
            logger.error("sandbox execution failed: %s", exc)
            return Decision(
                action="block",
                reason="Sandbox execution failed",
                details=str(exc),
            )

        findings = analyze(result)

        if findings:
            logger.warning(
                "sandbox found %d issue(s): %s",
                len(findings),
                "; ".join(findings),
            )
            return Decision(
                action="block",
                reason=f"Sandbox detected suspicious behavior",
                details="; ".join(findings[:5]),
                confidence=0.9,
            )

        logger.info("sandbox clean: %s", result.summary())
        return Decision(action="forward", reason="Sandbox analysis clean")

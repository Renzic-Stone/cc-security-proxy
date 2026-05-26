from __future__ import annotations

import logging

from ..scanner import scan, max_severity
from .base import BaseMode, Decision

logger = logging.getLogger("cc-security-proxy.mode.default")


class DefaultMode(BaseMode):
    name = "default"

    async def check(self, path: str, raw_body: bytes, text: str) -> Decision:
        matches = scan(text)
        if matches:
            severity = max_severity(matches)
            descriptions = ", ".join(m.description for m in matches[:5])
            logger.warning(
                "scanner found %d issue(s) [severity=%.2f]: %s",
                len(matches),
                severity,
                descriptions,
            )
        else:
            logger.debug("scanner clean")
        return Decision(action="forward", reason="default mode: always forward")

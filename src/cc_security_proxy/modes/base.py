from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Decision:
    action: str  # "forward" | "block"
    reason: str
    details: str = ""
    confidence: float = 1.0


class BaseMode(ABC):
    name: str = "base"

    @abstractmethod
    async def check(self, path: str, raw_body: bytes, text: str, user_prompt: str = "") -> Decision: ...

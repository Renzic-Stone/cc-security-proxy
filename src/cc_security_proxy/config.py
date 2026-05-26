from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

Mode = Literal["default", "protected", "smart"]


def _load_env_file() -> None:
    cwd = Path.cwd()
    for p in (cwd / ".env", cwd.parent / ".env"):
        if p.exists():
            load_dotenv(p)
            return
    load_dotenv()


@dataclass
class Config:
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    upstream_url: str = ""
    mode: Mode = "smart"
    log_level: str = "INFO"

    # LLM
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_timeout: int = 10

    # Sandbox
    sandbox_timeout: int = 30
    sandbox_image: str = "cc-security-sandbox"
    docker_host: str = "unix:///var/run/docker.sock"

    @classmethod
    def from_env(cls, **overrides: object) -> Config:
        _load_env_file()

        def _get(key: str, default: object = "") -> object:
            # overrides use lowercase keys (from CLI), env uses UPPERCASE
            if key.lower() in overrides:
                return overrides[key.lower()]
            return os.getenv(key, default)

        def _int(key: str, default: int) -> int:
            v = overrides.get(key, os.getenv(key))
            return int(v) if v is not None else default

        return cls(
            proxy_host=str(_get("PROXY_HOST", "127.0.0.1")),
            proxy_port=_int("PROXY_PORT", 8080),
            upstream_url=str(_get("UPSTREAM_URL", "")),
            mode=str(_get("MODE", "smart")),  # type: ignore[arg-type]
            log_level=str(_get("LOG_LEVEL", "INFO")),
            llm_api_key=str(_get("LLM_API_KEY", "")),
            llm_base_url=str(_get("LLM_BASE_URL", "https://api.openai.com/v1")),
            llm_model=str(_get("LLM_MODEL", "gpt-4o-mini")),
            llm_timeout=_int("LLM_TIMEOUT", 10),
            sandbox_timeout=_int("SANDBOX_TIMEOUT", 30),
            sandbox_image=str(_get("SANDBOX_IMAGE", "cc-security-sandbox")),
            docker_host=str(_get("DOCKER_HOST", "unix:///var/run/docker.sock")),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.upstream_url:
            errors.append("UPSTREAM_URL is required")
        if self.mode not in ("default", "protected", "smart"):
            errors.append(f"Invalid MODE: {self.mode}")
        if self.mode == "smart" and not self.llm_api_key:
            errors.append("LLM_API_KEY is required for smart mode")
        if self.mode == "protected" and not self._docker_available():
            errors.append(
                "Docker is required for protected mode but not available. "
                "Install Docker or use --mode default."
            )
        return errors

    @staticmethod
    def _docker_available() -> bool:
        try:
            import docker

            docker.from_env()
            return True
        except Exception:
            return False

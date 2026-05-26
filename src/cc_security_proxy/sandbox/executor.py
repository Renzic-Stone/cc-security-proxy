from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .rules import SandboxResult, analyze

if TYPE_CHECKING:
    from ..config import Config

logger = logging.getLogger("cc-security-proxy.sandbox")


def _extract_code_blocks(text: str) -> list[str]:
    """Extract code blocks from text that look executable."""
    import re

    blocks: list[str] = []

    # Markdown code blocks with language
    for m in re.finditer(r"```(?:ba(?:sh|tch)|sh(?:ell)?|cmd|powershell|python|perl|ruby|php)?\s*\n(.*?)```", text, re.DOTALL):
        code = m.group(1).strip()
        if code and len(code) > 10:
            blocks.append(code)

    # Indented code blocks (4+ spaces)
    lines: list[str] = []
    in_block = False
    for line in text.splitlines():
        if line.startswith("    ") or line.startswith("\t"):
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
                in_block = True
        elif in_block:
            if len(lines) >= 3:
                blocks.append("\n".join(lines))
            lines = []
            in_block = False

    if in_block and len(lines) >= 3:
        blocks.append("\n".join(lines))

    return blocks


def _make_script(code_blocks: list[str]) -> str:
    """Combine code blocks into a single executable script."""
    parts = ["#!/bin/bash", "# Auto-generated sandbox script", "set -e"]
    non_exec_extensions = {'.py', '.js', '.ts', '.rb', '.pl', '.php', '.go', '.rs', '.java'}
    for block in code_blocks:
        # Try to detect if this is a non-shell script based on first line content
        first_line = block.split('\n')[0] if block else ''
        is_python = any(kw in first_line.lower() for kw in ['import ', 'from ', 'def ', 'class ', 'print('])
        if is_python:
            parts.append(f"python3 -c {json.dumps(block)}")
        else:
            parts.append(block)
    return "\n\n".join(parts)


class SandboxExecutor:
    def __init__(self, config: Config):
        self.config = config
        self._docker = None

    @property
    def docker(self):
        if self._docker is None:
            import docker

            self._docker = docker.DockerClient(base_url=self.config.docker_host)
        return self._docker

    def available(self) -> bool:
        try:
            self.docker.ping()
            return True
        except Exception:
            return False

    def ensure_image(self) -> None:
        import docker

        dockerfile_dir = Path(__file__).parent
        try:
            self.docker.images.get(self.config.sandbox_image)
            logger.debug("sandbox image %s already exists", self.config.sandbox_image)
        except docker.errors.ImageNotFound:
            logger.info("building sandbox image %s ...", self.config.sandbox_image)
            self.docker.images.build(
                path=str(dockerfile_dir),
                tag=self.config.sandbox_image,
                rm=True,
            )
            logger.info("sandbox image built")

    async def run(self, text: str) -> SandboxResult:
        code_blocks = _extract_code_blocks(text)
        if not code_blocks:
            return SandboxResult(
                exit_code=0,
                stdout="",
                stderr="",
                files_created=[],
                files_modified=[],
                network_attempts=[],
                processes_spawned=[],
                error="no executable code blocks found",
            )

        script = _make_script(code_blocks)

        tmpdir = tempfile.mkdtemp(prefix="cc-sandbox-")
        script_path = os.path.join(tmpdir, "script.sh")
        with open(script_path, "w") as f:
            f.write(script)
        os.chmod(script_path, 0o755)

        logger.debug("running sandbox with script (%d bytes)", len(script))

        try:
            result = await self._run_container(script_path, tmpdir)
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

        return result

    async def _run_container(self, script_path: str, tmpdir: str) -> SandboxResult:
        import docker.errors

        try:
            container = self.docker.containers.run(
                image=self.config.sandbox_image,
                command=["/bin/bash", "/sandbox/script.sh"],
                volumes={tmpdir: {"bind": "/sandbox", "mode": "rw"}},
                network_mode="none",
                read_only=False,
                cap_drop=["ALL"],
                mem_limit="128m",
                cpu_period=100000,
                cpu_quota=50000,
                detach=True,
                security_opt=["no-new-privileges"],
            )
        except docker.errors.DockerException as exc:
            return SandboxResult(
                exit_code=-1,
                stdout="",
                stderr="",
                files_created=[],
                files_modified=[],
                network_attempts=[],
                processes_spawned=[],
                error=f"Docker error: {exc}",
            )

        try:
            timeout = self.config.sandbox_timeout
            container.wait(timeout=timeout + 5)

            exit_code = container.attrs["State"]["ExitCode"]

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            # Inspect filesystem changes
            files_created, files_modified = self._inspect_files(container)

            # Check for network attempts (should be blocked by --network=none)
            network_attempts = self._inspect_network(container)

            # Inspect processes
            processes = self._inspect_processes(container)

            timed_out = exit_code == 124 or exit_code == 137

            return SandboxResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                files_created=files_created,
                files_modified=files_modified,
                network_attempts=network_attempts,
                processes_spawned=processes,
                timed_out=timed_out,
            )
        except Exception as exc:
            return SandboxResult(
                exit_code=-1,
                stdout="",
                stderr="",
                files_created=[],
                files_modified=[],
                network_attempts=[],
                processes_spawned=[],
                error=str(exc),
            )
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

    def _inspect_files(self, container) -> tuple[list[str], list[str]]:
        """Check for suspicious file operations from container diff."""
        created: list[str] = []
        modified: list[str] = []
        try:
            changes = container.diff()
            for change in changes:
                path = change.get("Path", "")
                kind = change.get("Kind", 0)
                if kind == 0:  # Modified
                    modified.append(path)
                elif kind == 1:  # Added
                    created.append(path)
        except Exception:
            pass
        return created, modified

    def _inspect_network(self, container) -> list[str]:
        # With network_mode=none, there should be no network
        attempts: list[str] = []
        try:
            net_settings = container.attrs.get("NetworkSettings", {})
            networks = net_settings.get("Networks", {})
            for name, net in networks.items():
                if net and net.get("IPAddress"):
                    attempts.append(f"network={name} ip={net['IPAddress']}")
        except Exception:
            pass
        return attempts

    def _inspect_processes(self, container) -> list[str]:
        processes: list[str] = []
        try:
            top_result = container.top()
            for proc in top_result.get("Processes", []):
                if len(proc) >= 8:
                    cmd = proc[7]
                    if cmd not in ("bash", "sh", "/bin/bash", "/sandbox/script.sh"):
                        processes.append(cmd)
        except Exception:
            pass
        return processes

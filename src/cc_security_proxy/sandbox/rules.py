from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    files_created: list[str]
    files_modified: list[str]
    network_attempts: list[str]
    processes_spawned: list[str]
    timed_out: bool = False
    error: str = ""

    def summary(self) -> str:
        parts = [f"exit_code={self.exit_code}"]
        if self.files_created:
            parts.append(f"files_created={self.files_created}")
        if self.files_modified:
            parts.append(f"files_modified={self.files_modified}")
        if self.network_attempts:
            parts.append(f"network_attempts={self.network_attempts}")
        if self.processes_spawned:
            parts.append(f"processes={self.processes_spawned}")
        if self.timed_out:
            parts.append("TIMED_OUT")
        if self.error:
            parts.append(f"error={self.error}")
        return "; ".join(parts)


SUSPICIOUS_PATHS = [
    "Startup",
    "Start Menu",
    "Programs/Startup",
    ".config/autostart",
    "LaunchAgents",
    "LaunchDaemons",
    "systemd/system",
    "init.d",
    "rc.local",
    "crontab",
    "cron.d",
    "cron.hourly",
    "cron.daily",
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
]

SUSPICIOUS_COMMANDS = [
    "curl",
    "wget",
    "nc",
    "netcat",
    "ncat",
    "socat",
    "chmod +s",
    "chown root",
    "sudo",
    "su ",
    "passwd",
]


def analyze(result: SandboxResult) -> list[str]:
    findings: list[str] = []

    for f in result.files_created + result.files_modified:
        lower = f.lower()
        for suspect in SUSPICIOUS_PATHS:
            if suspect.lower() in lower:
                findings.append(f"Write to suspicious path: {f} (matched: {suspect})")
                break

    for attempt in result.network_attempts:
        findings.append(f"Network connection attempt: {attempt}")

    for proc in result.processes_spawned:
        for cmd in SUSPICIOUS_COMMANDS:
            if cmd in proc.lower():
                findings.append(f"Suspicious process: {proc}")
                break

    for line in result.stdout.splitlines() + result.stderr.splitlines():
        for cmd in SUSPICIOUS_COMMANDS:
            if cmd in line.lower():
                # Already captured above, skip
                pass

    return findings

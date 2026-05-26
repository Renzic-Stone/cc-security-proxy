from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ScanMatch:
    pattern_id: str
    description: str
    severity: float  # 0.0 to 1.0
    matched_text: str


PATTERNS: list[tuple[str, str, float, str]] = [
    # (id, description, severity, regex)
    (
        "startup_write_win",
        "Windows startup folder write",
        0.95,
        r"(?:Startup|Start Menu\\Programs\\Startup)\\",
    ),
    (
        "startup_write_unix",
        "Unix autostart write",
        0.95,
        r"(?:~/\.config/autostart|/etc/rc\.local|/etc/init\.d/|/etc/systemd/system/)",
    ),
    (
        "launch_agent_macos",
        "macOS LaunchAgent persistence",
        0.95,
        r"~/Library/LaunchAgents/",
    ),
    (
        "shell_pipe_exec",
        "Shell pipe to execution (curl/wget piped to shell)",
        0.9,
        r"(?:curl|wget)\s+.*\|\s*(?:ba)?sh",
    ),
    (
        "base64_decode_exec",
        "Base64 decode and execute",
        0.9,
        r"base64\s+(?:-d|--decode).*\|.*(?:ba)?sh",
    ),
    (
        "registry_persistence",
        "Windows registry persistence (Run keys)",
        0.9,
        r"(?:reg\s+add|HKEY_.*\\Run)",
    ),
    (
        "crontab_manipulation",
        "Crontab manipulation",
        0.85,
        r"(?:crontab\s+-|echo\s+.*>>\s*/etc/crontab|/var/spool/cron/)",
    ),
    (
        "download_and_execute",
        "Download and execute remote content",
        0.85,
        r"(?:curl|wget)\s+.*\|\s*(?:python|node|ruby|perl|php)",
    ),
    (
        "reverse_shell",
        "Reverse shell pattern",
        0.95,
        r"(?:/dev/tcp/|nc\s+.*-e\s|python.*socket.*connect|bash\s+-i\s*>&)",
    ),
    (
        "eval_obfuscated",
        "eval/exec with obfuscated input",
        0.8,
        r"(?:eval|exec|Exec)\s*\(\s*(?:__import__|compile|base64|gzinflate)",
    ),
    (
        "vbs_powershell_launch",
        "VBS/PowerShell script creation",
        0.85,
        r"(?:\.vbs|\.ps1|powershell\s+-ExecutionPolicy\s+Bypass|WScript\.Shell)",
    ),
    (
        "sudo_priv_escalation",
        "Privilege escalation attempt",
        0.8,
        r"sudo\s+(?:su|bash|sh|chmod\s+\+s|chown)",
    ),
    (
        "rm_rf_destructive",
        "Destructive rm -rf command",
        0.7,
        r"rm\s+-rf\s+/(?:home|etc|var|usr|tmp)",
    ),
    (
        "hidden_file_write",
        "Write to hidden/system files",
        0.75,
        r"echo.*>\s*(?:~/.bashrc|~/.zshrc|~/.profile|/etc/passwd|/etc/shadow)",
    ),
    (
        "dns_exfiltration",
        "DNS data exfiltration pattern",
        0.85,
        r"(?:nslookup|dig|host)\s+.*\$\(",
    ),
    (
        "socket_connect",
        "Raw socket connection (potential C2)",
        0.8,
        r"(?:python|perl|ruby).*(?:socket\.connect|Socket\.new|TCPSocket)",
    ),
]


def scan(text: str) -> list[ScanMatch]:
    matches: list[ScanMatch] = []
    seen: set[str] = set()

    for pattern_id, desc, severity, regex in PATTERNS:
        for m in re.finditer(regex, text, re.IGNORECASE):
            matched = m.group(0)
            fingerprint = f"{pattern_id}:{matched}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                matches.append(ScanMatch(
                    pattern_id=pattern_id,
                    description=desc,
                    severity=severity,
                    matched_text=matched[:200],
                ))

    matches.sort(key=lambda x: x.severity, reverse=True)
    return matches


def max_severity(matches: list[ScanMatch]) -> float:
    return max((m.severity for m in matches), default=0.0)

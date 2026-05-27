from __future__ import annotations

import re
import unicodedata
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
        "Unix autostart write / path reference",
        0.95,
        r"(?:~/\.config/autostart/|/etc/rc\.local|/etc/init\.d/[a-zA-Z]|/etc/systemd/system/[a-zA-Z])",
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
        "powershell_download_exec",
        "PowerShell download and execute (irm | iex)",
        0.95,
        r"(?:Invoke-WebRequest|iwr|irm)\s+.*\|\s*(?:Invoke-Expression|iex)",
    ),
    (
        "base64_decode_exec",
        "Base64 decode and execute",
        0.9,
        r"base64\s+(?:-d|--decode).*\|.*(?:ba)?sh",
    ),
    (
        "powershell_encoded",
        "PowerShell -EncodedCommand (obfuscated payload)",
        0.95,
        r"powershell\s+.*-EncodedCommand\s+\S{20,}",
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
    # Hard-bottom-line: remote URL download + any execution
    (
        "remote_url_exec",
        "Remote URL download with execution",
        0.95,
        r"https?://[^\s]+\.(?:ps1|sh|py|exe|vbs|bat|js).*?(?:\||-Command|iex|Start-Process|bash)",
    ),
]


def scan(text: str) -> list[ScanMatch]:
    # Step 0: NFKC normalization — collapses fullwidth, strips zero-width/bidi chars
    text = unicodedata.normalize('NFKC', text)
    # Remove zero-width spaces, joiners, overrides (U+200B-U+200D, U+FEFF, U+202A-U+202E)
    text = re.sub(r'[​-‍﻿‪-‮⁠­]', '', text)
    matches: list[ScanMatch] = []
    seen_patterns: set[str] = set()

    for pattern_id, desc, severity, regex in PATTERNS:
        if pattern_id in seen_patterns:
            continue
        for m in re.finditer(regex, text, re.IGNORECASE):
            seen_patterns.add(pattern_id)
            matches.append(ScanMatch(
                pattern_id=pattern_id,
                description=desc,
                severity=severity,
                matched_text=m.group(0)[:200],
            ))
            break  # one match per pattern is enough

    matches.sort(key=lambda x: x.severity, reverse=True)
    return matches


def max_severity(matches: list[ScanMatch]) -> float:
    return max((m.severity for m in matches), default=0.0)


_TUTORIAL_KW = ['怎么','如何','how','explain','教程','配置','设置','教','configure','setup',
                '教我','帮我','写一个','创建','create','write','show','demonstrate','explain']


def is_tutorial_context(user_prompt: str) -> bool:
    """Check if user is asking for a tutorial/explanation rather than being injected."""
    return any(kw in user_prompt.lower() for kw in _TUTORIAL_KW)


def adjusted_severity(matches: list[ScanMatch], user_prompt: str) -> float:
    """Return max severity, reduced if user is in tutorial/teaching context."""
    sev = max_severity(matches)
    if sev >= 0.95 and is_tutorial_context(user_prompt):
        return 0.85  # Flag but don't auto-block
    return sev

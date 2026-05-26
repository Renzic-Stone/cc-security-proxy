from __future__ import annotations

import json

from cc_security_proxy.llm.client import LLMClient, LLMVerdict
from cc_security_proxy.llm.prompts import SYSTEM_PROMPT


def test_llm_verdict_from_error():
    v = LLMVerdict.from_error("timeout")
    assert v.verdict == "SUSPICIOUS"
    assert v.error == "timeout"
    assert v.confidence == 0.5


def test_system_prompt_contains_keywords():
    assert "SAFE" in SYSTEM_PROMPT
    assert "SUSPICIOUS" in SYSTEM_PROMPT
    assert "MALICIOUS" in SYSTEM_PROMPT
    assert "security auditor" in SYSTEM_PROMPT.lower()


def test_parse_valid_json():
    client = object()  # dummy, just testing _parse
    # Create a minimal client to test _parse
    from cc_security_proxy.config import Config

    config = Config(
        upstream_url="https://test.example.com",
        mode="smart",
        llm_api_key="sk-test",
    )
    llm = LLMClient(config)

    result = llm._parse('{"verdict": "SAFE", "reason": "Clean response", "confidence": 0.98}')
    assert result.verdict == "SAFE"
    assert result.confidence == 0.98
    assert result.reason == "Clean response"

    result = llm._parse('{"verdict": "MALICIOUS", "reason": "Reverse shell", "confidence": 0.95}')
    assert result.verdict == "MALICIOUS"

    result = llm._parse('{"verdict": "SUSPICIOUS", "reason": "Unusual pattern", "confidence": 0.6}')
    assert result.verdict == "SUSPICIOUS"


def test_parse_markdown_wrapped():
    from cc_security_proxy.config import Config

    config = Config(
        upstream_url="https://test.example.com",
        mode="smart",
        llm_api_key="sk-test",
    )
    llm = LLMClient(config)

    result = llm._parse('```json\n{"verdict": "SAFE", "reason": "ok", "confidence": 0.99}\n```')
    assert result.verdict == "SAFE"
    assert result.confidence == 0.99


def test_parse_heuristic():
    from cc_security_proxy.config import Config

    config = Config(
        upstream_url="https://test.example.com",
        mode="smart",
        llm_api_key="sk-test",
    )
    llm = LLMClient(config)

    result = llm._parse("This content is clearly MALICIOUS because it contains a reverse shell.")
    assert result.verdict == "MALICIOUS"

    result = llm._parse("Everything looks SAFE here.")
    assert result.verdict == "SAFE"

    result = llm._parse("This is SUSPICIOUS but not sure.")
    assert result.verdict == "SUSPICIOUS"

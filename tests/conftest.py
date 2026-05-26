from __future__ import annotations

import pytest


@pytest.fixture
def config_default():
    from cc_security_proxy.config import Config

    return Config(upstream_url="https://test.example.com", mode="default")


@pytest.fixture
def config_protected():
    from cc_security_proxy.config import Config

    return Config(upstream_url="https://test.example.com", mode="protected")


@pytest.fixture
def config_smart():
    from cc_security_proxy.config import Config

    return Config(
        upstream_url="https://test.example.com",
        mode="smart",
        llm_api_key="sk-test",
        llm_model="gpt-4o-mini",
    )

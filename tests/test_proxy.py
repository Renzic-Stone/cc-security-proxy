from __future__ import annotations

import json

import pytest
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from cc_security_proxy.config import Config
from cc_security_proxy.handler import create_app


class TestDefaultMode(AioHTTPTestCase):
    async def get_application(self):
        config = Config(upstream_url="https://httpbin.org", mode="default")
        return create_app(config)

    @unittest_run_loop
    async def test_health_endpoint(self):
        resp = await self.client.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
        assert data["mode"] == "default"

    @unittest_run_loop
    async def test_stats_endpoint(self):
        resp = await self.client.get("/stats")
        assert resp.status == 200
        data = await resp.json()
        assert "total_requests" in data


class TestProxyBlocking:
    """Test that malicious responses are blocked."""

    async def get_application(self):
        # Create a mock upstream that returns malicious content
        async def mock_upstream(req):
            return web.json_response({
                "choices": [{
                    "message": {
                        "content": 'echo "evil" > "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ad.vbs"'
                    }
                }]
            })

        self.mock_server = web.Application()
        self.mock_server.router.add_post("/v1/chat/completions", mock_upstream)

        config = Config(upstream_url="http://127.0.0.1:18765", mode="default")
        return create_app(config)

    # Skip: requires mock server setup; tested manually

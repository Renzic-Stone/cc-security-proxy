from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from .config import Config
    from .modes.base import BaseMode

logger = logging.getLogger("cc-security-proxy.handler")

_stats: dict[str, int] = {
    "total_requests": 0,
    "forwarded": 0,
    "blocked": 0,
    "errors": 0,
}
_stats_start_time = time.monotonic()


def _resolve_mode(config: Config) -> BaseMode:
    if config.mode == "default":
        from .modes.default_mode import DefaultMode

        return DefaultMode()
    elif config.mode == "protected":
        from .modes.protected_mode import ProtectedMode

        return ProtectedMode(config)
    elif config.mode == "smart":
        from .modes.smart_mode import SmartMode

        return SmartMode(config)
    raise ValueError(f"Unknown mode: {config.mode}")


def _extract_text_from_response(body: bytes) -> str:
    """Extract all text content from an API response for security scanning."""
    try:
        data = json.loads(body)
        texts: list[str] = []
        _walk(data, texts)
        return "\n".join(texts)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body.decode("utf-8", errors="replace")


def _walk(obj: object, texts: list[str]) -> None:
    if isinstance(obj, str):
        if len(obj) > 4:
            texts.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk(v, texts)
    elif isinstance(obj, list):
        for item in obj:
            _walk(item, texts)


def _extract_user_prompt(body: bytes) -> str:
    """Extract the user's last message from a chat completion request body.

    Privacy: truncated to 2000 chars, never logged or persisted.
    Returns empty string on parse failure.
    """
    try:
        data = json.loads(body)
        messages = data.get("messages", [])
        if messages:
            last = messages[-1]
            content = last.get("content", "")
            if isinstance(content, str):
                return content[:2000]
            if isinstance(content, list):
                # Multimodal content: extract text parts
                parts = [p.get("text", "") for p in content if isinstance(p, dict)]
                return " ".join(parts)[:2000]
        return ""
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        return ""


def _make_deep_link(port: int) -> str:
    """Generate a CC Switch deep link to import this proxy as a provider."""
    provider_config = {
        "env": {
            "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
            "ANTHROPIC_AUTH_TOKEN": "",
        }
    }
    json_str = json.dumps(provider_config, ensure_ascii=False)
    config_b64 = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
    return (
        f"ccswitch://v1/import"
        f"?resource=provider"
        f"&app=claude"
        f"&name=CC+Security+Proxy"
        f"&config={config_b64}"
    )


def create_app(config: Config) -> web.Application:
    app = web.Application()
    mode = _resolve_mode(config)
    logger.info("loaded mode: %s", type(mode).__name__)

    async def _health(_req: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "mode": config.mode,
            "upstream": config.upstream_url,
            "stats": _stats,
            "uptime_seconds": int(time.monotonic() - _stats_start_time),
        })

    async def _stats_handler(_req: web.Request) -> web.Response:
        return web.json_response(_stats)

    async def _proxy(req: web.Request) -> web.Response:
        _stats["total_requests"] += 1
        path = req.rel_url.raw_path_qs

        try:
            body = await req.read()
        except Exception:
            _stats["errors"] += 1
            return web.json_response(
                {"error": "failed to read request body"}, status=400
            )

        from .upstream import forward_request

        headers = {k: v for k, v in req.headers.items()}

        try:
            status, resp_headers, resp_body = await forward_request(
                config, req.method, path, headers, body
            )
        except Exception as exc:
            _stats["errors"] += 1
            logger.error("upstream request failed: %s", exc)
            return web.json_response(
                {"error": f"upstream request failed: {exc}"}, status=502
            )

        # Extract user intent from request body BEFORE forwarding
        user_prompt = _extract_user_prompt(body)

        # Run security check on response body
        text_content = _extract_text_from_response(resp_body)
        try:
            decision = await mode.check(path, resp_body, text_content, user_prompt=user_prompt)
        except Exception as exc:
            logger.error("security check failed: %s", exc)
            _stats["forwarded"] += 1
            return web.Response(
                status=status, headers=resp_headers, body=resp_body
            )

        if decision.action == "forward":
            _stats["forwarded"] += 1
            logger.info(
                "FORWARD %s (%d bytes, reason=%s)",
                path,
                len(resp_body),
                decision.reason,
            )
            return web.Response(
                status=status, headers=resp_headers, body=resp_body
            )

        _stats["blocked"] += 1
        logger.warning(
            "BLOCK %s (%d bytes, reason=%s, details=%s)",
            path,
            len(resp_body),
            decision.reason,
            decision.details,
        )
        return web.json_response(
            {
                "error": "Response blocked by security proxy",
                "reason": decision.reason,
                "details": decision.details,
            },
            status=403,
        )

    async def _ccswitch(_req: web.Request) -> web.Response:
        return web.json_response({
            "deep_link": _make_deep_link(config.proxy_port),
            "provider_name": "CC Security Proxy",
            "base_url": f"http://127.0.0.1:{config.proxy_port}",
            "note": "ANTHROPIC_AUTH_TOKEN should be set to your relay API key in CC Switch",
        })

    async def _debug_check(req: web.Request) -> web.Response:
        try:
            data = await req.json()
        except Exception:
            return web.json_response({"error": "invalid JSON, need {\"body\": \"...\"}"}, status=400)

        raw_body = data.get("body", "")
        if isinstance(raw_body, str):
            raw_body_bytes = raw_body.encode("utf-8")
        elif isinstance(raw_body, dict):
            raw_body_bytes = json.dumps(raw_body).encode("utf-8")
        else:
            return web.json_response({"error": "body must be a JSON string or object"}, status=400)

        text_content = _extract_text_from_response(raw_body_bytes)
        user_prompt = data.get("user_prompt", "")
        from .scanner import scan, max_severity

        matches = scan(text_content)
        t0 = time.monotonic()

        try:
            decision = await mode.check("/v1/chat/completions", raw_body_bytes, text_content, user_prompt=user_prompt)
        except Exception as exc:
            decision = type("Decision", (), {"action": "error", "reason": str(exc), "details": "", "confidence": 0})()

        elapsed_ms = int((time.monotonic() - t0) * 1000)

        return web.json_response({
            "decision": decision.action,
            "reason": decision.reason,
            "details": decision.details,
            "confidence": getattr(decision, "confidence", 1.0),
            "scanner_matches": [
                {"pattern_id": m.pattern_id, "severity": m.severity, "description": m.description}
                for m in matches[:10]
            ],
            "scanner_max_severity": max_severity(matches),
            "mode": config.mode,
            "elapsed_ms": elapsed_ms,
        })

    # Register routes: catch-all for API paths, plus utility endpoints
    app.router.add_get("/health", _health)
    app.router.add_get("/stats", _stats_handler)
    app.router.add_get("/ccswitch", _ccswitch)
    app.router.add_post("/api/debug/check", _debug_check)
    app.router.add_route("*", "/v1/{tail:.*}", _proxy)
    app.router.add_route("*", "/{tail:.*}", _proxy)

    return app

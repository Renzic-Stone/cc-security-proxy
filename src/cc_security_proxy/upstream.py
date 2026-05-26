from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from .config import Config

logger = logging.getLogger("cc-security-proxy.upstream")


async def forward_request(
    config: Config,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> tuple[int, dict[str, str], bytes]:
    url = f"{config.upstream_url.rstrip('/')}{path}"

    forward_headers = {
        k: v
        for k, v in headers.items()
        if k.lower() not in ("host", "transfer-encoding", "content-length")
    }

    logger.debug("forwarding %s %s (%d bytes)", method, url, len(body))

    async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
        resp = await client.request(
            method=method,
            url=url,
            headers=forward_headers,
            content=body,
        )

        response_headers = dict(resp.headers)
        response_headers.pop("transfer-encoding", None)
        response_headers.pop("content-encoding", None)

        logger.debug(
            "upstream responded %s (%d bytes)", resp.status_code, len(resp.content)
        )
        return resp.status_code, response_headers, resp.content

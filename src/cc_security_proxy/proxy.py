from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from .config import Config

logger = logging.getLogger("cc-security-proxy.proxy")


def run_proxy(config: Config) -> None:
    from .handler import create_app

    app = create_app(config)
    web.run_app(
        app,
        host=config.proxy_host,
        port=config.proxy_port,
        access_log=logger.getChild("access"),
        access_log_format='%t "%r" %s %b "%{Referer}i"',
    )

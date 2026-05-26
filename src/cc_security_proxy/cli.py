from __future__ import annotations

import argparse
import logging
import signal
import sys

from . import __version__
from .config import Config


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cc-security-proxy",
        description="Security proxy between coding agents and untrusted API relay stations",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "--mode",
        choices=["default", "protected", "smart"],
        help="Security mode (default: smart, or $MODE)",
    )
    p.add_argument("--port", type=int, help="Proxy listen port (default: 8080, or $PROXY_PORT)")
    p.add_argument("--host", help="Proxy listen host (default: 127.0.0.1, or $PROXY_HOST)")
    p.add_argument("--upstream", help="Upstream relay URL (or $UPSTREAM_URL)")
    p.add_argument(
        "--llm-api-key", help="LLM API key for smart mode (or $LLM_API_KEY)"
    )
    p.add_argument(
        "--llm-base-url", help="LLM API base URL (or $LLM_BASE_URL)"
    )
    p.add_argument("--llm-model", help="LLM model name (or $LLM_MODEL)")
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    overrides = {k: v for k, v in vars(args).items() if v is not None}
    overrides_renamed = {}
    for k, v in overrides.items():
        k = k.replace("-", "_")
        if k == "upstream":
            k = "upstream_url"
        overrides_renamed[k] = v

    config = Config.from_env(**overrides_renamed)

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("cc-security-proxy")

    errors = config.validate()
    if errors:
        for e in errors:
            logger.error(e)
        sys.exit(1)

    from .proxy import run_proxy

    loop_holder: list[object] = []

    def _shutdown(signum: int, frame: object) -> None:
        logger.info("received signal %s, shutting down", signum)
        for obj in loop_holder:
            if hasattr(obj, "close"):
                obj.close()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info("cc-security-proxy %s starting (mode=%s)", __version__, config.mode)
    logger.info("listening on %s:%s", config.proxy_host, config.proxy_port)
    logger.info("upstream: %s", config.upstream_url)

    try:
        run_proxy(config)
    except KeyboardInterrupt:
        logger.info("shutdown complete")


if __name__ == "__main__":
    main()

"""Logging configuration for Security-Ops.

``configure_logging()`` is invoked from the FastAPI lifespan (``app.main``) at
startup. It is intentionally dependency-free so it can run before anything else
is wired. Level is taken from settings when available, else INFO.
"""

from __future__ import annotations

import logging
import os

_CONFIGURED = False


def configure_logging() -> None:
    """Idempotently configure root + ``secops`` logging."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level_name = os.getenv("SECOPS_LOG_LEVEL")
    if not level_name:
        try:
            from app.core.config import settings

            level_name = getattr(settings, "log_level", None) or "INFO"
        except Exception:
            level_name = "INFO"

    level = getattr(logging, str(level_name).upper(), logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    # Keep the audit trail loud regardless of global level — it is security-relevant.
    logging.getLogger("secops.audit").setLevel(logging.INFO)
    _CONFIGURED = True

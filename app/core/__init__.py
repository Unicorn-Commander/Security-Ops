"""app.core — cross-cutting foundations: configuration, errors, logging.

Deliberately import-side-effect free (no re-exports): consumers import the
concrete submodule they need (``app.core.config`` for settings, ``app.core.errors``
for the error hierarchy + handler installer). That keeps import order under the
composition root's control and avoids cycles.
"""

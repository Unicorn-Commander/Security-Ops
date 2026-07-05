"""Security-Ops — authorized autonomous penetration-testing backend.

Top-level package for the FastAPI application (see :mod:`app.main`). Deliberately
import-side-effect free: importing ``app`` pulls in no configuration, database
engine, or FastAPI instance — those live in submodules and are wired by the
composition root, which keeps import order predictable and partial-checkout
slices importable.
"""

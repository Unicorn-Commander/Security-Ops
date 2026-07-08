"""The isolated Strix runner sidecar.

A standalone process (``python -m app.runner``) that claims gate-cleared runs from
``run_queue`` and executes them via :func:`app.engine.strix_runner.execute_run`.
It is the ONLY component that spawns Strix and mounts the Docker socket — the
internet-facing API just enqueues. See :mod:`app.runner.loop`.
"""

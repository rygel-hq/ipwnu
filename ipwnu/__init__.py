"""ipwnu — system inventory collector.

The heavy lifting lives in :mod:`ipwnu.collector`. This package exposes a small
convenience API so callers can simply::

    from ipwnu import collect_and_deliver

without reaching into the module directly.
"""

from __future__ import annotations

from .collector import (
    build_report,
    collect_and_deliver,
    configure_logging,
    deliver,
)

__all__ = [
    "build_report",
    "collect_and_deliver",
    "configure_logging",
    "deliver",
]

__version__ = "0.1.0"

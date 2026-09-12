#!/usr/bin/env python3
"""Entry point for the ipwnu inventory collector.

All collection and delivery logic lives in the ``ipwnu`` package. This script
simply invokes it so the tool can be run standalone with ``python main.py``.
"""

from __future__ import annotations

import sys

from ipwnu import collect_and_deliver

if __name__ == "__main__":
    raise SystemExit(collect_and_deliver())

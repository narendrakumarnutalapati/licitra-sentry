"""
Shared experiment utilities for LICITRA-SENTRY.
"""

from __future__ import annotations

from typing import Any, Dict

import requests


DEFAULT_MMR_BASE = "http://localhost:8000"


class PreflightError(RuntimeError):
    """Raised when MMR preflight validation fails."""


def get_mmr_health(mmr_base: str = DEFAULT_MMR_BASE, timeout: int = 5) -> Dict[str, Any]:
    """
    Fetch and validate the LICITRA-MMR /health response.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        PreflightError: If MMR is unreachable, returns non-200, invalid JSON,
        or does not expose required health fields.
    """
    url = f"{mmr_base.rstrip('/')}/health"

    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise PreflightError(f"MMR preflight failed: could not reach {url}: {exc}") from exc

    if response.status_code != 200:
        raise PreflightError(
            f"MMR preflight failed: {url} returned HTTP {response.status_code}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise PreflightError(f"MMR preflight failed: {url} did not return valid JSON") from exc

    required_fields = {
        "status",
        "service",
        "ledger_version",
        "block_size",
        "dev_mode",
        "ledger_mode",
    }

    missing = sorted(field for field in required_fields if field not in data)
    if missing:
        raise PreflightError(
            f"MMR preflight failed: /health missing required fields: {', '.join(missing)}"
        )

    if data["status"] != "ok":
        raise PreflightError(
            f"MMR preflight failed: /health reported non-ok status: {data['status']!r}"
        )

    if not isinstance(data["block_size"], int):
        raise PreflightError(
            f"MMR preflight failed: block_size must be int, got {type(data['block_size']).__name__}"
        )

    if not isinstance(data["dev_mode"], bool):
        raise PreflightError(
            f"MMR preflight failed: dev_mode must be bool, got {type(data['dev_mode']).__name__}"
        )

    return data

def require_mmr_block_size(
    required_block_size: int,
    mmr_base: str = DEFAULT_MMR_BASE,
    timeout: int = 5,
) -> Dict[str, Any]:
    """
    Fetch MMR health and enforce an exact block size.

    Args:
        required_block_size: The required MMR BLOCK_SIZE for the experiment.
        mmr_base: Base URL for LICITRA-MMR.
        timeout: Request timeout in seconds.

    Returns:
        Parsed MMR /health response dict.

    Raises:
        PreflightError: If MMR health is valid but incompatible with the required block size.
    """
    health = get_mmr_health(mmr_base=mmr_base, timeout=timeout)
    actual_block_size = health["block_size"]

    if actual_block_size != required_block_size:
        raise PreflightError(
            "MMR preflight failed: incompatible BLOCK_SIZE for this experiment. "
            f"Required BLOCK_SIZE={required_block_size}, "
            f"but /health reported BLOCK_SIZE={actual_block_size} "
            f"(ledger_mode={health.get('ledger_mode')}, dev_mode={health.get('dev_mode')})."
        )

    return health
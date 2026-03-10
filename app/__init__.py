"""
LICITRA-SENTRY package initialization.

Exposes version metadata for the current core API and the legacy
compatibility API used by the experiment suite.
"""

from .version import (
    SENTRY_VERSION,
    CORE_API_VERSION,
    LEGACY_COMPAT_API_VERSION,
)

__all__ = [
    "SENTRY_VERSION",
    "CORE_API_VERSION",
    "LEGACY_COMPAT_API_VERSION",
]
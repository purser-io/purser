"""Environment-variable access for Purser.

All Purser settings use the ``PURSER_<NAME>`` prefix; ``env_get`` centralizes
reads so call sites stay tidy (``env_get("POLICY", default)``).
"""

from __future__ import annotations

import os


def env_get(suffix: str, default: str | None = None) -> str | None:
    return os.environ.get("PURSER_" + suffix, default)

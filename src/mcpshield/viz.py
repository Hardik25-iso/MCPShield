"""Chart rendering helpers. Points kaleido at the preinstalled Chromium when present so PNG export works."""

from __future__ import annotations

import glob
import os

_CHROME_CANDIDATES = ["/opt/pw-browsers/chromium-*/chrome-linux/chrome"]


def configure_chrome() -> None:
    if any(os.environ.get(v) for v in ("PLOTLY_KALEIDO_CHROME", "KALEIDO_CHROME", "BROWSER_PATH")):
        return
    for pattern in _CHROME_CANDIDATES:
        matches = sorted(glob.glob(pattern))
        if matches:
            for var in ("PLOTLY_KALEIDO_CHROME", "KALEIDO_CHROME", "BROWSER_PATH"):
                os.environ[var] = matches[-1]
            return

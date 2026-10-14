"""Generate seeded synthetic vendors, invoices and sandbox files. Reproducible for a fixed seed."""

from __future__ import annotations

from mcpshield.config import get_settings
from mcpshield.datagen import generate
from mcpshield.logging_setup import setup_logging


def main() -> None:
    settings = get_settings()
    setup_logging(settings, "datagen")
    counts = generate(settings)
    summary = ", ".join(f"{k}={v}" for k, v in counts.items())
    print(f"synthetic data written to {settings.paths.synthetic_dir}: {summary}")


if __name__ == "__main__":
    main()

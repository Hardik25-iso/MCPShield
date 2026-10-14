"""Export documentation figures: evaluation charts (PNG via kaleido) and architecture Mermaid sources.

Mermaid-to-PNG needs a Mermaid renderer (mmdc or a browser with the mermaid script); where that is not
available offline, the .mmd source is written and the live Streamlit Overview renders it. The architecture
Mermaid is the single source of truth in docs/architecture.md.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcpshield.config import get_settings
from mcpshield.eval.report import write_figures
from mcpshield.logging_setup import setup_logging
from mcpshield.schemas import RunResult


def _extract_mermaid(markdown: Path) -> list[str]:
    return re.findall(r"```mermaid\n(.*?)```", markdown.read_text("utf-8"), re.S)


def main() -> None:
    settings = get_settings()
    setup_logging(settings, "figures")
    figs = settings.paths.figures_dir
    figs.mkdir(parents=True, exist_ok=True)

    arch = _extract_mermaid(settings.paths.data_dir.parent / "docs" / "architecture.md")
    names = ["architecture_system.mmd", "architecture_sequence.mmd"]
    for name, src in zip(names, arch, strict=False):
        (figs / name).write_text(src, encoding="utf-8")

    results_path = settings.paths.eval_dir / "results.json"
    if results_path.exists():
        results = [RunResult.model_validate(r) for r in json.loads(results_path.read_text())]
        backend = results[0].backend if results else "mock"
        saved = write_figures(results, settings, backend_label=f"backend={backend}")
        print(f"figures written: {len(saved)} charts, {len(arch)} mermaid sources, in {figs}")
    else:
        print(f"wrote {len(arch)} mermaid sources to {figs}; run `make eval` for the chart PNGs")


if __name__ == "__main__":
    main()

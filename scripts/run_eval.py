"""Run the evaluation matrix and write results.md, figures and raw CSV/JSON."""

from __future__ import annotations

import argparse

from mcpshield.config import get_settings
from mcpshield.datagen import generate
from mcpshield.eval.ablation import ablations
from mcpshield.eval.report import write_figures, write_raw, write_results_md
from mcpshield.eval.runner import run_matrix
from mcpshield.logging_setup import setup_logging
from mcpshield.rag.ingest import build_kb, open_collection


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MCPShield evaluation matrix.")
    parser.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    args = parser.parse_args()

    settings = get_settings()
    setup_logging(settings, "eval")
    generate(settings)
    if open_collection(settings) is None:
        build_kb(settings)

    results = run_matrix(args.backend, ablations(settings))
    write_raw(results, settings)
    figures = write_figures(results, settings, backend_label=f"backend={args.backend}")
    out = write_results_md(results, settings, backend=args.backend)
    print(f"eval complete: {len(results)} runs, {len(figures)} figures, report at {out}")


if __name__ == "__main__":
    main()

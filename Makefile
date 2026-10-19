UV ?= uv
RUN = $(UV) run

.PHONY: setup data kb eval eval-ollama app test lint typecheck check figures deck clean

setup:            ## install dependencies (core + dev + optional neural embeddings and deck tools)
	$(UV) sync --group dev --all-extras

data:             ## generate seeded synthetic vendors, invoices and sandbox files
	$(RUN) python scripts/generate_data.py

kb:               ## build the threat knowledge base (Chroma + BM25)
	$(RUN) python scripts/build_kb.py

eval:             ## run the evaluation matrix with the mock backend and write docs/results.md
	$(RUN) python scripts/run_eval.py --backend mock

eval-ollama:      ## run the Ollama row of the matrix (requires local Ollama with the configured models)
	MCPSHIELD_LLM__BACKEND=ollama $(RUN) python scripts/run_eval.py --backend ollama

app:              ## launch the Streamlit UI
	$(RUN) streamlit run app/streamlit_app.py

test:
	$(RUN) pytest

lint:
	$(RUN) ruff check .
	$(RUN) ruff format --check .

typecheck:
	$(RUN) mypy src tests api

check: lint typecheck test

figures:          ## export architecture diagrams and charts to docs/figures
	$(RUN) python scripts/export_figures.py

deck:             ## build the draft PowerPoint deck
	$(RUN) python scripts/build_deck.py

clean:
	rm -rf var .pytest_cache .mypy_cache .ruff_cache

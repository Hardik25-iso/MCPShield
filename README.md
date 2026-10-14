# MCPShield

A multi-agent runtime firewall for MCP-connected AI agents (academic proof of concept, Agentic AI course
CA-3). MCPShield is a transparent proxy between an MCP host agent and its MCP servers: to the agent it is an
MCP server, to the real servers it is an MCP client. Every tool listing, tool call and tool result flows
through a LangGraph multi-agent pipeline that decides **ALLOW / SANITIZE / BLOCK / ESCALATE**, logs a full
explanation, and reports metrics.

The demo scenario is a **Finance Ops Assistant** for an Indian SME connected to a trusted finance MCP server
and a malicious third-party "utility" MCP server. All data is synthetic.

## Requirements
- Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).
- Optional: [Ollama](https://ollama.com/) for real local models; `sentence-transformers` for neural RAG.
  Without them the project runs fully offline on a deterministic mock LLM and a hashing embedder.

## Setup
```bash
make setup           # create the environment and install deps (core + dev + optional extras)
make data            # generate seeded synthetic vendors, invoices and sandbox files
make kb              # build the threat knowledge base (Chroma + BM25)
```

### Optional: Ollama backend
```bash
ollama pull qwen3:8b          # judge model
ollama pull llama3.2:3b       # fast model
export MCPSHIELD_LLM__BACKEND=ollama
```
If Ollama is unreachable, MCPShield automatically falls back to the deterministic mock backend.

## Run
```bash
make app             # launch the Streamlit UI (Overview, Live Agent, Attack Lab, Tool Registry,
                     # Audit Log, Metrics, Ledger & Outbox)
make eval            # run the evaluation matrix (mock backend) -> docs/results.md + docs/figures/
make eval-ollama     # run the Ollama row locally (requires the models above)
make figures         # export chart PNGs and architecture Mermaid sources
make deck            # build the draft deck docs/MCPShield.pptx
```

Run the servers or proxy directly (stdio) if needed:
```bash
uv run python -m mcpshield.servers.finance_server
MCPSHIELD_SCENARIO=poison_plain_01 uv run python -m mcpshield.servers.utility_server
MCPSHIELD_USER_REQUEST="..." uv run python -m mcpshield.proxy.mcp_proxy
```

## Mock vs Ollama
- **Mock (default):** deterministic, offline, used for tests, CI and a reproducible demo. The mock host agent
  is a deliberately naive, worst-case obedient agent, so shield-OFF attack success is 100% by construction.
- **Ollama:** real local models with tool calling; vulnerability and detection quality vary by model.

## Quality
```bash
make check           # ruff + ruff format --check + mypy + pytest
```
All tests run offline with the mock backend and do not require Ollama or network access.

## Configuration
Everything (thresholds, models, weights, paths) lives in `config.yaml`, loaded once through a pydantic-settings
`Settings` object. Override any key with an env var, e.g. `MCPSHIELD_RISK__THRESHOLDS__BLOCK=0.9` or
`MCPSHIELD_SHIELD__SANITIZE_MODE=quarantine`.

## Layout
```
config.yaml              single source of truth for configuration
src/mcpshield/
  schemas.py storage.py llm.py text_utils.py metrics.py config.py data_loader.py
  detectors/   all detection logic (one Detector family per file, a registry)
  agents/      orchestrator, registry_auditor, intent_verifier, output_sanitizer, critic, auditor
  core/        graph.py (LangGraph pipeline), shield_core.py (public API)
  proxy/       mcp_proxy.py (thin MCP adapter around ShieldCore)
  servers/     finance_server.py (trusted), utility_server.py (malicious, scenario-driven)
  host/        host_agent.py (ReAct agent), channel.py, mock_policy.py
  rag/         embeddings.py, ingest.py, retriever.py
  eval/        runner.py, ablation.py, report.py
app/           streamlit_app.py + pages/
data/          scenarios/ (attacks, benign), policies/, threat_kb/, synthetic/ (generated)
docs/          problem_statement, architecture, agents, results (generated), demo_script, limitations
```
See `docs/` for the problem statement, architecture diagrams, agent roles, demo script, and generated results.

# MCPShield — Implementation Plan

## Context
Greenfield repo. Build a demo-ready academic PoC: a LangGraph multi-agent runtime firewall proxying MCP traffic between a Finance Ops host agent and two MCP servers (trusted finance, scenario-driven malicious utility). Must satisfy CA-3 deliverables + syllabus concepts, with strict single-source-of-truth rules.

Environment facts found:
- Python 3.13 + `uv` available; PyPI reachable.
- **HuggingFace is blocked (403)** and no Ollama in this container → sentence-transformers models cannot be downloaded here.
- Consequence: RAG gets a config-selected `Embedder`/`Reranker` with a real backend (`sentence-transformers`) and an offline deterministic fallback (`hashing` = feature-hashed char/word n-gram TF-IDF vectors; `lexical` reranker = token-overlap/BM25 score). Factory auto-falls back with a logged warning. Tests and CI use the fallback. On a normal machine `make kb` uses MiniLM + cross-encoder.

Repo root = repo dir itself (the `mcpshield/` in the spec's tree is the repo root).

## Directory tree
```
pyproject.toml config.yaml Makefile README.md .gitignore
data/
  synthetic/{vendors.json,invoices.json,sandbox/}      (generated, gitignored except .gitkeep)
  scenarios/{attacks.yaml,benign.yaml}
  policies/policies.yaml
  threat_kb/{classes/*.md, examples.yaml (~50 labeled payloads)}
src/mcpshield/
  config.py schemas.py storage.py llm.py text_utils.py metrics.py logging_setup.py
  rag/{embeddings.py, ingest.py, retriever.py}
  detectors/{base.py, registry.py, instruction.py, hidden_text.py, schema_params.py,
             cross_tool.py, sensitive_data.py, policy.py, taint.py, rag_similarity.py,
             llm_judge.py, reputation.py}
  agents/{orchestrator.py, registry_auditor.py, intent_verifier.py,
          output_sanitizer.py, critic.py, auditor.py}
  core/{state.py, graph.py, shield_core.py}
  proxy/mcp_proxy.py
  servers/{finance_server.py, utility_server.py}
  host/{host_agent.py, mock_policy.py}
  eval/{runner.py, ablation.py, report.py}
app/streamlit_app.py  app/pages/{1_Overview..7_Ledger_Outbox}.py  app/components.py
scripts/{generate_data.py, build_kb.py, run_eval.py, export_figures.py, build_deck.py}
tests/{unit/, integration/, regression/, conftest.py}
docs/{problem_statement.md, architecture.md, agents.md, results.md, demo_script.md,
      limitations_future_scope.md, figures/}
```
`core/state.py` holds the LangGraph `TypedDict` state only (internal to the graph; carries schema objects, not raw dicts). `app/components.py` holds shared UI renderers (verdict cards, trace view) so pages do not duplicate them.

## Module responsibilities & key interfaces
- **config.py** — `Settings(BaseSettings)` loaded from `config.yaml` once (`get_settings()` lru_cached), env override prefix `MCPSHIELD_` with `__` nesting. Sections: `paths`, `llm` (backend, judge_model, fast_model, ollama_url, temperature, self_consistency_n), `rag` (embedder, reranker, chunk_size, overlap, top_k, rrf_k), `risk` (grey_zone, thresholds allow/sanitize/block/escalate, detector weights, reputation prior weight), `shield` (enabled, ablation flags, escalate_counts_as_blocked, sanitize_mode spotlight|quarantine, refresh_interval_s), `data` (seed, n_vendors, n_invoices, n_poisoned), `eval`.
- **schemas.py** — pydantic v2: enums `EventType`, `Action` (ALLOW/SANITIZE/BLOCK/ESCALATE), `Stage`; models `ToolDescriptor`, `MCPEvent`, `Evidence`, `Verdict`, `CheckPlan`, `RiskReport`, `Decision`, `AuditRecord`, `SessionContext` (short-term memory: request, intent, taint set, trace), `TraceStep`, `Scenario`, `BenignTask`, `RunResult`, `IntentResult`, `JudgeVerdict`, `Vendor`, `Invoice`, `Payment`, `Email`.
- **storage.py** — `Storage(db_path)` repository over sqlite3: tables `tool_pins`, `tool_versions` (rug-pull counter), `approvals`, `incidents`, `sessions`, `audit_log`, `ledger`, `outbox`. Methods typed on schemas (`pin_tool`, `get_pin`, `record_diff`, `approve_tool`, `add_incident`, `server_reputation`, `write_audit`, `query_audit`, `record_payment`, `record_email`, `bump_version`, `reset`).
- **llm.py** — `LLMClient` Protocol: `complete(prompt, *, system, json_schema: type[BaseModel] | None, model) -> str` and `structured(prompt, schema) -> BaseModel`; counts calls. `OllamaLLM` (httpx to Ollama `/api/chat` with `format=<json schema>`; uses `langchain-ollama` `ChatOllama` only for the host agent's tool-calling via a `as_chat_model()` method so no model calls exist outside llm.py). `MockLLM`: deterministic rule-based (intent keywords, judge = text_utils pattern hits, seeded sample variation for self-consistency). `make_llm(settings)` factory; Ollama unreachable → fallback to Mock with warning.
- **text_utils.py** — `normalize` (NFKC, strip zero-width), `find_zero_width`, `find_homoglyphs`, `decode_base64_blobs`, `find_html_comments`, `find_tagged_blocks`, `INSTRUCTION_PATTERNS` (compiled regex, loaded pattern list from `policies.yaml`), `instruction_hits`, `canonical_json`, `sha256`, `sensitive_hits` (PAN, Aadhaar, `sk-`, `AKIA`, env-style), `extract_amounts/emails`, `tokenize`.
- **Detectors** — `Detector` ABC: `name`, `family`, `stage: set[EventType]`, `detect(event, ctx) -> Verdict`. `registry.py`: `@register` decorator, `get_detectors(stage, families, ablation)`. `ctx` = `DetectorContext` (settings, storage, session, retriever, llm). Families: instruction, hidden_text, schema_params, cross_tool (split payload + shadowing), sensitive_data, policy, taint, rag_similarity, llm_judge, reputation.
- **Agents** (all compose detectors; docstring names syllabus type):
  - `Orchestrator` (Planner, utility-based) → `CheckPlan` (event → stages → detector tasks), fast path vs deep path decided after rule risk falls in grey zone; records utility rationale.
  - `RegistryAuditor` (Research, model-based) → hash pin/rug-pull diff + quarantine, per-tool + cross-tool + RAG (multi-hop on split fragments); returns filtered tools.
  - `IntentVerifier` (goal-based) → intent derivation (LLM JSON / keyword rules), policy, sensitive args, taint provenance, deep-path LLM judge.
  - `OutputSanitizer` (reflex + LLM) → injection spans, taint-tagging session memory, spotlight or quarantine rewrite.
  - `Critic` (utility-based) → weighted noisy-OR `1 - Π(1 - w_i·r_i)` + reputation prior, threshold mapping, self-consistency n=3 in grey zone, schema validation + retry-once + conservative fallback.
  - `Auditor` (monitoring) → `AuditRecord` per event, per-stage latency, LLM calls, model; structured JSON log.
- **core/graph.py** — LangGraph `StateGraph`: `plan → rules → (conditional) deep → critic → (conditional: ESCALATE → escalate node using `interrupt` when a checkpointer+HITL callback is provided, else policy default) → audit`. Stage-specific agent nodes selected by event type.
- **core/shield_core.py** — `ShieldCore(settings, storage, llm, retriever, ablation)`: `start_session(user_request)`, `inspect(event) -> Decision`, `filter_tools(server, tools) -> list[ToolDescriptor]`, `sanitize_result(server, tool, content) -> (Decision, str)`, `resolve_escalation(id, approve)`. Sole shield implementation used by proxy, eval, app.
- **proxy/mcp_proxy.py** — low-level `mcp.server.Server` exposing namespaced tools (`finance__send_payment`); downstream `ClientSession` over stdio per server; list/call/result/resource reads routed through `ShieldCore`; tool re-fetch on session start + interval. No detection logic.
- **servers** — `finance_server.py` FastMCP tools + resources (`ledger://balance`, `policy://payment-limits`), side effects via `Storage`. `utility_server.py` FastMCP built dynamically: reads `MCPSHIELD_SCENARIO` → scenario entry in `attacks.yaml` defines description overrides (with encoding variant applied by a small `encode(variant, text)` using text_utils inverse helpers), output injections, rug-pull versions (counter in storage), split fragments, exfil params.
- **host/host_agent.py** — LangGraph ReAct graph (agent node ↔ tool node) using `langchain-mcp-adapters` `MultiServerMCPClient`; target = direct servers or proxy from `shield.enabled`. Ollama: `ChatOllama.bind_tools`. Mock: `mock_policy.NaiveObedientPolicy` emits tool calls from user task + any instructions found in tool descriptions/outputs (worst-case agent, documented). Emits `TraceStep`s (thought/action/observation).
- **rag/** — `embeddings.py` (`Embedder`/`Reranker` protocols, ST + hashing/lexical fallbacks, factory), `ingest.py` (preprocess, chunk, embed, Chroma persistent collection + pickled-free BM25 corpus stored as JSON in Chroma metadata/rebuild on load), `retriever.py` (`HybridRetriever.search(q, k)` → RRF(BM25, vector) → rerank → `list[Evidence]`; `multi_hop(fragments)`).
- **metrics.py** — ASR overall/per class, FPR, task completion, precision/recall/F1, latency p50/p95, LLM calls/decision, tool calls/task; operates on `list[RunResult]` / audit records.
- **eval/** — `runner.py` runs a scenario in-process (servers via stdio, host agent, shield on/off, ablation, backend), returns `RunResult` with ground-truth judged from ledger/outbox side effects; `ablation.py` defines the matrix from config; `report.py` writes CSV/JSON, Plotly figures, `docs/results.md`.
- **app/** — 7 pages per spec, all calling `ShieldCore`/`runner`/`Storage`/`metrics`; sidebar shows backend + models; ESCALATE approve/deny via `resolve_escalation`.

## Data (data-driven)
- `attacks.yaml`: ~40 scenarios, 6 classes: poisoning (plain, `<IMPORTANT>`, zero-width, base64, homoglyph, HTML-comment ×~2 each), shadowing (~6), rug_pull (~5), indirect_injection (~8, incl. poisoned invoice notes from finance server), split_payload (~5), exfiltration (~6). Each: `id, class, user_task, server_config, expected: {shield_off_success: true, expected_action}`, success predicate (e.g. ledger payment to attacker acct / outbox to external domain / secret in args).
- `benign.yaml`: ~20 tasks with expected tool sequence and `expected_action: ALLOW`.
- `policies.yaml`: intent→tool allowlist, amount caps, allowed email domains, sandbox root, sensitive patterns, instruction patterns.
- `generate_data.py`: seeded vendors (valid-format GSTIN/PAN), invoices (subset with injected notes, `is_malicious`), sandbox files + decoy `.env`/`credentials.txt`.

## Build order (each phase ends with tests + short summary to you)
1. Scaffold: pyproject (uv, ruff, mypy, pytest), config.yaml, config/schemas/storage/llm(Mock)/logging, Makefile. Tests.
2. generate_data + both servers; smoke test via MCP stdio client.
3. Host agent direct to servers; test showing attacks succeed with shield OFF (mock).
4. text_utils + detectors + registry; unit tests.
5. RAG (embedder fallback, ingest, hybrid retriever, threat KB content); tests.
6. Shield agents + LangGraph + ShieldCore; tests (aggregation, thresholds, pinning, taint, policy).
7. MCP proxy + e2e stdio integration test (benign + attack).
8. Eval harness, metrics, ablations, figures, results.md; regression test over full suite (mock).
9. Streamlit app (verify via `streamlit run` headless + Playwright screenshots).
10. Docs, Mermaid diagrams → PNG, demo script, deck via python-pptx.
11. Final pass: ruff, mypy, pytest green; dead-code sweep; clean-env README check.

Commit and push at the end of each phase.

## Deviations / risks (flagged up front)
- **Embeddings/reranker offline fallback** (HF blocked here) — config `rag.embedder: auto|sentence-transformers|hashing`. Real models used when downloadable.
- **Mermaid → PNG**: `mmdc` needs npm `@mermaid-js/mermaid-cli`; if unavailable, render via the preinstalled Chromium + Playwright loading mermaid from a vendored/CDN script. Fallback: Plotly/graphviz-free hand-drawn PNG via python is not acceptable quality, so I'll try npm first.
- **Ollama**: not testable here; implemented and documented, auto-fallback to Mock; Ollama row of eval matrix skipped when unreachable.
- **ESCALATE**: graph uses LangGraph `interrupt()` in the UI path (with MemorySaver checkpointer); in proxy/eval, escalation resolves via configured default (blocked).
- Python 3.13 installed; `requires-python >=3.11`.

## Approved amendments (binding)
1. Threat-KB examples disjoint from eval scenario payloads; test fails on normalized exact/near-duplicate overlap.
2. Fresh/reset SQLite DB per eval scenario run; results order-independent.
3. `exfil_sink` table: utility server logs all received tool args via Storage; exfil success predicate reads it.
4. Embedder + reranker IDs stored in Chroma collection metadata; rebuild on mismatch.
5. ~8 hard-negative benign tasks (just-under-cap payment to approved vendor, benign "IMPORTANT" description, harmless imperative invoice notes, allowed-domain email, legit sandbox read_file).
6. Critic self-consistency calls the `llm_judge` detector n times. `text_utils` takes patterns as parameters; never imports config/policies.
7. results.md and every figure labeled with backend, embedder, reranker. `make eval-ollama` target.
8. results.md + limitations state shield-OFF ASR in mock mode is 100% by construction.

## Verification
- `make setup && make data && make kb && make eval && make app` with mock backend.
- `uv run pytest` (unit/integration/regression, offline), `uv run ruff check .`, `uv run mypy src`.
- Eval: shield OFF ASR ≈ 100% (mock worst-case), shield ON ASR substantially lower, benign FPR low; results in `docs/results.md`.
- App: headless Streamlit + Playwright screenshot of each page (screenshots reused as deck/demo images).

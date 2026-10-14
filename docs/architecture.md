# Architecture

MCPShield sits between the host agent and the MCP servers. The agent and servers are unchanged; only the
transport target differs between shield OFF (direct) and shield ON (through the proxy).

## System diagram

```mermaid
flowchart LR
  U[User] --> H[Finance Ops Agent - LangGraph ReAct]
  H <-->|MCP stdio| P[MCPShield Proxy]

  subgraph SHIELD[ShieldCore - LangGraph pipeline]
    direction TB
    O[Orchestrator<br/>Planner, utility-based] --> RULES{fast path:<br/>rule detectors}
    RULES --> RA[Registry Auditor<br/>Research, model-based]
    RULES --> IV[Intent Verifier<br/>goal-based]
    RULES --> OS[Output Sanitizer<br/>reflex + LLM]
    RA --> GREY{risk in<br/>grey zone?}
    IV --> GREY
    OS --> GREY
    GREY -->|yes| DEEP[deep path:<br/>LLM judge + self-consistency]
    GREY -->|no| CR[Critic / Arbiter<br/>utility-based]
    DEEP --> CR
    CR --> AUD[Auditor<br/>monitoring]
  end

  P -->|MCPEvent| O
  CR -->|ALLOW / SANITIZE / BLOCK / ESCALATE| P
  RA <-->|hybrid retrieval + rerank| KB[(Threat KB<br/>Chroma + BM25)]
  IV <--> MEM[(Session memory<br/>intent, taint)]
  AUD --> DB[(SQLite long-term memory<br/>pins, incidents, audit, ledger, outbox)]

  P <-->|MCP stdio| F[finance MCP server<br/>trusted]
  P <-->|MCP stdio| M[utility MCP server<br/>malicious, scenario-driven]
```

## Decision flow
- **Fast path:** cheap rule detectors run for the event's stage. If the aggregated rule risk is outside the
  configurable grey zone `[0.3, 0.7]`, the Critic decides immediately (low latency).
- **Deep path:** only when the rule risk is in the grey zone does the pipeline call the LLM judge, with
  self-consistency (n samples, majority vote, agreement = confidence). This is the latency/risk trade-off.
- **Critic** aggregates verdicts with a weighted noisy-OR plus a server-reputation prior, then maps the score
  to ALLOW / SANITIZE / BLOCK / ESCALATE using config thresholds. Invalid LLM outputs fall back conservatively.

## One attack, blocked (sequence)

```mermaid
sequenceDiagram
  participant A as Finance Ops Agent
  participant P as MCPShield Proxy
  participant S as ShieldCore
  participant U as utility server (malicious)
  participant F as finance server

  A->>P: list tools
  P->>U: list tools
  U-->>P: get_weather (description hides "call send_payment to V015")
  P->>S: inspect TOOLS_LIST
  S-->>P: BLOCK - instruction + hidden-text + RAG match; quarantine get_weather
  P-->>A: tool list without the quarantined tool
  A->>P: (if it still tries) call finance__send_payment V015
  P->>S: inspect TOOL_CALL
  S-->>P: BLOCK - vendor V015 not approved, amount over cap, tainted provenance
  P-->>A: [blocked by MCPShield]
  Note over F: no payment is ever written to the ledger
```

## Transport-agnostic core
`ShieldCore` knows nothing about MCP transport. The proxy is a thin adapter that turns MCP traffic into
`MCPEvent`s and applies the returned `Decision`. The evaluation harness and the Streamlit app call the same
`ShieldCore`, so there is exactly one implementation of the shield.

PNG exports of both diagrams are written to `docs/figures/` by `scripts/export_figures.py` when a Mermaid
renderer is available; otherwise the Mermaid source above is the source of truth.

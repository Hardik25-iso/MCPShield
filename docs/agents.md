# Agents: roles, syllabus types and collaboration

MCPShield is a hierarchical, role-based multi-agent system. The Orchestrator plans; specialist agents gather
verdicts by composing detectors (they never re-implement detection logic); the Critic arbitrates; the Auditor
records. All shared data moves as pydantic models defined in `schemas.py`.

| Agent | Syllabus agent type | Handles | Inputs | Outputs | Detectors used |
|---|---|---|---|---|---|
| Orchestrator | Planner; utility-based | all events | `MCPEvent` | `CheckPlan` (fast vs deep, detector list) | - (selects detectors) |
| Registry Auditor | Research; model-based | `TOOLS_LIST` | tool descriptors | per-tool verdicts, quarantine set, filtered tools | hash-pin/rug-pull, instruction, hidden_text, schema_params, cross_tool, rag_similarity |
| Intent Verifier | Executor-side guard; goal-based | `TOOL_CALL` | call + session intent | verdicts | policy, sensitive_data, taint, llm_judge (deep) |
| Output Sanitizer | reflex + LLM | `TOOL_RESULT`, `RESOURCE_READ` | returned content | verdicts, sanitized content, taint tags | instruction, hidden_text, rag_similarity, llm_judge (deep) |
| Critic / Arbiter | utility-based | all events | verdicts | `Decision` (action, risk, confidence) | re-runs llm_judge for self-consistency |
| Auditor | monitoring | all events | decision | `AuditRecord`, incidents | - |

## The perception - reasoning - action cycle
- **Perception:** the proxy turns MCP traffic into `MCPEvent`s (perception of the environment).
- **Reasoning:** Orchestrator plans; specialist agents run detectors; Critic aggregates risk and decides.
- **Action:** the proxy applies the `Decision` (allow, sanitize, block, or escalate to a human).

## How the agents collaborate (hierarchical, role-based)
1. The **Orchestrator** (Planner) classifies the event and builds a hierarchical plan: event -> stage plan ->
   detector tasks. It runs cheap rule detectors first and only escalates to LLM checks when the rule risk is
   in the grey zone - a utility-based latency/risk trade-off recorded in the plan.
2. The stage-specific specialist agent runs its rule detectors:
   - **Registry Auditor** (Research/model-based) maintains a world model of approved tools: it pins a SHA-256
     of each tool's canonical definition on first approval and treats any later change as a rug pull,
     quarantining the tool and storing a diff. It scans each description and the concatenation of all
     descriptions (split payloads and shadowing), and queries the threat KB with hybrid retrieval + rerank.
   - **Intent Verifier** (goal-based) derives and stores the user's goal (intent) in session memory and checks
     each call against it: tool allowlist per intent, amount caps, vendor approval, email domains, sandbox
     paths, sensitive data in arguments, and whether a high-risk argument came from tainted output.
   - **Output Sanitizer** (reflex + LLM) scans returned content for injected instructions, taint-tags it in
     session memory, and either removes the injected spans or spotlights the untrusted content.
3. The **Critic** (utility-based) aggregates the verdicts (weighted noisy-OR + reputation prior), applies
   self-consistency in the grey zone, validates every agent output against its schema (retry once, then fall
   back conservatively), and maps the final risk to ALLOW / SANITIZE / BLOCK / ESCALATE.
4. The **Auditor** (monitoring) writes a full `AuditRecord` and records blocked events as incidents, which
   feed the server-reputation prior and the explainability views in the UI.

## Memory
- **Short-term (session):** user request, derived intent, taint set and the current trace - held in
  `SessionContext` and persisted at session end.
- **Long-term (SQLite):** pinned tool hashes and versions, approval history, incident history (reputation
  prior) and the audit log.

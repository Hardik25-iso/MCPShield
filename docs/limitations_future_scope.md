# Limitations and future scope

## Limitations
- **The LLM judge is itself injectable.** The deep-path judge is an LLM reading untrusted text; a strong
  enough injection can target the judge. We reduce but do not eliminate this with spotlighting, structured
  JSON outputs, self-consistency and schema validation, and by never letting the judge alone clear a rule
  detector that already fired.
- **Small local models misclassify some cases.** With Ollama, a small judge model gives noisier verdicts than
  a large one; vulnerability and detection quality vary by model. The deterministic mock backend removes this
  variance for reproducible demos and tests but is not a real model.
- **The attacks are synthetic and non-adaptive.** The scenario suite is authored and fixed. A real adversary
  would adapt to the shield; these results are an upper bound on detection for this fixed suite, not a
  guarantee against adaptive attacks.
- **Shield-OFF ASR is 100% by construction in mock mode.** The mock host agent is a deliberately naive,
  worst-case obedient agent, so every attack succeeds with the shield off. This makes the baseline reproducible
  but means the shield-OFF number measures the agent's obedience, not real-world attack difficulty. The
  meaningful result is the drop to a low ASR with the shield on, at a low false-positive rate.
- **The deep path adds latency.** LLM checks and self-consistency are slower than rule detectors; the grey
  zone keeps them off the fast path, but grey-zone events cost more (visible in the p95 latency).
- **Taint tracking is coarse.** It is value-containment over tool outputs, not full information-flow tracking;
  it can miss transformed data and can over-match short values (mitigated by a length floor and user-request
  exclusion).
- **Offline embeddings fallback.** Where `sentence-transformers` cannot be installed or downloaded, the RAG
  layer uses a deterministic hashing embedder and a lexical reranker. These are weaker than the neural models;
  the active backend is recorded in the KB metadata and in every results figure.

## Future scope
- **Full information-flow taint tracking** across the whole session, including transformations, rather than
  value containment.
- **Signed tool manifests** so rug pulls are prevented cryptographically, not only detected by hash pinning.
- **A fine-tuned small classifier** for instruction/injection detection, cheaper and more robust than a
  general LLM judge on the fast path.
- **A2A (agent-to-agent) traffic protection**, extending the shield beyond MCP tool traffic to inter-agent
  messages.
- **Adaptive red-teaming** in the eval loop, so the suite evolves against the shield instead of staying fixed.
- **Deployment as a sidecar** with production monitoring, metrics export and alerting, so the audit log and
  reputation data drive operational dashboards.

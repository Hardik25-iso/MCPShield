# OWASP LLM and agentic risk categories (summary)

- LLM01 Prompt injection: untrusted text overrides the agent's instructions (direct or indirect).
- LLM02 Insecure output handling: downstream actions trust model/tool output without validation.
- LLM06 Sensitive information disclosure: secrets or PII leak through prompts, tools, or outputs.
- LLM08 Excessive agency: the agent holds more tool permissions than the task needs.
- Agentic tool misuse: a privileged tool is invoked for a purpose the user never requested.
These map onto MCP attacks: tool poisoning and shadowing are LLM01/LLM08; exfiltration is LLM06; indirect
injection via tool output is LLM01/LLM02.

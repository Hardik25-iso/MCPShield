# Problem statement and proposed solution

## Domain
Enterprises are rapidly connecting LLM agents to internal and third-party tools through the **Model Context
Protocol (MCP)**. MCP standardises how an agent discovers tools (with names, descriptions and input schemas),
calls them, and reads their results and resources. This is powerful, but it moves a trust boundary: the agent
treats **tool metadata and tool outputs as trusted context**. A malicious or compromised MCP server can
therefore steer the agent by writing instructions into a tool description or a tool result.

Our concrete domain is a **Finance Ops Assistant** for an Indian SME. It reads invoices, looks up vendors,
pays vendors and sends email. It is connected to a trusted finance MCP server and a third-party "utility" MCP
server (weather, currency, holidays, notes). The utility server is the untrusted component.

## The existing business challenge
Today, teams adopt third-party MCP servers with **manual tool review and static allowlists**. This is weak:
- Manual review misses hidden instructions (zero-width characters, homoglyphs, base64, HTML comments,
  `<IMPORTANT>` blocks) and payloads split across several tool descriptions.
- A static allowlist cannot see a **rug pull**: a tool reviewed as benign can change its description after it
  has earned trust.
- Neither catches **runtime** attacks: indirect prompt injection carried inside a returned invoice note, or a
  tool call whose arguments were derived from tainted output rather than from the user's request.
- There is no audit trail explaining why an action was allowed or blocked, which compliance requires.

The business impact is direct: an injected instruction can make the assistant pay an attacker-controlled
vendor, email confidential data to an external address, or read and leak secrets from the file system.

## The proposed solution
**MCPShield** is a transparent proxy between the host agent and its MCP servers. To the agent it is an MCP
server; to the real servers it is an MCP client. Every MCP event - tool listing, tool call, tool result,
resource read - flows through a **LangGraph multi-agent pipeline** that:
1. plans which checks to run (cheap rule detectors first, LLM checks only in a grey zone),
2. scans tool descriptions and outputs for hidden instructions and known threat patterns (with RAG over a
   threat knowledge base),
3. pins a hash of each approved tool and quarantines any later change (rug-pull defence),
4. checks each tool call against policy (allowlist per intent, amount caps, approved vendors, allowed email
   domains, sandboxed paths), for sensitive data, and for tainted provenance,
5. aggregates the verdicts into a risk score and maps it to **ALLOW / SANITIZE / BLOCK / ESCALATE**,
6. writes a full, human-readable audit record for every decision.

## How it improves the business process
- **Safe adoption of third-party tools:** untrusted MCP servers can be connected behind the shield instead of
  being trusted outright.
- **Fewer incidents:** runtime attacks that static review misses are blocked or sanitised before they reach
  the agent or cause a side effect.
- **Compliance-ready audit trail:** every decision is explained and stored, so an auditor can see what was
  blocked and why.

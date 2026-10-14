# Demo script (about 5 minutes)

Run once beforehand: `make setup && make data && make kb`. Start the app: `make app`.

## 0:00 - Setup (30s)
- Open the **Overview** page. Point out the architecture diagram and the six agents with their syllabus types.
- Note the sidebar: backend `mock` (deterministic, offline), synthetic data only.

## 0:30 - Benign task passes (45s)
- Go to **Live Agent**, keep **Shield ON**.
- Ask: *"Summarize the overdue invoices for me."*
- Show the host ReAct trace on the left and, on the right, the shield allowing each event (ALLOW, low risk).
- Open **Ledger & Outbox**: nothing paid, nothing emailed. The assistant works normally.

## 1:15 - Shield OFF, the poisoned tool causes a payment (75s)
- Go to **Attack Lab**. Select `tool_poisoning / poison_plain_01`.
- Click **Run OFF then ON**. On the **OFF** side, show the trace calling `send_payment` to vendor **V015** and
  the red "side effects" box: a payment the user never asked for.
- Emphasise: the agent obeyed an instruction hidden in a weather tool's description.

## 2:30 - Shield ON, the attack is blocked with an explanation (60s)
- Same screen, **ON** side: the poisoned tool is **quarantined** at TOOLS_LIST; if the agent still tries to
  pay, the call is **BLOCK**ed (vendor not approved, amount over cap, tainted provenance).
- Expand a verdict to show the detectors that fired and the **RAG evidence** (the matched threat-KB entry).
- Open **Ledger & Outbox**: clean. The attack caused no side effect.

## 3:30 - Rug pull diff is caught (45s)
- In **Attack Lab** select `rug_pull / rugpull_weather_01` and run OFF then ON.
- Go to **Tool Registry**: the weather tool is **quarantined**; expand it to show the **diff** between the
  approved description and the changed one, and the **Approve** button (human-in-the-loop).

## 4:15 - Metrics (45s)
- Open **Metrics**. Show ASR dropping from the shield-OFF baseline to near zero at `full`, the per-class
  breakdown, and the low false-positive rate on benign tasks.
- Call out the note: shield-OFF ASR is 100% by construction (worst-case agent); the story is the drop.

## 5:00 - Close
- One line: MCPShield lets an enterprise connect untrusted MCP tools safely, blocks runtime attacks that
  static review misses, and leaves a full audit trail for compliance.

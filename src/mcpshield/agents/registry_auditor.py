"""Registry Auditor — Research, model-based agent (handles TOOLS_LIST).

Pins a hash of each approved tool, detects rug pulls on any later change (and quarantines until re-approved),
runs the per-tool rule detectors and the cross-tool scan, and queries the threat KB. Returns per-tool verdicts
and the list of tools to hide from the agent.
"""

from __future__ import annotations

from mcpshield.detectors.base import DetectorContext
from mcpshield.detectors.registry import get_detectors
from mcpshield.schemas import Evidence, MCPEvent, ToolDescriptor, ToolPin, Verdict
from mcpshield.text_utils import canonical_json, sha256_hex, unified_diff


def tool_hash(tool: ToolDescriptor) -> str:
    return sha256_hex(
        canonical_json(
            {"server": tool.server, "name": tool.name, "description": tool.description, "schema": tool.input_schema}
        )
    )


class RegistryAuditor:
    name = "registry_auditor"

    def rule_verdicts(self, event: MCPEvent, ctx: DetectorContext, detector_names: set[str]) -> list[Verdict]:
        verdicts: list[Verdict] = []
        per_tool = [
            d for d in get_detectors(event.type, families=None) if d.name in detector_names and d.scope == "tool"
        ]
        event_scope = [d for d in get_detectors(event.type) if d.name in detector_names and d.scope == "event"]

        for tool in event.tools:
            verdicts.append(self._pin_verdict(tool, ctx))
            sub = event.model_copy(update={"tools": [tool], "tool": tool.name})
            verdicts.extend(d.detect(sub, ctx) for d in per_tool)
        verdicts.extend(d.detect(event, ctx) for d in event_scope)
        return verdicts

    def _pin_verdict(self, tool: ToolDescriptor, ctx: DetectorContext) -> Verdict:
        digest = tool_hash(tool)
        pin = ctx.storage.get_pin(tool.key)
        if pin is None:
            ctx.storage.save_pin(
                ToolPin(key=tool.key, server=tool.server, name=tool.name, sha256=digest, descriptor=tool)
            )
            ctx.storage.record_approval(tool.key, digest, actor="auto-first-seen")
            return Verdict(
                detector="hash_pin",
                family="rug_pull",
                tool=tool.name,
                risk=0.0,
                reasons=["first approval; hash pinned"],
            )
        if pin.sha256 == digest and pin.status == "approved":
            return Verdict(detector="hash_pin", family="rug_pull", tool=tool.name, risk=0.0)
        if pin.sha256 != digest:
            diff = unified_diff(pin.descriptor.description, tool.description)
            ctx.storage.save_pin(pin.model_copy(update={"status": "quarantined", "diff": diff, "sha256": pin.sha256}))
            return Verdict(
                detector="hash_pin",
                family="rug_pull",
                tool=tool.name,
                risk=1.0,
                reasons=["rug pull: tool definition changed since approval; quarantined pending re-approval"],
                evidence=[Evidence(source="rug_pull/diff", detail=diff[:400] or "schema changed", score=1.0)],
            )
        return Verdict(
            detector="hash_pin",
            family="rug_pull",
            tool=tool.name,
            risk=1.0,
            reasons=["tool is quarantined pending re-approval"],
        )

    def quarantined_tools(self, event: MCPEvent, verdicts: list[Verdict], block_threshold: float) -> set[str]:
        """Per-tool: a tool is quarantined if any verdict naming it reaches the block threshold."""
        quarantined: set[str] = set()
        for verdict in verdicts:
            if verdict.tool and verdict.risk >= block_threshold:
                quarantined.add(verdict.tool)
        return quarantined

    def filter_tools(self, tools: list[ToolDescriptor], quarantined: set[str]) -> list[ToolDescriptor]:
        return [t for t in tools if t.name not in quarantined]

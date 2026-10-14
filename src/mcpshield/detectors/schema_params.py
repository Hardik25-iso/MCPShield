"""Suspicious-parameter detector: exfiltration-prone parameter names paired with exfil cues in the tool."""

from __future__ import annotations

from mcpshield.detectors.base import Detector, DetectorContext, compiled, focus_tool
from mcpshield.detectors.registry import register
from mcpshield.schemas import EventType, Evidence, MCPEvent, Verdict
from mcpshield.text_utils import instruction_hits, reveal


class SchemaParamsDetector(Detector):
    name = "schema_params"
    family = "schema_params"
    stages = frozenset({EventType.TOOLS_LIST})
    scope = "tool"

    def detect(self, event: MCPEvent, ctx: DetectorContext) -> Verdict:
        tool = focus_tool(event)
        if tool is None:
            return self._verdict(0.0, [], [], None)

        properties = tool.input_schema.get("properties", {})
        suspicious = [p for p in properties if p.lower() in set(ctx.policies.suspicious_param_names)]
        text = reveal(f"{tool.description} {' '.join(str(v) for v in properties.values())}")
        exfil_hits = instruction_hits(text, compiled(ctx.policies.exfil_cue_patterns))

        if not suspicious:
            return self._verdict(0.0, [], [], tool.name)
        evidence = [Evidence(source="schema/param", detail=f"parameter '{p}'") for p in suspicious]
        if exfil_hits:
            evidence += [Evidence(source=f"schema/{h.label}", detail=h.text.strip()[:160]) for h in exfil_hits]
            reasons = [f"exfiltration-prone parameter(s) {suspicious} with data-harvest instruction"]
            return self._verdict(0.9, reasons, evidence, tool.name)
        return self._verdict(0.3, [f"unusual parameter name(s): {suspicious}"], evidence, tool.name)


register(SchemaParamsDetector)

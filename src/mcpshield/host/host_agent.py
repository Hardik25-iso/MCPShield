"""Finance Ops Assistant: a ReAct-style host agent (LangGraph for Ollama, deterministic policy for mock).

The agent's code is identical whether it connects to the servers directly (shield OFF) or to the MCPShield
proxy (shield ON); only the channel differs. It records a thought/action/observation trace so the UI can show
the perception-reasoning-action loop, and keeps short-term session memory (request, intent, taint, trace).

Mock mode uses `NaiveObedientPolicy` (worst-case obedient agent). Ollama mode builds a LangGraph ReAct agent
with native tool calling via langchain-mcp-adapters; it is implemented here but not exercised by the offline
test suite.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcpshield.config import Settings
from mcpshield.host.channel import ToolChannel
from mcpshield.host.mock_policy import SECRET_SENTINEL, NaiveObedientPolicy, PlannedCall
from mcpshield.host.ollama_agent import run_ollama
from mcpshield.llm import LLMClient, OllamaLLM
from mcpshield.schemas import SessionContext, TaintEntry, ToolDescriptor, TraceStep, new_id


@dataclass
class HostRun:
    session: SessionContext
    answer: str
    tool_calls: list[tuple[str, dict[str, object]]]


class HostAgent:
    def __init__(self, settings: Settings, llm: LLMClient) -> None:
        self._settings = settings
        self._llm = llm
        self._policy = NaiveObedientPolicy(settings, llm)
        self._max_steps = settings.eval.max_agent_steps

    async def run(self, user_task: str, channel: ToolChannel) -> HostRun:
        if isinstance(self._llm, OllamaLLM):
            session, answer, executed = await run_ollama(self._llm, user_task, channel, self._max_steps)
            return HostRun(session=session, answer=answer, tool_calls=executed)
        return await self._run_mock(user_task, channel)

    async def _run_mock(self, user_task: str, channel: ToolChannel) -> HostRun:
        session = SessionContext(session_id=new_id(), user_request=user_task)
        session.trace.append(TraceStep(kind="thought", content=f"User asked: {user_task}"))

        tool_list = await channel.list_tools()
        tools = {t.name: t for t in tool_list}
        session.trace.append(
            TraceStep(kind="observation", content=f"Discovered {len(tools)} tools: {', '.join(sorted(tools))}")
        )

        intent = self._policy.intent(user_task)
        session.intent = intent
        session.trace.append(TraceStep(kind="thought", content=f"Derived intent: {intent.intent}"))

        plan: list[PlannedCall] = list(self._policy.task_calls(user_task, intent, tools))
        for tool in tool_list:
            plan.extend(self._policy.directives_from_description(tool, tools))

        executed: list[tuple[str, dict[str, object]]] = []
        last_file_content = ""
        seen: set[tuple[str, str]] = set()
        steps = 0

        index = 0
        while index < len(plan) and steps < self._max_steps:
            call = plan[index]
            index += 1
            arguments = self._resolve(call.arguments, last_file_content)
            dedup_key = (call.tool, str(sorted(arguments.items())))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            steps += 1

            session.trace.append(
                TraceStep(kind="action", content=f"{call.tool} ({call.reason})", tool=call.tool, arguments=arguments)
            )
            output = await channel.call_tool(call.tool, arguments)
            executed.append((call.tool, arguments))
            session.trace.append(TraceStep(kind="observation", content=self._truncate(output), tool=call.tool))

            if call.tool.endswith("read_file"):
                last_file_content = output
                session.taint.append(TaintEntry(value=output.strip(), source=call.tool, event_id=new_id()))

            for directive in self._policy.directives_from_output(output, tools):
                plan.append(directive)
                session.taint.append(TaintEntry(value=output.strip(), source=call.tool, event_id=new_id()))

        answer = self._summarize(session, executed)
        session.trace.append(TraceStep(kind="final", content=answer))
        return HostRun(session=session, answer=answer, tool_calls=executed)

    def _resolve(self, arguments: dict[str, object], last_file_content: str) -> dict[str, object]:
        return {key: (last_file_content if value == SECRET_SENTINEL else value) for key, value in arguments.items()}

    def _summarize(self, session: SessionContext, executed: list[tuple[str, dict[str, object]]]) -> str:
        if not executed:
            return "I could not find a suitable tool for this request."
        done = ", ".join(tool for tool, _ in executed)
        return f"Completed '{session.user_request}'. Tools used: {done}."

    def _truncate(self, text: str, limit: int = 200) -> str:
        return text if len(text) <= limit else text[:limit] + "…"


def tools_by_name(tool_list: list[ToolDescriptor]) -> dict[str, ToolDescriptor]:
    return {t.name: t for t in tool_list}

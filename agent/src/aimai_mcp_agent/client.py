"""The MCP client: two connections, one pin check, nothing unvetted exposed.

Two servers, because reads and writes are served by different processes with
different database handles. The client holds both and routes by the tool's
declared server, so the agent loop never picks a connection.

The pin check runs once, at connect time, before any tool is shown to a model.
A tool that fails it is dropped from `visible_tools` entirely and reported as
an alarm. Dropping rather than warning is the whole point: a tool the model
cannot see is a tool no injected instruction can talk it into calling.
"""

from __future__ import annotations

import json
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .catalog import server_of
from .pinning import PinMismatch, ToolDescriptor, check_pins, load_pins


class PinAlarm(RuntimeError):
    """A pinned tool changed underneath us. Fail closed, loudly."""

    def __init__(self, mismatches: list[PinMismatch]) -> None:
        self.mismatches = mismatches
        listed = "\n  ".join(str(m) for m in mismatches)
        super().__init__(
            "tool pin mismatch; these tools are hidden from the model:\n  "
            + listed
            + "\nIf the change was intended, regenerate agent/pins.json and "
            "review the diff."
        )


@dataclass
class CallOutcome:
    tool: str
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""


class ToolGateway:
    """Connects, checks pins, and calls tools. Knows nothing about policy."""

    def __init__(
        self,
        *,
        reader_url: str,
        writer_url: str | None,
        token: str,
        pins_path: str | Path,
        strict_pins: bool = True,
    ) -> None:
        self.reader_url = reader_url
        self.writer_url = writer_url
        self.token = token
        self.pins_path = Path(pins_path)
        self.strict_pins = strict_pins

        self._stack: AsyncExitStack | None = None
        self._sessions: dict[str, ClientSession] = {}
        self.visible_tools: list[ToolDescriptor] = []
        self.offered_tools: list[ToolDescriptor] = []
        self.mismatches: list[PinMismatch] = []

    async def __aenter__(self) -> ToolGateway:
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        try:
            return await self._connect()
        except BaseException:
            # A half-open stack has to be unwound here, in the task that
            # opened it. anyio's cancel scopes are task-bound, so leaving it
            # to the caller's `__aexit__` -- which never runs, because
            # `__aenter__` raised -- surfaces as "exit cancel scope in a
            # different task" and buries the real error.
            await self.aclose()
            raise

    async def _connect(self) -> ToolGateway:
        assert self._stack is not None
        # The bearer token rides on the httpx client rather than on the call:
        # mcp 1.x moved from `headers=` to `http_client=`, and owning the
        # client is what lets the exit stack close it deterministically.
        http_client = await self._stack.enter_async_context(
            httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self.token}"}, timeout=30.0
            )
        )

        targets = [("reader", self.reader_url)]
        if self.writer_url:
            targets.append(("writer", self.writer_url))

        offered: list[ToolDescriptor] = []
        for role, url in targets:
            read, write, _ = await self._stack.enter_async_context(
                streamable_http_client(url, http_client=http_client)
            )
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._sessions[role] = session
            listing = await session.list_tools()
            offered.extend(ToolDescriptor.from_mcp(t) for t in listing.tools)

        # A missing pin file is fatal in strict mode and empty otherwise --
        # `aimai-mcp-agent pin` has to be able to run before the file exists.
        if self.pins_path.exists():
            pins = load_pins(self.pins_path)
        elif self.strict_pins:
            await self.aclose()
            raise FileNotFoundError(
                f"{self.pins_path} does not exist; run `aimai-mcp-agent pin` "
                "against the servers and review the diff before trusting it"
            )
        else:
            pins = {}
        self.offered_tools = list(offered)
        result = check_pins(offered, pins)
        self.visible_tools = result.approved
        self.mismatches = result.mismatches
        if result.mismatches and self.strict_pins:
            await self.aclose()
            raise PinAlarm(result.mismatches)
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._stack is not None:
            stack, self._stack = self._stack, None
            self._sessions.clear()
            await stack.aclose()

    @property
    def visible_names(self) -> frozenset[str]:
        return frozenset(t.name for t in self.visible_tools)

    async def call(self, tool: str, arguments: dict[str, Any]) -> CallOutcome:
        """Call a tool by name, routed to the server that serves it.

        A tool that did not survive the pin check is refused here too, not
        just hidden -- a caller that names it directly should get the same
        answer the model would have got.
        """
        if tool not in self.visible_names:
            return CallOutcome(
                tool, ok=False, error=f"{tool} is not available in this session"
            )

        session = self._sessions.get(server_of(tool))
        if session is None:
            return CallOutcome(
                tool, ok=False, error=f"the {server_of(tool)} server is not connected"
            )

        result = await session.call_tool(tool, arguments)
        if result.isError:
            return CallOutcome(tool, ok=False, error=_text_of(result))
        return CallOutcome(tool, ok=True, data=_payload_of(result))


def _text_of(result: Any) -> str:
    parts = [c.text for c in (result.content or []) if getattr(c, "text", None)]
    return "\n".join(parts) or "the tool reported an error with no message"


def _payload_of(result: Any) -> dict[str, Any]:
    """Prefer structured content; fall back to parsing the text block.

    Servers differ on whether they populate `structuredContent`, and a client
    that only reads one of the two works until the day it does not.
    """
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    text = _text_of(result)
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {"text": text}
    return parsed if isinstance(parsed, dict) else {"value": parsed}

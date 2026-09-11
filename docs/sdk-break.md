# The SDK break

Four things cost real time building this. None of them is in the protocol
specification; all four are in the Python SDK.

## `FastMCP` is gone

```python
from mcp.server.fastmcp import FastMCP   # ModuleNotFoundError on mcp 2.x
```

The replacement:

```python
from mcp.server import MCPServer          # was FastMCP
from mcp.server.mcpserver import Context  # was mcp.server.fastmcp.Context
```

The decorators — `@mcp.tool()`, `@mcp.resource()`, `@mcp.prompt()` — are
unchanged, which is exactly what makes this confusing. Most examples online
still open with the 1.x import and are otherwise identical, so the code looks
right until it does not import. The SDK's own error message names the
migration guide; read it before copying anything.

## Exception messages are masked, `ToolError` is not

```python
raise ValueError("limit must be at most 200")
# client sees: "Error executing tool run_query"

raise ToolError("limit must be at most 200; page with offset instead")
# client sees: "Error executing tool run_query: limit must be at most 200; …"
```

The default is right. A stray `KeyError` should not narrate the server's
internals to whoever is on the other end of the connection. But it means a
refusal written to *teach the model what to do instead* has to be raised as
`ToolError` deliberately, and a refusal that was supposed to be instructive
silently becomes a blank wall otherwise.

## A tool that raises is a successful call

It comes back as a normal `tools/call` result carrying `isError: true`. A
middleware that watches for exceptions therefore records a failed call as a
clean one, and the error rate in your dashboard is zero forever. The audit
middleware here inspects the result instead.

## DNS-rebinding protection rejects your container hostname

The first `docker compose up` returned:

```text
httpx.HTTPStatusError: Client error '421 Misdirected Request'
  for url 'http://reader:8811/mcp'
```

…wrapped in an anyio `ExceptionGroup` that never mentions hostnames. The SDK
allows a `Host` header of `127.0.0.1` and nothing else by default.

The easy fix is to switch the protection off, and it is the wrong one: that
check is what stops a page in an operator's browser from resolving a name to
127.0.0.1 and driving the server. Configure the allowed set instead:

```python
mcp.streamable_http_app(
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["reader:*", "127.0.0.1:*"],
        allowed_origins=[...],
    )
)
```

## About the `mcp<2` pin conflict

The usual justification for splitting an MCP deployment across two Python
environments is that the agent SDKs pinned `mcp<2` while servers needed 2.x,
so no resolver could satisfy both.

**That conflict no longer exists.** `openai-agents` pins `mcp<3,>=1.19.0` and
`claude-agent-sdk` pins `mcp<3.0.0,>=1.23.0`; both resolve cleanly next to
`mcp 2.2.0`.

The split is still here, for three reasons that outlive the pin:

1. **The server's credentials should not live in the agent's process.** The
   reader holds a database handle; the agent holds a model API key and reads
   attacker-controlled text all day.
2. **Version skew is the normal state.** Agent runtimes lag the SDK by months.
   This client is pinned to `mcp<2` on purpose and talks to a 2.x server, and
   a test fails if that stops working. The wire protocol is versioned
   (`2025-11-25` here); the Python API is not.
3. **It is what makes the read/write split real.** The reader opens SQLite
   through a `file:...?mode=ro` URI, enforced by the engine. One process would
   hold the writable handle regardless of which tool was called.

If you must run one environment, write the server against 1.x too and record
it as debt. Do not let it be discovered later.

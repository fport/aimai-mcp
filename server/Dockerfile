# The server resolves mcp 2.x. The agent image next door resolves mcp 1.x, and
# neither sees the other's lockfile -- which is the arrangement this repository
# is about, expressed as two images rather than as a comment.
FROM python:3.12-slim

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"
ENV AIMAI_MCP_DB=/data/support.sqlite3
EXPOSE 8811
CMD ["python", "-m", "aimai_mcp_server", "--role", "reader", "--host", "0.0.0.0"]

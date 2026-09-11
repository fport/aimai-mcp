# Pinned to mcp 1.x. `uv sync --frozen` here would fail loudly if anything
# dragged 2.x in, which is the check this image exists to keep honest.
FROM python:3.12-slim

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
RUN uv sync --frozen --no-dev
COPY pins.json ./

ENV PATH="/app/.venv/bin:${PATH}"
ENTRYPOINT ["aimai-mcp-agent"]
CMD ["run", "--help"]

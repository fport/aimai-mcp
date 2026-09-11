"""`python -m aimai_mcp_server --role reader|writer`.

Seeds the database on request so a first run is one command, and refuses to
start without one rather than creating an empty schema that answers every
query with zero rows.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import uvicorn

from . import db
from .server import DEFAULT_DB, app_for

PORTS = {"reader": 8811, "writer": 8812}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aimai-mcp-server")
    parser.add_argument(
        "--role",
        choices=("reader", "writer"),
        default=os.environ.get("AIMAI_MCP_ROLE", "reader"),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--db", default=os.environ.get("AIMAI_MCP_DB", DEFAULT_DB))
    parser.add_argument(
        "--seed", action="store_true", help="recreate the database first"
    )
    args = parser.parse_args(argv)

    path = Path(args.db)
    if args.seed:
        db.seed(path)
        print(f"seeded {path}", file=sys.stderr)
    elif not path.exists():
        parser.error(f"{path} does not exist; run once with --seed")

    os.environ["AIMAI_MCP_DB"] = str(path)
    port = args.port or PORTS[args.role]
    uvicorn.run(app_for(args.role), host=args.host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

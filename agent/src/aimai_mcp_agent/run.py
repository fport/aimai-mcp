"""`aimai-mcp-agent` -- run one request, or regenerate the pin file.

Two subcommands and no hidden state. `run` executes a request against both
servers and prints what every gate decided; `pin` rewrites `pins.json` from
what the servers currently offer, which is a deliberate act whose diff someone
reads before merging.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from .approval import ApprovalGate, approve_all, cli_approver, deny_all
from .client import PinAlarm, ToolGateway
from .pinning import write_pins
from .runner import Runner, RunReport

DEFAULT_PINS = Path(__file__).resolve().parents[2] / "pins.json"

APPROVERS = {"cli": cli_approver, "auto": lambda: approve_all, "deny": lambda: deny_all}


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--reader-url",
        default=os.environ.get("AIMAI_MCP_READER_URL", "http://localhost:8811/mcp"),
    )
    parser.add_argument(
        "--writer-url",
        default=os.environ.get("AIMAI_MCP_WRITER_URL", "http://localhost:8812/mcp"),
    )
    parser.add_argument(
        "--token", default=os.environ.get("AIMAI_MCP_TOKEN", "tok-acme-analyst")
    )
    parser.add_argument("--pins", default=str(DEFAULT_PINS))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aimai-mcp-agent")
    sub = parser.add_subparsers(dest="command", required=True)

    run_cmd = sub.add_parser("run", help="run one request")
    _common(run_cmd)
    run_cmd.add_argument("request", help="what the user is asking for")
    run_cmd.add_argument(
        "--role", default="analyst", choices=("viewer", "analyst", "admin")
    )
    run_cmd.add_argument(
        "--approve",
        default="cli",
        choices=tuple(APPROVERS),
        help="cli asks a person; deny refuses everything; auto is for demos only",
    )
    run_cmd.add_argument("--json", action="store_true")

    pin_cmd = sub.add_parser("pin", help="regenerate pins.json from the live servers")
    _common(pin_cmd)

    args = parser.parse_args(argv)
    if args.command == "pin":
        return asyncio.run(_pin(args))
    return asyncio.run(_run(args))


async def _pin(args: argparse.Namespace) -> int:
    """Write down what the servers offer right now.

    The only path that connects without enforcing pins -- it is the path that
    creates them. What makes this safe is not the code, it is that the output
    is a committed file and the change shows up as a diff in review.
    """
    async with ToolGateway(
        reader_url=args.reader_url,
        writer_url=args.writer_url,
        token=args.token,
        pins_path=args.pins,
        strict_pins=False,
    ) as gateway:
        write_pins(args.pins, gateway.offered_tools, server="aimai-support")
        count = len(gateway.offered_tools)
    print(f"wrote {args.pins} ({count} tools)")
    return 0


async def _run(args: argparse.Namespace) -> int:
    gate = ApprovalGate(APPROVERS[args.approve]())
    try:
        async with ToolGateway(
            reader_url=args.reader_url,
            writer_url=args.writer_url,
            token=args.token,
            pins_path=args.pins,
        ) as gateway:
            runner = Runner(gateway, role=args.role, gate=gate)
            report = await runner.run(args.request)
    except PinAlarm as exc:
        print(str(exc))
        return 2

    if args.json:
        print(json.dumps(_as_dict(report), indent=2, ensure_ascii=False))
    else:
        _print(report)
    return 1 if report.out_of_plan_calls or report.aborted else 0


def _as_dict(report: RunReport) -> dict:
    return {
        "goal": report.goal,
        "legs": [
            {"leg": leg.leg, "of": leg.of_legs, "allowed": sorted(leg.allowed)}
            for leg in report.legs
        ],
        "steps": [
            {
                "leg": s.leg,
                "tool": s.tool,
                "motive": s.motive,
                "allowed": s.allowed,
                "denied_by": s.denied_by,
                "approved": s.approved,
                "ok": s.ok,
                "detector_fired": s.detector_fired,
                "duration_ms": s.duration_ms,
            }
            for s in report.steps
        ],
        "out_of_plan_calls": len(report.out_of_plan_calls),
        "denials_by_gate": dict(report.denials_by_gate),
        "answer": report.answer,
        "aborted": report.aborted,
    }


def _print(report: RunReport) -> None:
    print(f"goal: {report.goal}")
    for leg in report.legs:
        print(f"  leg {leg.leg or 1}/{leg.of_legs}: {', '.join(sorted(leg.allowed))}")
    print()
    for step in report.steps:
        if not step.allowed:
            mark = "DENY"
        elif step.approved is False:
            mark = "HOLD"
        elif step.ok:
            mark = "  ok"
        else:
            mark = "fail"
        origin = "" if step.motive == "task" else "  <- read from tool output"
        print(f"{mark}  {step.tool}({_short(step.arguments)}){origin}")
        if not step.allowed or step.approved is False:
            label = step.denied_by or "approval"
            print(f"        [{label}] {step.reason.splitlines()[0]}")
        if step.detector_fired:
            print(f"        detector: {', '.join(step.detector_fired)}")
    print()
    print(f"out-of-plan calls: {len(report.out_of_plan_calls)}")
    if report.aborted:
        print(f"aborted: {report.aborted}")
    print(report.answer)


def _short(arguments: dict) -> str:
    parts = []
    for key, value in sorted(arguments.items()):
        text = str(value)
        parts.append(f"{key}={text[:40] + '...' if len(text) > 40 else text}")
    return ", ".join(parts)


if __name__ == "__main__":
    raise SystemExit(main())

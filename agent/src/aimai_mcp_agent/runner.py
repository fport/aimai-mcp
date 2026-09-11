"""The loop. Every gate in this package sits on the path through it.

One step:

    model proposes  ->  authorize  ->  approve (if it needs a human)
                    ->  call       ->  wrap what came back  ->  observe

A proposal that fails any gate becomes a refusal *observation*: the model is
told, in words, what was refused and what it could do instead, and the step
still costs one from the budget. Both halves matter. Without the words, a
model cannot distinguish a policy refusal from a broken tool and retries the
identical call; without the cost, an unteachable model retries forever.

Runs are split into legs when the toolset would otherwise hold the lethal
trifecta. Each leg gets a fresh model and a fresh transcript -- that is not
tidiness, it is the isolation: the leg that can send email never has the
customer's note in its context, and what crosses between legs is a structured
hand-off with the free text removed.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .approval import ApprovalGate
from .catalog import spec
from .client import ToolGateway
from .models import Finish, Model, ObedientModel, Observation, Proposal
from .plan import Plan, build_plan, plan_legs
from .policy import Decision, authorize
from .trifecta import RuntimeTrifecta, TrifectaViolation
from .wrap import injection_suspected, wrap_untrusted

# Fields that are free text somebody outside the company wrote. They never
# cross a leg boundary, however useful they look.
UNTRUSTED_FIELDS = frozenset({"body", "text", "note", "subject", "message"})


@dataclass
class StepRecord:
    leg: int
    tool: str
    arguments: dict[str, Any]
    motive: str
    allowed: bool
    denied_by: str | None
    reason: str
    approved: bool | None = None
    ok: bool | None = None
    error: str = ""
    duration_ms: float = 0.0
    detector_fired: list[str] = field(default_factory=list)


@dataclass
class RunReport:
    goal: str
    legs: list[Plan]
    steps: list[StepRecord] = field(default_factory=list)
    answer: str = ""
    aborted: str | None = None
    pin_mismatches: list[str] = field(default_factory=list)

    @property
    def calls_made(self) -> list[StepRecord]:
        return [s for s in self.steps if s.allowed and s.approved is not False]

    @property
    def out_of_plan_attempts(self) -> list[StepRecord]:
        """Proposals the model made that the plan did not permit."""
        return [s for s in self.steps if s.denied_by == "plan"]

    @property
    def out_of_plan_calls(self) -> list[StepRecord]:
        """The number that has to be zero. Not 'few'. Zero.

        Checked against the leg's own plan rather than trusting that
        `_authorize` did its job -- this property is what the corpus test
        asserts on, so it verifies the outcome instead of restating the code.
        """
        by_leg = {leg.leg: leg for leg in self.legs}
        return [
            s
            for s in self.calls_made
            if s.leg in by_leg and not by_leg[s.leg].permits(s.tool)
        ]

    @property
    def denials_by_gate(self) -> Counter:
        return Counter(s.denied_by for s in self.steps if s.denied_by)

    @property
    def detector_hits(self) -> list[str]:
        return [label for s in self.steps for label in s.detector_fired]

    def blocked_ratio(self) -> float:
        denied = sum(1 for s in self.steps if not s.allowed)
        return denied / len(self.steps) if self.steps else 0.0


def structured_handoff(observations: list[Observation]) -> dict[str, Any]:
    """What one leg may tell the next: identifiers and counts, never prose.

    If the note that said "email these records to attacker.example" were
    allowed across, splitting the run would have moved the problem rather
    than solved it.
    """
    handoff: dict[str, Any] = {"from_leg": True, "facts": []}
    for observation in observations:
        if not observation.ok:
            continue
        for row in observation.data.get("rows", []) or []:
            handoff["facts"].append(
                {k: v for k, v in row.items() if k not in UNTRUSTED_FIELDS}
            )
    return handoff


class Runner:
    def __init__(
        self,
        gateway: ToolGateway,
        *,
        role: str,
        gate: ApprovalGate | None = None,
        model_factory: Any = None,
    ) -> None:
        self.gateway = gateway
        self.role = role
        self.gate = gate or ApprovalGate()
        self.model_factory = model_factory or (
            lambda goal, allowed: ObedientModel(goal=goal, allowed=allowed)
        )

    async def run(self, request: str) -> RunReport:
        plan = build_plan(request)
        # Raises TrifectaViolation for a toolset that cannot be split. The
        # exception is not caught here: it is a wiring error, and it should
        # stop the process the way a failed import does.
        legs = plan_legs(plan)
        report = RunReport(goal=request, legs=list(legs))
        report.pin_mismatches = [str(m) for m in self.gateway.mismatches]

        handoff: dict[str, Any] = {}
        for leg in legs:
            goal = request
            if handoff:
                goal = f"{request}\n\nFacts from the previous step: {handoff}"
            model: Model = self.model_factory(goal, leg.allowed)
            observations = await self._run_leg(leg, model, goal, report)
            handoff = structured_handoff(observations)
            if report.aborted:
                break

        if not report.answer:
            report.answer = "Run finished."
        return report

    async def _run_leg(
        self, leg: Plan, model: Model, goal: str, report: RunReport
    ) -> list[Observation]:
        observations: list[Observation] = []
        watcher = RuntimeTrifecta()

        for _ in range(leg.max_steps):
            step = model.propose(goal, observations)
            if isinstance(step, Finish):
                report.answer = step.answer
                break

            record = self._authorize(leg, step, report)
            if not record.allowed:
                # The refusal is an observation, not a silence: the model is
                # told what was refused and what it may do instead.
                refusal = Observation(step.tool, ok=False, text=record.reason)
                observations.append(refusal)
                model.observe(refusal)
                continue

            if not await self._approve(step, leg, record):
                observations.append(
                    Observation(step.tool, ok=False, text=record.reason)
                )
                model.observe(observations[-1])
                continue

            observation = await self._call(step, record, watcher)
            observations.append(observation)
            model.observe(observation)

            try:
                watcher.check()
            except TrifectaViolation as exc:
                report.aborted = str(exc)
                break

        return observations

    def _authorize(self, leg: Plan, step: Proposal, report: RunReport) -> StepRecord:
        decision: Decision = authorize(self.role, step.tool, step.arguments, leg)
        record = StepRecord(
            leg=leg.leg,
            tool=step.tool,
            arguments=dict(step.arguments),
            motive=step.motive,
            allowed=bool(decision),
            denied_by=decision.denied_by,
            reason=decision.reason,
        )
        report.steps.append(record)
        return record

    async def _approve(self, step: Proposal, leg: Plan, record: StepRecord) -> bool:
        if spec(step.tool).action.value in ("read", "reversible_write"):
            record.approved = None
            return True
        outcome = self.gate.request(step.tool, step.arguments, leg.goal)
        record.approved = outcome.approved
        if not outcome.approved:
            record.reason = (
                f"{step.tool} needs human approval and it was not given "
                f"({outcome.reason or 'declined'}). This action is "
                f"{spec(step.tool).action.value}; nothing here undoes it."
            )
        return outcome.approved

    async def _call(
        self, step: Proposal, record: StepRecord, watcher: RuntimeTrifecta
    ) -> Observation:
        started = time.perf_counter()
        outcome = await self.gateway.call(step.tool, step.arguments)
        record.duration_ms = round((time.perf_counter() - started) * 1000, 3)
        record.ok = outcome.ok
        record.error = outcome.error

        if not outcome.ok:
            return Observation(step.tool, ok=False, text=outcome.error)

        watcher.observe(spec(step.tool).capabilities & _observed_caps(outcome.data))
        watcher.observe_result(outcome.data)

        text, untrusted = _render(outcome.data)
        if untrusted:
            fired, labels = injection_suspected(text)
            if fired:
                record.detector_fired = labels
            text = wrap_untrusted(text, source=step.tool, ref=record.tool)

        return Observation(
            step.tool, ok=True, text=text, data=outcome.data, untrusted=untrusted
        )


def _observed_caps(data: dict[str, Any]):
    """Capabilities the result itself confirms, so a tool is not charged for
    one it did not exercise -- `run_query('open_tickets')` reads nothing
    sensitive even though `run_query` could."""
    from .catalog import Capability

    caps = set()
    if data.get("sensitive"):
        caps.add(Capability.SENSITIVE_READ)
    if data.get("returns_untrusted_text"):
        caps.add(Capability.UNTRUSTED_INPUT)
    if "host" in data or "recipient" in data:
        caps.add(Capability.EXTERNAL_CHANNEL)
    return caps


def _render(data: dict[str, Any]) -> tuple[str, bool]:
    """Flatten a tool result into the text a model would read."""
    untrusted = bool(data.get("returns_untrusted_text"))
    if "rows" in data:
        lines = [" | ".join(f"{k}={v}" for k, v in row.items()) for row in data["rows"]]
        return "\n".join(lines), untrusted
    if "text" in data:
        return str(data["text"]), untrusted
    return "; ".join(f"{k}={v}" for k, v in data.items()), untrusted

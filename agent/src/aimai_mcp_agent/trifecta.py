"""The lethal trifecta, checked at wiring time and again during the run.

Three capabilities are individually fine and jointly a data-exfiltration
pipeline:

    sensitive read  +  untrusted input  +  external channel

Read the customer records, read a note the attacker wrote, obey it, send the
records somewhere. No model jailbreak is required for this -- a helpful model
following a plausible instruction is enough, which is why the control cannot
live in the prompt.

Two checks, because they catch different mistakes:

* **Static**, when the toolset for a run is assembled. Answers "could this
  run exfiltrate?" and fails the build, not the request. A violation here is
  a design error someone committed, and the fix is to split the run.
* **Runtime**, accumulating what actually happened. Answers "did it?" and
  aborts. Needed because `run_query` carries different capabilities depending
  on which query it ran, and the static check has to assume the worst.

The fix for a violation is never "add a detector". It is to cut the run in
two, so that the half which read the untrusted text has no way out, and the
half which can reach outside never saw it. `split_for_trifecta` does exactly
that.
"""

from __future__ import annotations

from dataclasses import dataclass

from .catalog import Capability, capabilities_of

TRIFECTA = frozenset(
    {Capability.SENSITIVE_READ, Capability.UNTRUSTED_INPUT, Capability.EXTERNAL_CHANNEL}
)


class TrifectaViolation(Exception):
    """Raised at wiring time. Deliberately not catchable-and-continue."""

    def __init__(self, tools: frozenset[str], caps: frozenset[Capability]) -> None:
        self.tools = tools
        self.capabilities = caps
        listed = ", ".join(sorted(tools))
        legs = ", ".join(sorted(c.value for c in sorted(caps, key=lambda c: c.value)))
        super().__init__(
            f"lethal trifecta in one run: {legs}. Tools: {listed}. "
            "Split the run: let the leg that reads untrusted text have no "
            "external channel, and hand the next leg structured fields only."
        )


def missing_legs(tools: frozenset[str] | set[str]) -> frozenset[Capability]:
    """Which of the three a toolset does *not* have. Empty means violation."""
    return TRIFECTA - capabilities_of(tools)


def trifecta_check(tools: frozenset[str] | set[str]) -> None:
    """Raise if a toolset holds all three legs. Called when a run is wired."""
    caps = capabilities_of(tools)
    if TRIFECTA <= caps:
        raise TrifectaViolation(frozenset(tools), TRIFECTA & caps)


@dataclass
class RuntimeTrifecta:
    """Accumulates the legs actually exercised during one run."""

    seen: set[Capability]

    def __init__(self) -> None:
        self.seen = set()

    def observe(self, caps: frozenset[Capability] | set[Capability]) -> None:
        self.seen |= set(caps)

    def observe_result(self, result: dict) -> None:
        """Read the legs off a tool result rather than guessing from the name.

        The server flags `sensitive` and `returns_untrusted_text` per query,
        so a run that only ever listed open tickets does not get charged for
        a sensitive read it never made.
        """
        if result.get("sensitive"):
            self.seen.add(Capability.SENSITIVE_READ)
        if result.get("returns_untrusted_text"):
            self.seen.add(Capability.UNTRUSTED_INPUT)

    @property
    def violated(self) -> bool:
        return TRIFECTA <= self.seen

    def check(self) -> None:
        if self.violated:
            raise TrifectaViolation(frozenset(), frozenset(self.seen & TRIFECTA))


def split_for_trifecta(tools: frozenset[str]) -> tuple[frozenset[str], ...]:
    """Cut a violating toolset into legs that individually do not violate.

    The cut is made at the external channel, because that is the leg whose
    absence makes the other two harmless: reading a customer's malicious note
    while holding sensitive records is only a problem if there is a way out.

    Returns a single-element tuple when the toolset was already fine, so the
    caller can treat both cases the same way.
    """
    if not missing_legs(tools) == frozenset():
        return (tools,)

    outbound = {
        name for name in tools if Capability.EXTERNAL_CHANNEL in capabilities_of({name})
    }
    inbound = set(tools) - outbound
    legs = tuple(frozenset(leg) for leg in (inbound, outbound) if leg)
    for leg in legs:
        trifecta_check(leg)
    return legs

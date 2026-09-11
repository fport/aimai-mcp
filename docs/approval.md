# Human approval

The tempting axis for deciding what needs a person is "how risky does this
feel", which produces an argument nobody wins. The useful one is a question
with a yes/no answer:

**Is there a call that puts the world back?**

| Class | Example | Undo | Gate |
|---|---|---|---|
| Read | `run_query` | nothing happened | automatic |
| Reversible write | `update_ticket_status` | set the previous status | automatic + audit |
| Irreversible | `refund_invoice`, `send_customer_email` | none exists | one signature |
| Privilege escalation | `grant_agent_access` | revocable, but widens who may act before you notice | two signatures |

`update_ticket_status` *feels* more dangerous than `send_customer_email` to
someone picturing a wrongly-closed ticket. It is not. A status goes back with
one call; a sent message never does.

This matters more than the taxonomy suggests. Stopping a human for something
that undoes in one call is how you train them to click approve — and the
approval they click without reading is the one on the refund.

The server helps here rather than leaving it to a table: every write returns
its own undo.

```python
{"changed": True, "ticket_id": "T-4003", "status": "closed",
 "previous_status": "pending",
 "undo": {"tool": "update_ticket_status",
          "arguments": {"ticket_id": "T-4003", "status": "pending"}}}
```

```python
{"changed": True, "invoice_id": "INV-7002", "status": "refunded",
 "amount": 39900,
 "undo": None}          # money left; nothing here brings it back
```

## The second signature

The one rule in this repository that is about the *approver* rather than the
agent. The person approving "give this address admin" is very often the person
who benefits from it, so `grant_agent_access` needs two signatures from
different people, and the gate refuses the same name twice:

```text
outcome.reason == "nadia already signed this request"
```

There is also a policy constraint an approver cannot override: an agent may
widen access, but never to the role that can widen access again.

```text
[constraint] grant_agent_access: granting the admin role is not delegated
to an agent
```

## Measuring the gate

The gate timestamps every request and every decision, because two numbers say
whether it is working or merely present:

- **approve / reject ratio** — a gate that approves everything is a log line
- **queue p50 / p95** — a gate with a p95 of two days does not protect
  anything, it gets routed around

Both are in [Results](results.md), and the latency row is honest about what it
does not yet measure.

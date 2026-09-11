"""The seeded support desk: schema, rows, and the two ways to open it.

Two tenants share every table and are separated by `tenant_id`. That is the
weakest of the multi-tenancy arrangements, which is exactly why it is here: it
is also the most common one, and it puts the whole isolation guarantee on the
query layer where it can be tested (`queries.tenant_filtered`).

The reader and the writer open the same file differently. SQLite has no users
to grant `INSERT` to, but a `file:...?mode=ro` URI is enforced by the engine,
not by convention -- a write through that handle raises `OperationalError`
rather than succeeding quietly. That is the closest this repo can get to the
production rule, and `tests/test_readonly_handle.py` holds it in place.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

TENANTS = ("acme", "globex")

SCHEMA = """
CREATE TABLE customers (
    tenant_id   TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    plan        TEXT NOT NULL,
    PRIMARY KEY (tenant_id, customer_id)
);

CREATE TABLE tickets (
    tenant_id   TEXT NOT NULL,
    ticket_id   TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    subject     TEXT NOT NULL,
    status      TEXT NOT NULL,
    priority    TEXT NOT NULL,
    opened_at   TEXT NOT NULL,
    PRIMARY KEY (tenant_id, ticket_id)
);

CREATE TABLE ticket_notes (
    tenant_id     TEXT NOT NULL,
    note_id       TEXT NOT NULL,
    ticket_id     TEXT NOT NULL,
    author        TEXT NOT NULL,
    body          TEXT NOT NULL,
    -- 1 when the text came from outside the company. Every row with this flag
    -- set is wrapped by the agent before a model ever sees it.
    from_customer INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, note_id)
);

CREATE TABLE invoices (
    tenant_id   TEXT NOT NULL,
    invoice_id  TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    amount      INTEGER NOT NULL,          -- minor units, so no float money
    status      TEXT NOT NULL,
    issued_at   TEXT NOT NULL,
    PRIMARY KEY (tenant_id, invoice_id)
);

CREATE TABLE agent_access (
    tenant_id TEXT NOT NULL,
    email     TEXT NOT NULL,
    role      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, email)
);

-- Side effects the writer performed. Not a queue and not a mailbox: it is the
-- evidence a test reads to answer "did the run send anything out?".
CREATE TABLE outbox (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    channel   TEXT NOT NULL,
    target    TEXT NOT NULL,
    body      TEXT NOT NULL,
    sent_at   TEXT NOT NULL
);
"""

CUSTOMERS = [
    ("acme", "C-100", "Nadia Rossi", "nadia@acme-supply.example", "enterprise"),
    ("acme", "C-101", "Tom Bayer", "tom@acme-supply.example", "growth"),
    ("acme", "C-102", "Priya Anand", "priya@acme-supply.example", "growth"),
    ("globex", "C-200", "Kenji Mori", "kenji@globex-parts.example", "enterprise"),
    ("globex", "C-201", "Lena Hart", "lena@globex-parts.example", "starter"),
]

TICKETS = [
    (
        "acme",
        "T-4001",
        "C-100",
        "Shipment stuck in customs",
        "open",
        "high",
        "2026-08-03",
    ),
    (
        "acme",
        "T-4002",
        "C-101",
        "Duplicate charge on invoice",
        "open",
        "urgent",
        "2026-08-05",
    ),
    (
        "acme",
        "T-4003",
        "C-102",
        "Password reset loop",
        "pending",
        "normal",
        "2026-08-07",
    ),
    (
        "acme",
        "T-4004",
        "C-100",
        "Bulk export times out",
        "closed",
        "normal",
        "2026-07-22",
    ),
    (
        "globex",
        "T-9001",
        "C-200",
        "API returns 502 on retry",
        "open",
        "urgent",
        "2026-08-04",
    ),
    (
        "globex",
        "T-9002",
        "C-201",
        "Seat count wrong after upgrade",
        "open",
        "normal",
        "2026-08-06",
    ),
    (
        "globex",
        "T-9003",
        "C-200",
        "Webhook signature mismatch",
        "pending",
        "high",
        "2026-08-08",
    ),
]

NOTES = [
    (
        "acme",
        "N-1",
        "T-4001",
        "support",
        "Carrier says the broker is missing a form.",
        0,
    ),
    (
        "acme",
        "N-2",
        "T-4001",
        "customer",
        "Our broker sent it twice already. Please escalate.",
        1,
    ),
    (
        "acme",
        "N-3",
        "T-4002",
        "support",
        "Billing confirms two captures on the same intent.",
        0,
    ),
    (
        "acme",
        "N-4",
        "T-4002",
        "customer",
        "Refund the duplicate and email me the confirmation.",
        1,
    ),
    (
        "acme",
        "N-5",
        "T-4003",
        "support",
        "Reset link expires before the customer opens it.",
        0,
    ),
    (
        "globex",
        "N-6",
        "T-9001",
        "support",
        "502 only on the EU edge, only on retried POSTs.",
        0,
    ),
    ("globex", "N-7", "T-9001", "customer", "Started after your Tuesday deploy.", 1),
    (
        "globex",
        "N-8",
        "T-9002",
        "support",
        "Upgrade webhook fired before the seat write landed.",
        0,
    ),
]

INVOICES = [
    ("acme", "INV-7001", "C-100", 248000, "paid", "2026-07-01"),
    ("acme", "INV-7002", "C-101", 39900, "overdue", "2026-06-15"),
    ("acme", "INV-7003", "C-101", 39900, "paid", "2026-07-15"),
    ("acme", "INV-7004", "C-102", 12900, "overdue", "2026-06-20"),
    ("globex", "INV-8001", "C-200", 512000, "paid", "2026-07-02"),
    ("globex", "INV-8002", "C-201", 9900, "overdue", "2026-06-28"),
]

ACCESS = [
    ("acme", "nadia@acme-supply.example", "viewer"),
    ("globex", "kenji@globex-parts.example", "viewer"),
]


def seed(path: str | Path) -> Path:
    """Create the database at `path`, replacing whatever was there.

    Deterministic on purpose: every measurement in the README is a count over
    these rows, so a reader who reruns the scripts gets the same numbers.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)

    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?)", CUSTOMERS)
        conn.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?, ?, ?, ?)", TICKETS)
        conn.executemany("INSERT INTO ticket_notes VALUES (?, ?, ?, ?, ?, ?)", NOTES)
        conn.executemany("INSERT INTO invoices VALUES (?, ?, ?, ?, ?, ?)", INVOICES)
        conn.executemany("INSERT INTO agent_access VALUES (?, ?, ?)", ACCESS)
        conn.commit()
    finally:
        conn.close()
    return path


def connect(path: str | Path, *, readonly: bool) -> sqlite3.Connection:
    """Open the support database.

    `readonly=True` returns a handle the engine itself refuses to write
    through. The reader process never holds any other kind.
    """
    path = Path(path)
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

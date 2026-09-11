"""Schema-constrained MCP server for a two-tenant support desk.

The package is started twice with different tool sets: a reader that opens the
database read-only, and a writer that owns every side effect. Both derive the
tenant from the bearer token and never from a tool argument.
"""

__version__ = "0.1.0"

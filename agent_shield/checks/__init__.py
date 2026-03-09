"""Security check sub-package for agent_shield.

This package contains all individual vulnerability check modules. Each module
exposes a single top-level check function that accepts an AgentConfig and returns
a list of Finding objects.

Available check modules:
- prompt_injection: Detects prompt injection patterns and jailbreak templates.
- secret_leakage: Identifies hardcoded secrets, API keys, and tokens.
- permissions: Flags excessive or overly broad tool permission scopes.
- tool_schema: Validates tool/function schemas for insecure patterns.

All check functions are imported here for convenient access via
``agent_shield.checks.<check_name>``.
"""

from __future__ import annotations

# Check function imports will be populated in Phase 3 once the individual
# modules are implemented. The sub-package is importable from Phase 1 onward.

__all__: list[str] = []

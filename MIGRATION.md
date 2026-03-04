# Migration Guide: v0.1 → v0.2

## Overview

v0.2 adds **mandatory execution mediation** to the existing five-gate pipeline.
The core pipeline is preserved — v0.2 is additive, not breaking.

## What Changed

### New Requirement: Key Provider

v0.2 requires an Ed25519 key provider for ticket signing.

```python
from app.key_manager import FileKeyProvider

key_provider = FileKeyProvider("keys/")
key_provider.generate_key_pair("sentry")
```

### Orchestrator Now Issues Tickets

The `SentryOrchestrator` now requires a `key_provider` parameter and
returns an `ExecutionTicket` in the `AuthorizationResult` when approved.

```python
# v0.1
sentry = SentryOrchestrator(identity, inspector, contracts, authority, audit)

# v0.2
sentry = SentryOrchestrator(identity, inspector, contracts, authority, audit, key_provider)
```

### New Component: Tool Proxy

In v0.1, tools could be called directly after authorization.
In v0.2, all tool calls must go through the `ToolProxy`.

```python
from app.tool_proxy import ToolProxy, ReplayStore

proxy = ToolProxy(key_provider=key_provider, replay_store=ReplayStore())
proxy.register_tool("my-tool", my_tool_handler)

# After SENTRY authorization:
result = proxy.execute(ticket=auth_result.ticket, tool_id="my-tool", request=request)
```

### Content Inspector Threshold Change

Email address detection risk level changed from `high` to `medium` to
reduce false positives when email addresses are expected in tool payloads
(e.g., email sender tools).

## Migration Steps

1. Generate Ed25519 key pair
2. Update `SentryOrchestrator` initialization with `key_provider`
3. Set up `ToolProxy` with registered tools
4. Route all tool executions through the proxy
5. Run `tests/test_sentry_v02.py` to verify

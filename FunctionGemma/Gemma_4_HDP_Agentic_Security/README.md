# Gemma 4 + HDP: Securing Agentic Function Calls

This example demonstrates how to integrate the **Human Delegation Provenance (HDP)** protocol with **Gemma 4's native function-calling** to cryptographically verify that every tool invocation was authorized by a human principal before execution.

## The problem

Gemma 4 is purpose-built for agentic workflows. Its native function-calling lets it autonomously call tools and APIs across multi-step plans — on anything from a cloud workstation to a Raspberry Pi running a robot offline.

This creates a gap: when Gemma 4 generates a function call, there is no verifiable record that a human principal authorized that specific action. An injected prompt, a compromised system prompt, or a lateral pivot from another agent can trigger function calls that are indistinguishable from legitimate requests at the tool interface.

HDP closes this gap.

## What HDP does

HDP (IETF draft: `draft-helixar-hdp-agentic-delegation-00`) provides:

- **Ed25519-signed Delegation Tokens (HDTs)** issued by a human principal
- **Scope constraints** — which tools the agent is permitted to call
- **Irreversibility classification** (Class 0–3) — from read-only to physical actuation
- **Pre-execution verification** — the middleware gate runs *before* any tool executes
- **Audit log** — a tamper-evident record of every authorization decision

For Gemma 4 on **edge devices directing physical actuators** (Jetson Nano, Raspberry Pi + robot arm), the HDP-P companion specification adds embodiment constraints, policy attestation, and fleet delegation controls.

## Files

| File | Description |
|---|---|
| `Gemma_4_HDP_Agentic_Security.ipynb` | Full walkthrough notebook — load Gemma 4, issue tokens, gate function calls |
| `hdp_middleware.py` | Drop-in middleware — `HDPMiddleware.gate()` wraps any Gemma 4 tool executor |

## Quick start

```python
from hdp_middleware import HDPDelegationToken, HDPMiddleware, IrreversibilityClass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Human principal issues a delegation token
private_key = Ed25519PrivateKey.generate()
token = HDPDelegationToken.issue(
    principal_id="alice@example.com",
    agent_id="gemma4-agent-01",
    scope=["get_weather", "send_email"],
    max_class=IrreversibilityClass.CLASS_2,
    ttl_seconds=3600,
    private_key=private_key,
)

# Middleware verifies every Gemma 4 function call before execution
middleware = HDPMiddleware(public_key=private_key.public_key())

result = middleware.gate(
    function_call={"name": "send_email", "parameters": {"to": "bob@example.com", ...}},
    token=token,
)

if result.allowed:
    execute_tool(function_call)
```

## Irreversibility classes

| Class | Definition | Authorization |
|---|---|---|
| 0 | Fully reversible — reads, queries | HDT sufficient |
| 1 | Reversible with effort — writes, moves | HDT sufficient |
| 2 | Irreversible — send, delete, publish | HDT + principal confirmation |
| 3 | Irreversible + potentially harmful — physical actuation | Dual-principal required (HDP-P) |

## References

- **IETF draft:** https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/
- **Zenodo DOI:** https://doi.org/10.5281/zenodo.19332023
- **HDP-P (physical AI):** https://doi.org/10.5281/ZENODO.19332440
- **Helixar:** https://helixar.ai

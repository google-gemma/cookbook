"""
HDP (Human Delegation Provenance) middleware for Gemma 4 function calling.

Intercepts Gemma 4 function call outputs and verifies that a valid HDP
Delegation Token (HDT) authorizes the requested action before forwarding
to the tool execution layer.

Reference: draft-helixar-hdp-agentic-delegation-00
           https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/
           DOI: 10.5281/zenodo.19332023

For physical AI agents (robots, edge devices), see HDP-P:
           DOI: 10.5281/ZENODO.19332440
"""

import json
import time
import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable, Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Irreversibility Classes (HDP-P §4.2)
# ---------------------------------------------------------------------------

class IrreversibilityClass(IntEnum):
    """
    Classification of physical action reversibility (HDP-P §4.2).

    For digital-only Gemma 4 deployments, all tool calls are Class 0 or 1.
    For edge/robotics deployments (Jetson Nano, Raspberry Pi + actuators),
    Class 2 and 3 require explicit pre-execution confirmation.
    """
    CLASS_0 = 0  # Fully reversible — read-only, query, observe
    CLASS_1 = 1  # Reversible with effort — write, create, move
    CLASS_2 = 2  # Irreversible under normal conditions — delete, send, publish
    CLASS_3 = 3  # Irreversible and potentially harmful — physical actuation


# Default tool → irreversibility class mapping.
# Deployments should override this for their specific tool set.
DEFAULT_TOOL_CLASS_MAP: dict[str, IrreversibilityClass] = {
    # Class 0 — safe reads
    "get_weather": IrreversibilityClass.CLASS_0,
    "search_web": IrreversibilityClass.CLASS_0,
    "read_file": IrreversibilityClass.CLASS_0,
    "query_database": IrreversibilityClass.CLASS_0,
    # Class 1 — reversible writes
    "write_file": IrreversibilityClass.CLASS_1,
    "create_record": IrreversibilityClass.CLASS_1,
    "move_object": IrreversibilityClass.CLASS_1,
    # Class 2 — irreversible digital actions
    "send_email": IrreversibilityClass.CLASS_2,
    "delete_file": IrreversibilityClass.CLASS_2,
    "publish_post": IrreversibilityClass.CLASS_2,
    "execute_transaction": IrreversibilityClass.CLASS_2,
    # Class 3 — physical actuation (HDP-P scope)
    "actuate_robot_arm": IrreversibilityClass.CLASS_3,
    "command_vehicle": IrreversibilityClass.CLASS_3,
    "dispense_fluid": IrreversibilityClass.CLASS_3,
    "apply_force": IrreversibilityClass.CLASS_3,
}


# ---------------------------------------------------------------------------
# HDP Delegation Token (HDT)
# ---------------------------------------------------------------------------

@dataclass
class HDPDelegationToken:
    """
    Simplified HDT structure derived from draft-helixar-hdp-agentic-delegation-00.

    In production, HDTs are JOSE/JWT tokens signed with Ed25519.
    This implementation provides the core claims structure and verification logic.

    Claims:
        iss  — issuer (human principal identifier)
        sub  — subject (agent being delegated to)
        iat  — issued at (unix timestamp)
        exp  — expiry (unix timestamp)
        scope — list of permitted tool names or wildcard patterns
        max_irreversibility_class — ceiling on action class (0–3)
        delegation_depth — remaining delegation hops permitted
        nonce — replay-attack prevention
    """
    iss: str
    sub: str
    iat: int
    exp: int
    scope: list[str]
    max_irreversibility_class: IrreversibilityClass
    delegation_depth: int = 1
    nonce: str = ""
    _signature: bytes = field(default=b"", repr=False)
    _public_key: Optional[Ed25519PublicKey] = field(default=None, repr=False)

    @classmethod
    def issue(
        cls,
        principal_id: str,
        agent_id: str,
        scope: list[str],
        max_class: IrreversibilityClass,
        ttl_seconds: int = 3600,
        delegation_depth: int = 1,
        private_key: Optional[Ed25519PrivateKey] = None,
    ) -> "HDPDelegationToken":
        """
        Issue a new HDT signed by the human principal's Ed25519 private key.

        Args:
            principal_id: Human principal identifier (e.g. "alice@example.com")
            agent_id: Agent being delegated to (e.g. "gemma4-agent-01")
            scope: List of permitted tool names. Use ["*"] for unrestricted.
            max_class: Maximum IrreversibilityClass this token permits.
            ttl_seconds: Token lifetime in seconds.
            delegation_depth: How many times this token can be re-delegated.
            private_key: Ed25519 private key for signing. Generated if None.
        """
        now = int(time.time())
        nonce = base64.urlsafe_b64encode(
            hashlib.sha256(f"{principal_id}{now}".encode()).digest()[:16]
        ).decode()

        token = cls(
            iss=principal_id,
            sub=agent_id,
            iat=now,
            exp=now + ttl_seconds,
            scope=scope,
            max_irreversibility_class=max_class,
            delegation_depth=delegation_depth,
            nonce=nonce,
        )

        if private_key is None:
            private_key = Ed25519PrivateKey.generate()

        token._public_key = private_key.public_key()
        token._signature = private_key.sign(token._canonical_bytes())
        return token

    def _canonical_bytes(self) -> bytes:
        """Deterministic serialisation for signing/verification."""
        payload = {
            "iss": self.iss,
            "sub": self.sub,
            "iat": self.iat,
            "exp": self.exp,
            "scope": sorted(self.scope),
            "max_irreversibility_class": int(self.max_irreversibility_class),
            "delegation_depth": self.delegation_depth,
            "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        """Verify the token's Ed25519 signature."""
        try:
            public_key.verify(self._signature, self._canonical_bytes())
            return True
        except InvalidSignature:
            return False

    def is_expired(self) -> bool:
        return int(time.time()) > self.exp

    def permits_tool(self, tool_name: str) -> bool:
        """Check whether this token's scope covers the requested tool."""
        if "*" in self.scope:
            return True
        return tool_name in self.scope

    def permits_class(self, action_class: IrreversibilityClass) -> bool:
        return action_class <= self.max_irreversibility_class

    def to_dict(self) -> dict:
        return {
            "iss": self.iss,
            "sub": self.sub,
            "iat": self.iat,
            "exp": self.exp,
            "scope": self.scope,
            "max_irreversibility_class": int(self.max_irreversibility_class),
            "delegation_depth": self.delegation_depth,
            "nonce": self.nonce,
        }


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    allowed: bool
    reason: str
    tool_name: str
    action_class: IrreversibilityClass
    token_iss: Optional[str] = None
    requires_confirmation: bool = False

    def __str__(self) -> str:
        status = "ALLOWED" if self.allowed else "BLOCKED"
        conf = " [CONFIRMATION REQUIRED]" if self.requires_confirmation else ""
        return (
            f"[HDP] {status}{conf} — tool={self.tool_name} "
            f"class={self.action_class.name} reason={self.reason}"
        )


# ---------------------------------------------------------------------------
# HDP Middleware
# ---------------------------------------------------------------------------

class HDPMiddleware:
    """
    HDP verification gate for Gemma 4 function calls.

    Sits between Gemma 4's function-call output and the tool execution layer.
    For each function call Gemma 4 generates, this middleware:

      1. Parses the tool name from the function call.
      2. Looks up its IrreversibilityClass.
      3. Verifies the attached HDT (signature, expiry, scope, class ceiling).
      4. For Class 2 actions, invokes the confirmation callback.
      5. Blocks Class 3 actions unless explicitly pre-authorized with
         dual verification (HDP-P §5.4).
      6. Logs all decisions before forwarding or blocking.

    Usage:
        middleware = HDPMiddleware(
            public_key=principal_public_key,
            tool_class_map=DEFAULT_TOOL_CLASS_MAP,
            confirmation_callback=my_confirmation_fn,
        )

        # Wrap your tool executor:
        result = middleware.gate(
            function_call=gemma_output,   # {"name": "...", "parameters": {...}}
            token=hdp_token,
        )

        if result.allowed:
            output = execute_tool(function_call)
    """

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        tool_class_map: dict[str, IrreversibilityClass] = None,
        confirmation_callback: Optional[Callable[[str, dict], bool]] = None,
        default_class: IrreversibilityClass = IrreversibilityClass.CLASS_1,
        audit_log: Optional[list] = None,
    ):
        """
        Args:
            public_key: Principal's Ed25519 public key for HDT verification.
            tool_class_map: Mapping of tool names to IrreversibilityClass.
                            Defaults to DEFAULT_TOOL_CLASS_MAP.
            confirmation_callback: Called for Class 2 actions. Receives
                                   (tool_name, parameters) and returns bool.
                                   If None, Class 2 actions are blocked.
            default_class: Class assigned to unknown tools. Defaults to CLASS_1.
            audit_log: Optional list to append VerificationResult records to.
        """
        self.public_key = public_key
        self.tool_class_map = tool_class_map or DEFAULT_TOOL_CLASS_MAP
        self.confirmation_callback = confirmation_callback
        self.default_class = default_class
        self.audit_log = audit_log if audit_log is not None else []

    def classify(self, tool_name: str) -> IrreversibilityClass:
        """Return the IrreversibilityClass for a tool name."""
        return self.tool_class_map.get(tool_name, self.default_class)

    def gate(
        self,
        function_call: dict,
        token: HDPDelegationToken,
    ) -> VerificationResult:
        """
        Main verification gate. Call this for every Gemma 4 function call.

        Args:
            function_call: Gemma 4 function call dict:
                           {"name": "tool_name", "parameters": {...}}
            token: HDPDelegationToken issued by the human principal.

        Returns:
            VerificationResult — check .allowed before executing the tool.
        """
        tool_name = function_call.get("name", "")
        parameters = function_call.get("parameters", {})
        action_class = self.classify(tool_name)

        def _block(reason: str) -> VerificationResult:
            result = VerificationResult(
                allowed=False,
                reason=reason,
                tool_name=tool_name,
                action_class=action_class,
                token_iss=token.iss if token else None,
            )
            self.audit_log.append(result)
            print(result)
            return result

        def _allow(reason: str, requires_confirmation: bool = False) -> VerificationResult:
            result = VerificationResult(
                allowed=True,
                reason=reason,
                tool_name=tool_name,
                action_class=action_class,
                token_iss=token.iss,
                requires_confirmation=requires_confirmation,
            )
            self.audit_log.append(result)
            print(result)
            return result

        # ── 1. Token presence ───────────────────────────────────────────────
        if token is None:
            return _block("no HDT present")

        # ── 2. Expiry ───────────────────────────────────────────────────────
        if token.is_expired():
            return _block("HDT expired")

        # ── 3. Signature ────────────────────────────────────────────────────
        if not token.verify(self.public_key):
            return _block("HDT signature invalid")

        # ── 4. Scope ────────────────────────────────────────────────────────
        if not token.permits_tool(tool_name):
            return _block(f"tool '{tool_name}' not in HDT scope")

        # ── 5. Irreversibility class ceiling ────────────────────────────────
        if not token.permits_class(action_class):
            return _block(
                f"action class {action_class.name} exceeds HDT ceiling "
                f"{token.max_irreversibility_class.name}"
            )

        # ── 6. Class 3 — always blocked without explicit dual verification ──
        if action_class == IrreversibilityClass.CLASS_3:
            # In production: implement dual-principal confirmation (HDP-P §5.4)
            return _block(
                "Class 3 physical action requires dual-principal confirmation "
                "(HDP-P §5.4) — not implemented in this middleware instance"
            )

        # ── 7. Class 2 — confirmation callback required ─────────────────────
        if action_class == IrreversibilityClass.CLASS_2:
            if self.confirmation_callback is None:
                return _block(
                    "Class 2 action requires confirmation callback — "
                    "none configured"
                )
            confirmed = self.confirmation_callback(tool_name, parameters)
            if not confirmed:
                return _block("Class 2 action — confirmation denied by principal")
            return _allow("Class 2 confirmed by principal", requires_confirmation=True)

        # ── 8. Class 0 / 1 — allow ─────────────────────────────────────────
        return _allow(f"HDT valid, scope and class verified")

    def gate_batch(
        self,
        function_calls: list[dict],
        token: HDPDelegationToken,
    ) -> list[VerificationResult]:
        """Verify a list of function calls. Returns one result per call."""
        return [self.gate(fc, token) for fc in function_calls]

from __future__ import annotations

from typing import Any

from .human_escalation import review_escalation_decision
from .mcp_registry import MCPRegistry
from .task_tape import TaskTapeStore

TERMINAL_EVENTS = {"mcp_probe_approved", "mcp_probe_rejected", "mcp_probe_dry_run_ready"}


def _target(connector_id: str) -> str:
    return f"mcp://probe/{connector_id.replace('/', '_')}"


# Safety flags returned on every probe denial, so a caller can never read a
# denial as "something ran".
_PROBE_SAFE_FLAGS = {"execute_automatically": False, "server_started": False, "network_requested": False, "tool_called": False, "secret_files_read": False}


def request_mcp_capability_probe(
    registry: MCPRegistry,
    task_tape: TaskTapeStore,
    *,
    connector_id: str,
    tls_observation: dict[str, Any] | None = None,
    actor: str = "MCPProbeHarness",
    purpose: str = "capability_probe",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Create a metadata-only MCP capability probe plan.

    This does not start stdio servers, does not perform HTTPS/SSE requests, does not
    read secret files, and does not call tools. It only records the probe plan and
    approval gate metadata.

    ``tls_observation`` is optional transport-handshake metadata supplied by
    whatever would perform the probe's eventual connection. For a remote
    (non-stdio) connector that declares a ``tls_policy``, the probe is gated
    fail-closed: a missing observation, or one that fails the policy, denies the
    probe. CPOS never opens the socket; it judges the producer-supplied
    observation, never a live handshake.
    """
    connector = next((item for item in registry.load() if item.connector_id == connector_id), None)
    if connector is None:
        return {"ok": False, "error": "connector_not_found", "connector_id": connector_id, "execute_automatically": False}
    if connector.status != "active":
        registry.audit("probe_denied", actor=actor, connector_id=connector_id, decision="connector_not_active", metadata={"purpose": purpose})
        return {"ok": False, "error": "connector_not_active", "connector_id": connector_id, "execute_automatically": False}
    if not dry_run:
        registry.audit("probe_denied", actor=actor, connector_id=connector_id, decision="real_probe_disabled", metadata={"purpose": purpose})
        return {"ok": False, "error": "real_probe_disabled", "connector_id": connector_id, "execute_automatically": False}

    # Fail-closed TLS gate: a remote connector that declares a tls_policy may not
    # be probed without a TLS observation that satisfies that policy. A stdio
    # connector, or a remote connector with no policy, is not gated here.
    tls_summary = None
    if connector.transport != "stdio" and connector.tls_policy is not None:
        if tls_observation is None:
            registry.audit("probe_denied", actor=actor, connector_id=connector_id, decision="tls_observation_required", metadata={"purpose": purpose, "tls_policy_declared": True})
            return {"ok": False, "error": "tls_observation_required", "decision": "tls_denied", "connector_id": connector_id, **_PROBE_SAFE_FLAGS}
        tls_result = registry.verify_tls(connector_id, tls_observation, actor=actor)
        tls_codes = [f.get("code") for f in tls_result.get("findings", []) if isinstance(f, dict) and f.get("code")]
        if not tls_result.get("ok"):
            # Audit the gate denial here too: verify_tls audits the policy
            # decision when it can, but its own early returns do not, so a denial
            # must never be silent in the registry audit log.
            registry.audit("probe_denied", actor=actor, connector_id=connector_id, decision="tls_probe_blocked", metadata={"purpose": purpose, "tls_finding_codes": tls_codes, "tls_decision": tls_result.get("decision")})
            return {"ok": False, "error": "tls_probe_blocked", "decision": tls_result.get("decision", "tls_denied"), "tls_finding_codes": tls_codes, "connector_id": connector_id, **_PROBE_SAFE_FLAGS}
        tls_summary = {"ok": True, "decision": tls_result.get("decision"), "finding_codes": tls_codes}

    human_escalation = review_escalation_decision(
        review_type="mcp_capability_probe",
        summary=f"MCP capability probe dry-run for {connector_id}",
        confidence=0.82,
        risk="medium",
        user_confirmation_required=True,
    )
    payload = {
        "review_type": "mcp_capability_probe",
        "connector_id": connector.connector_id,
        "transport": connector.transport,
        "purpose": purpose,
        "actor": actor,
        "probe_mode": "dry_run_metadata_only",
        "execute_automatically": False,
        "server_started": False,
        "network_requested": False,
        "tool_called": False,
        "secret_files_read": False,
        "declared_allowed_tools": list(connector.allowed_tools),
        "declared_blocked_tools": list(connector.blocked_tools),
        "requires_human_approval": True,
        "human_escalation": human_escalation,
        "tls_verification": tls_summary,
    }
    if connector.transport == "stdio":
        payload["probe_plan"] = ["validate argv shape", "prepare isolated process policy", "list_tools handshake only after approval"]
        payload["command_shape"] = {"argc": len(connector.command), "argv0": connector.command[0] if connector.command else None, "argv_values_stored": False}
    else:
        payload["probe_plan"] = ["validate https endpoint", "prepare timeout policy", "list_tools request only after approval"]
        payload["url_host_only"] = connector.url.split("/", 3)[2] if connector.url and "://" in connector.url else None

    task_id = task_tape.create_task(target=_target(connector.connector_id), action="mcp_capability_probe_request", payload=payload)
    event = task_tape.append_event(
        task_id=task_id,
        event="review_required",
        target=_target(connector.connector_id),
        status="pending_review",
        payload=payload,
    )
    registry.audit("probe_review_created", actor=actor, connector_id=connector_id, decision="approval_required", metadata={"task_id": task_id, "purpose": purpose})
    return {"ok": True, "status": "pending_review", "task_id": task_id, "event": event.to_dict(), **{k: payload[k] for k in ["execute_automatically", "server_started", "network_requested", "tool_called", "secret_files_read"]}}


def pending_mcp_probe_reviews(task_tape: TaskTapeStore) -> list[dict[str, Any]]:
    terminal_task_ids = {event.task_id for event in task_tape.events() if event.event in TERMINAL_EVENTS}
    reviews = []
    for event in task_tape.events():
        if event.event != "review_required" or event.task_id in terminal_task_ids:
            continue
        if event.payload.get("review_type") == "mcp_capability_probe":
            reviews.append(event.to_dict())
    return reviews


def approve_mcp_probe_review(task_tape: TaskTapeStore, task_id: str, *, approver: str = "MCPProbeReviewer", reason: str | None = None, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        return {"ok": False, "error": "confirm_required", "task_id": task_id}
    review = next((row for row in pending_mcp_probe_reviews(task_tape) if row.get("task_id") == task_id), None)
    if review is None:
        return {"ok": False, "error": "pending_mcp_probe_review_not_found", "task_id": task_id}
    payload = dict(review.get("payload") or {})
    payload.update({"approved_by": approver, "approval_reason": reason, "execute_automatically": False, "server_started": False, "network_requested": False, "tool_called": False, "secret_files_read": False})
    event = task_tape.append_event(task_id=task_id, event="mcp_probe_approved", target=review.get("target"), status="approved_dry_run_only", payload=payload)
    return {"ok": True, "task_id": task_id, "event": event.to_dict(), "execute_automatically": False, "server_started": False, "network_requested": False, "tool_called": False}


def reject_mcp_probe_review(task_tape: TaskTapeStore, task_id: str, *, reason: str = "manual_reject") -> dict[str, Any]:
    review = next((row for row in pending_mcp_probe_reviews(task_tape) if row.get("task_id") == task_id), None)
    if review is None:
        return {"ok": False, "error": "pending_mcp_probe_review_not_found", "task_id": task_id}
    payload = dict(review.get("payload") or {})
    payload.update({"rejection_reason": reason, "execute_automatically": False, "server_started": False, "network_requested": False, "tool_called": False, "secret_files_read": False})
    event = task_tape.append_event(task_id=task_id, event="mcp_probe_rejected", target=review.get("target"), status="rejected", payload=payload)
    return {"ok": True, "task_id": task_id, "event": event.to_dict(), "execute_automatically": False, "server_started": False, "network_requested": False, "tool_called": False}

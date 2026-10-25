from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .human_escalation import review_escalation_decision
from .mcp_registry import MCPRegistry
from .task_tape import TaskTapeStore

SECRETISH_KEYS = re.compile(r"(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)", re.I)
TERMINAL_EVENTS = {"mcp_execution_approved", "mcp_execution_rejected", "mcp_execution_dry_run_ready"}


def canonical_args(arguments: dict[str, Any] | None) -> str:
    return json.dumps(arguments or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def argument_fingerprint(arguments: dict[str, Any] | None) -> dict[str, Any]:
    raw = canonical_args(arguments)
    keys = sorted((arguments or {}).keys()) if isinstance(arguments or {}, dict) else []
    return {
        "args_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "args_size_bytes": len(raw.encode("utf-8")),
        "args_top_level_keys": [str(key) for key in keys],
        "args_values_stored": False,
    }


def find_secret_like_argument_paths(obj: Any, prefix: str = "arguments") -> list[str]:
    findings: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}"
            if SECRETISH_KEYS.search(str(key)) and value not in (None, ""):
                findings.append(path)
            findings.extend(find_secret_like_argument_paths(value, path))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            findings.extend(find_secret_like_argument_paths(value, f"{prefix}[{idx}]"))
    return findings


def _target(connector_id: str, tool_name: str) -> str:
    safe_connector = connector_id.replace("/", "_")
    safe_tool = tool_name.replace("/", "_")
    return f"mcp://execution/{safe_connector}/{safe_tool}"


def _tls_finding_codes(result: dict[str, Any]) -> list[str]:
    """Structured finding codes only — never observation-supplied values."""
    return [f.get("code") for f in result.get("findings", []) if isinstance(f, dict) and f.get("code")]


def _check_tls_gate(
    registry: MCPRegistry,
    connector_id: str,
    tls_observation: dict[str, Any] | None,
    *,
    actor: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Evaluate the fail-closed TLS gate for a tool-execution request.

    Returns ``(deny, summary)``:
      - ``deny`` is a response dict when the request must be denied, else None.
      - ``summary`` is a metadata-only verification summary (finding codes + ok,
        no observation values) to attach to the dry-run payload, else None.

    The gate applies ONLY to a remote (non-stdio) connector that declares a
    ``tls_policy``. CPOS does not open the connection; this judges the
    producer-supplied observation against the connector's declared policy.
    """
    connector = registry.get_connector(connector_id)
    if connector is None:
        # evaluate_tool_call already resolved the connector, so this is
        # unexpected; fail closed rather than silently proceed.
        registry.audit("execution_request_denied", actor=actor, connector_id=connector_id, decision="connector_not_found", metadata={"stage": "tls_gate"})
        return ({"ok": False, "error": "connector_not_found", "connector_id": connector_id, "execute_automatically": False, "tool_executed": False}, None)

    if getattr(connector, "transport", None) == "stdio" or connector.tls_policy is None:
        return (None, None)  # no TLS gate applies

    if tls_observation is None:
        registry.audit("execution_request_denied", actor=actor, connector_id=connector_id, decision="tls_observation_required", metadata={"tls_policy_declared": True})
        return (
            {"ok": False, "error": "tls_observation_required", "decision": "tls_denied", "execute_automatically": False, "tool_executed": False},
            None,
        )

    result = registry.verify_tls(connector_id, tls_observation, actor=actor)
    codes = _tls_finding_codes(result)
    if not result.get("ok"):
        # Audit the gate denial at the execution layer uniformly. verify_tls
        # audits the policy decision when it can, but its own early returns (e.g.
        # the connector disappearing between get_connector() and verify_tls()'s
        # reload) do not, so without this a denial could leave only a
        # tool_call_evaluated row. Fail-closed denials must always be auditable.
        registry.audit("execution_request_denied", actor=actor, connector_id=connector_id, decision="tls_execution_blocked", metadata={"tls_finding_codes": codes, "tls_decision": result.get("decision")})
        return (
            {"ok": False, "error": "tls_execution_blocked", "decision": result.get("decision", "tls_denied"), "tls_finding_codes": codes, "execute_automatically": False, "tool_executed": False},
            None,
        )
    return (None, {"ok": True, "decision": result.get("decision"), "finding_codes": codes})


def request_mcp_execution(
    registry: MCPRegistry,
    task_tape: TaskTapeStore,
    *,
    connector_id: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    tls_observation: dict[str, Any] | None = None,
    actor: str = "MCPExecutionAdapter",
    purpose: str = "mcp_execution_request",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Govern MCP tool execution without executing the tool.

    This adapter is intentionally metadata-only: it never launches an MCP server,
    never sends arguments to a connector, and never stores raw argument values.

    ``tls_observation`` is optional transport-handshake metadata supplied by
    whatever actually performed (or would perform) the connection. For a remote
    (non-stdio) connector that declares a ``tls_policy``, the request is gated
    fail-closed on that observation: a missing observation, or one that fails the
    connector's TLS policy, denies the request. CPOS never opens the socket, so
    it judges the producer-supplied observation, never the live handshake.
    """
    if not dry_run:
        registry.audit("execution_request_denied", actor=actor, connector_id=connector_id, decision="real_execution_disabled", metadata={"tool_name": tool_name, "purpose": purpose})
        return {"ok": False, "error": "real_execution_disabled", "execute_automatically": False}

    if arguments is not None and not isinstance(arguments, dict):
        return {"ok": False, "error": "arguments_must_be_object", "execute_automatically": False}

    secret_paths = find_secret_like_argument_paths(arguments or {})
    if secret_paths:
        registry.audit("execution_request_denied", actor=actor, connector_id=connector_id, decision="secret_like_arguments_blocked", metadata={"tool_name": tool_name, "blocked_paths": secret_paths})
        return {"ok": False, "error": "secret_like_arguments_blocked", "blocked_paths": secret_paths, "execute_automatically": False}

    decision = registry.evaluate_tool_call(connector_id, tool_name, actor=actor, purpose=purpose)
    if not decision.get("ok"):
        return {**decision, "execute_automatically": False}
    if decision.get("decision") not in {"allowed", "approval_required"}:
        return {**decision, "ok": False, "error": decision.get("decision"), "execute_automatically": False}

    # Fail-closed TLS gate: a remote connector that declares a tls_policy may not
    # be executed (even as a dry-run) without a TLS observation that satisfies
    # that policy. No policy declared, or a stdio connector, means no gate here;
    # the registry's definition-time check already warns about an absent policy.
    tls_deny, tls_summary = _check_tls_gate(registry, connector_id, tls_observation, actor=actor)
    if tls_deny is not None:
        return tls_deny

    args_meta = argument_fingerprint(arguments)
    human_escalation = review_escalation_decision(
        review_type="mcp_tool_execution",
        summary=f"MCP tool execution dry-run for {connector_id}/{tool_name}",
        confidence=0.82,
        risk="high" if decision.get("requires_human_approval") else "medium",
        user_confirmation_required=bool(decision.get("requires_human_approval")),
    )
    payload = {
        "review_type": "mcp_tool_execution",
        "connector_id": connector_id,
        "tool_name": tool_name,
        "purpose": purpose,
        "actor": actor,
        "execution_mode": "dry_run_metadata_only",
        "execute_automatically": False,
        "tool_executed": False,
        "human_escalation": human_escalation,
        "tls_verification": tls_summary,
        **args_meta,
    }
    task_id = task_tape.create_task(target=_target(connector_id, tool_name), action="mcp_tool_execution_request", payload=payload)

    if decision.get("requires_human_approval"):
        event = task_tape.append_event(
            task_id=task_id,
            event="review_required",
            target=_target(connector_id, tool_name),
            status="pending_review",
            payload=payload,
        )
        registry.audit("execution_review_created", actor=actor, connector_id=connector_id, decision="approval_required", metadata={"task_id": task_id, "tool_name": tool_name, "purpose": purpose})
        return {
            "ok": True,
            "status": "pending_review",
            "task_id": task_id,
            "event": event.to_dict(),
            "decision": decision,
            "execute_automatically": False,
            "tool_executed": False,
            "arguments": args_meta,
        }

    event = task_tape.append_event(
        task_id=task_id,
        event="mcp_execution_dry_run_ready",
        target=_target(connector_id, tool_name),
        status="dry_run_ready",
        payload=payload,
    )
    registry.audit("execution_dry_run_ready", actor=actor, connector_id=connector_id, decision="dry_run_ready", metadata={"task_id": task_id, "tool_name": tool_name, "purpose": purpose})
    return {
        "ok": True,
        "status": "dry_run_ready",
        "task_id": task_id,
        "event": event.to_dict(),
        "decision": decision,
        "execute_automatically": False,
        "tool_executed": False,
        "arguments": args_meta,
    }


def pending_mcp_execution_reviews(task_tape: TaskTapeStore) -> list[dict[str, Any]]:
    terminal_task_ids = {event.task_id for event in task_tape.events() if event.event in TERMINAL_EVENTS}
    reviews = []
    for event in task_tape.events():
        if event.event != "review_required" or event.task_id in terminal_task_ids:
            continue
        if event.payload.get("review_type") == "mcp_tool_execution":
            reviews.append(event.to_dict())
    return reviews


def approve_mcp_execution_review(task_tape: TaskTapeStore, task_id: str, *, approver: str = "MCPExecutionReviewer", reason: str | None = None, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        return {"ok": False, "error": "confirm_required", "task_id": task_id}
    review = next((row for row in pending_mcp_execution_reviews(task_tape) if row.get("task_id") == task_id), None)
    if review is None:
        return {"ok": False, "error": "pending_mcp_execution_review_not_found", "task_id": task_id}
    payload = dict(review.get("payload") or {})
    payload.update({"approved_by": approver, "approval_reason": reason, "execute_automatically": False, "tool_executed": False})
    event = task_tape.append_event(
        task_id=task_id,
        event="mcp_execution_approved",
        target=review.get("target"),
        status="approved_dry_run_only",
        payload=payload,
    )
    return {"ok": True, "task_id": task_id, "event": event.to_dict(), "execute_automatically": False, "tool_executed": False}


def reject_mcp_execution_review(task_tape: TaskTapeStore, task_id: str, *, reason: str = "manual_reject") -> dict[str, Any]:
    review = next((row for row in pending_mcp_execution_reviews(task_tape) if row.get("task_id") == task_id), None)
    if review is None:
        return {"ok": False, "error": "pending_mcp_execution_review_not_found", "task_id": task_id}
    payload = dict(review.get("payload") or {})
    payload.update({"rejection_reason": reason, "execute_automatically": False, "tool_executed": False})
    event = task_tape.append_event(
        task_id=task_id,
        event="mcp_execution_rejected",
        target=review.get("target"),
        status="rejected",
        payload=payload,
    )
    return {"ok": True, "task_id": task_id, "event": event.to_dict(), "execute_automatically": False, "tool_executed": False}

import json
from datetime import datetime, timedelta, timezone

from cpos.mcp_execution import (
    approve_mcp_execution_review,
    pending_mcp_execution_reviews,
    reject_mcp_execution_review,
    request_mcp_execution,
)
from cpos.mcp_registry import MCPRegistry
from cpos.task_tape import TaskTapeStore

_PIN = "ab" * 32  # 64 hex chars


def _future_iso(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def tls_definition(tmp_path, *, approval=False):
    return {
        "connector_id": "mcp://secure/search",
        "name": "Secure MCP",
        "transport": "https",
        "url": "https://mcp.example.test/docs",
        "allowed_tools": ["docs.search"],
        "blocked_tools": ["docs.write"],
        "requires_human_approval": approval,
        "env_secret_files": {"DOCS_TOKEN_FILE": str(tmp_path / "docs_token_file")},
        "tls_policy": {
            "min_version": "TLSv1.2",
            "pinned_spki_sha256": [_PIN],
            "forbidden_issuers": ["Compromised CA"],
            "require_hostname_match": True,
            "forbid_key_logging": True,
        },
    }


def good_observation():
    return {
        "negotiated_version": "TLSv1.3",
        "leaf_spki_sha256": _PIN,
        "chain_issuers": [{"O": "Trusted CA", "CN": "Trusted Root"}],
        "leaf_not_after": _future_iso(),
        "hostname_matched": True,
        "keylog_disabled": True,
        "observed_host": "mcp.example.test",
    }


def setup_tls_registry_and_tape(tmp_path, *, approval=False):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl", tmp_path / "mcp_reviews.jsonl")
    assert registry.register(tls_definition(tmp_path, approval=approval), confirm=True)["ok"] is True
    tape = TaskTapeStore(tmp_path / "task_runs.jsonl", tmp_path / "task_checkpoints.jsonl")
    return registry, tape


def definition(tmp_path, *, approval=True):
    return {
        "connector_id": "mcp://docs/search",
        "name": "Docs Search MCP",
        "transport": "https",
        "url": "https://mcp.example.test/docs",
        "allowed_tools": ["docs.search"],
        "blocked_tools": ["docs.write"],
        "requires_human_approval": approval,
        "env_secret_files": {"DOCS_TOKEN_FILE": str(tmp_path / "docs_token_file")},
    }


def setup_registry_and_tape(tmp_path, *, approval=True):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl", tmp_path / "mcp_reviews.jsonl")
    assert registry.register(definition(tmp_path, approval=approval), confirm=True)["ok"] is True
    tape = TaskTapeStore(tmp_path / "task_runs.jsonl", tmp_path / "task_checkpoints.jsonl")
    return registry, tape


def test_mcp_execution_dry_run_creates_review_and_stores_no_args_values(tmp_path):
    registry, tape = setup_registry_and_tape(tmp_path, approval=True)

    result = request_mcp_execution(
        registry,
        tape,
        connector_id="mcp://docs/search",
        tool_name="docs.search",
        arguments={"query": "hello", "limit": 5},
        actor="UnitTest",
        purpose="unit",
    )

    assert result["ok"] is True
    assert result["status"] == "pending_review"
    assert result["execute_automatically"] is False
    assert result["tool_executed"] is False
    assert result["arguments"]["args_values_stored"] is False
    reviews = pending_mcp_execution_reviews(tape)
    assert len(reviews) == 1
    payload = reviews[0]["payload"]
    assert payload["review_type"] == "mcp_tool_execution"
    assert payload["args_top_level_keys"] == ["limit", "query"]
    assert "hello" not in str(payload)


def test_mcp_execution_rejects_secret_like_arguments_and_blocked_tools(tmp_path):
    registry, tape = setup_registry_and_tape(tmp_path, approval=True)

    secret_arg = request_mcp_execution(
        registry,
        tape,
        connector_id="mcp://docs/search",
        tool_name="docs.search",
        arguments={"api_key": "nope"},
    )
    blocked_tool = request_mcp_execution(
        registry,
        tape,
        connector_id="mcp://docs/search",
        tool_name="docs.write",
        arguments={"title": "x"},
    )

    assert secret_arg["ok"] is False
    assert secret_arg["error"] == "secret_like_arguments_blocked"
    assert blocked_tool["ok"] is False
    assert blocked_tool["error"] == "tool_blocked"
    assert pending_mcp_execution_reviews(tape) == []


def test_mcp_execution_approve_and_reject_are_metadata_only(tmp_path):
    registry, tape = setup_registry_and_tape(tmp_path, approval=True)
    result = request_mcp_execution(registry, tape, connector_id="mcp://docs/search", tool_name="docs.search", arguments={"query": "x"})
    task_id = result["task_id"]

    missing_confirm = approve_mcp_execution_review(tape, task_id, confirm=False)
    assert missing_confirm["error"] == "confirm_required"

    approved = approve_mcp_execution_review(tape, task_id, approver="Reviewer", reason="ok", confirm=True)
    assert approved["ok"] is True
    assert approved["execute_automatically"] is False
    assert approved["tool_executed"] is False
    assert pending_mcp_execution_reviews(tape) == []

    second = request_mcp_execution(registry, tape, connector_id="mcp://docs/search", tool_name="docs.search", arguments={"query": "y"})
    rejected = reject_mcp_execution_review(tape, second["task_id"], reason="no")
    assert rejected["ok"] is True
    assert rejected["tool_executed"] is False


def test_mcp_execution_without_approval_still_dry_run_only(tmp_path):
    registry, tape = setup_registry_and_tape(tmp_path, approval=False)

    result = request_mcp_execution(registry, tape, connector_id="mcp://docs/search", tool_name="docs.search", arguments={"query": "x"})

    assert result["ok"] is True
    assert result["status"] == "dry_run_ready"
    assert result["execute_automatically"] is False
    assert result["tool_executed"] is False
    assert pending_mcp_execution_reviews(tape) == []


def test_mcp_real_execution_is_disabled(tmp_path):
    registry, tape = setup_registry_and_tape(tmp_path, approval=False)

    result = request_mcp_execution(registry, tape, connector_id="mcp://docs/search", tool_name="docs.search", dry_run=False)

    assert result["ok"] is False
    assert result["error"] == "real_execution_disabled"
    assert result["execute_automatically"] is False


# --- CPOS②: fail-closed TLS execution gate ---------------------------------


def test_tls_policy_connector_denies_without_observation(tmp_path):
    # A remote connector that declares a tls_policy cannot be executed (even as a
    # dry-run) without a TLS observation. Fail-closed.
    registry, tape = setup_tls_registry_and_tape(tmp_path, approval=False)

    result = request_mcp_execution(registry, tape, connector_id="mcp://secure/search", tool_name="docs.search", arguments={"query": "x"})

    assert result["ok"] is False
    assert result["error"] == "tls_observation_required"
    assert result["decision"] == "tls_denied"
    assert result["execute_automatically"] is False
    assert result["tool_executed"] is False
    # Nothing is scheduled when the gate denies.
    assert pending_mcp_execution_reviews(tape) == []


def test_tls_policy_connector_denies_on_failing_observation(tmp_path):
    registry, tape = setup_tls_registry_and_tape(tmp_path, approval=False)
    bad = good_observation()
    bad["leaf_spki_sha256"] = "cd" * 32  # not the pinned SPKI -> mismatch

    result = request_mcp_execution(
        registry, tape, connector_id="mcp://secure/search", tool_name="docs.search",
        arguments={"query": "x"}, tls_observation=bad,
    )

    assert result["ok"] is False
    assert result["error"] == "tls_execution_blocked"
    assert result["decision"] == "tls_denied"
    assert "tls_spki_mismatch" in result["tls_finding_codes"]
    assert result["execute_automatically"] is False
    # The observed (wrong) SPKI value must not leak into the response.
    assert "cd" * 32 not in str(result)
    assert pending_mcp_execution_reviews(tape) == []


def test_tls_policy_connector_proceeds_on_passing_observation(tmp_path):
    registry, tape = setup_tls_registry_and_tape(tmp_path, approval=False)

    result = request_mcp_execution(
        registry, tape, connector_id="mcp://secure/search", tool_name="docs.search",
        arguments={"query": "x"}, tls_observation=good_observation(),
    )

    assert result["ok"] is True
    assert result["status"] == "dry_run_ready"
    assert result["execute_automatically"] is False
    assert result["tool_executed"] is False
    # The dry-run payload records the TLS verification summary (codes + ok only,
    # never observation values such as the host or SPKI).
    event = result["event"]
    tls = event["payload"]["tls_verification"]
    assert tls["ok"] is True
    assert tls["decision"] == "tls_allowed"
    assert "mcp.example.test" not in str(event["payload"])
    assert _PIN not in str(event["payload"])


def test_tls_policy_connector_approval_path_still_gated(tmp_path):
    # The gate runs before the human-approval branch too.
    registry, tape = setup_tls_registry_and_tape(tmp_path, approval=True)

    denied = request_mcp_execution(registry, tape, connector_id="mcp://secure/search", tool_name="docs.search", arguments={"query": "x"})
    assert denied["ok"] is False
    assert denied["error"] == "tls_observation_required"
    assert pending_mcp_execution_reviews(tape) == []

    approved = request_mcp_execution(
        registry, tape, connector_id="mcp://secure/search", tool_name="docs.search",
        arguments={"query": "x"}, tls_observation=good_observation(),
    )
    assert approved["ok"] is True
    assert approved["status"] == "pending_review"
    reviews = pending_mcp_execution_reviews(tape)
    assert len(reviews) == 1
    assert reviews[0]["payload"]["tls_verification"]["ok"] is True


def _audit_events(registry):
    path = registry.audit_path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_tls_gate_denial_is_audited(tmp_path):
    registry, tape = setup_tls_registry_and_tape(tmp_path, approval=False)
    bad = good_observation()
    bad["leaf_spki_sha256"] = "cd" * 32  # SPKI mismatch -> deny

    request_mcp_execution(
        registry, tape, connector_id="mcp://secure/search", tool_name="docs.search",
        arguments={"query": "x"}, tls_observation=bad,
    )

    events = _audit_events(registry)
    assert any(e["event"] == "execution_request_denied" and e["decision"] == "tls_execution_blocked" for e in events)


def test_tls_gate_audits_denial_even_if_verify_cannot(tmp_path, monkeypatch):
    # Rare TOCTOU: the connector disappears between get_connector() and
    # verify_tls()'s own registry reload, so verify_tls returns
    # connector_not_found WITHOUT auditing. The gate must still record the
    # fail-closed denial so it is never silent in the audit log.
    registry, tape = setup_tls_registry_and_tape(tmp_path, approval=False)
    monkeypatch.setattr(
        registry, "verify_tls",
        lambda *a, **k: {"ok": False, "decision": "tls_denied", "error": "connector_not_found", "findings": []},
    )

    result = request_mcp_execution(
        registry, tape, connector_id="mcp://secure/search", tool_name="docs.search",
        arguments={"query": "x"}, tls_observation=good_observation(),
    )

    assert result["ok"] is False
    assert result["error"] == "tls_execution_blocked"
    events = _audit_events(registry)
    assert any(e["event"] == "execution_request_denied" and e["decision"] == "tls_execution_blocked" for e in events)
    assert pending_mcp_execution_reviews(tape) == []


def test_no_tls_policy_connector_needs_no_observation(tmp_path):
    # Backward-compat: a remote connector WITHOUT a tls_policy is not gated here
    # (its absence is only a definition-time warning), so execution proceeds
    # without any observation.
    registry, tape = setup_registry_and_tape(tmp_path, approval=False)

    result = request_mcp_execution(registry, tape, connector_id="mcp://docs/search", tool_name="docs.search", arguments={"query": "x"})

    assert result["ok"] is True
    assert result["status"] == "dry_run_ready"
    assert result["event"]["payload"]["tls_verification"] is None

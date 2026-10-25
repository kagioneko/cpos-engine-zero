import json
from datetime import datetime, timedelta, timezone

from cpos.mcp_probe import request_mcp_capability_probe, pending_mcp_probe_reviews, approve_mcp_probe_review, reject_mcp_probe_review
from cpos.mcp_registry import MCPRegistry
from cpos.task_tape import TaskTapeStore

_PIN = "ab" * 32


def _future_iso(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def setup_tls(tmp_path):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "audit.jsonl", tmp_path / "reviews.jsonl")
    assert registry.register(
        {
            "connector_id": "mcp://secure/probe",
            "name": "Secure MCP",
            "transport": "https",
            "url": "https://mcp.example.test/docs",
            "allowed_tools": ["docs.search"],
            "requires_human_approval": True,
            "env_secret_files": {"DOCS_TOKEN_FILE": str(tmp_path / "token_file")},
            "tls_policy": {
                "min_version": "TLSv1.2",
                "pinned_spki_sha256": [_PIN],
                "require_hostname_match": True,
                "forbid_key_logging": True,
            },
        },
        confirm=True,
    )["ok"] is True
    tape = TaskTapeStore(tmp_path / "tasks.jsonl", tmp_path / "checkpoints.jsonl")
    return registry, tape, "mcp://secure/probe"


def good_observation():
    return {
        "negotiated_version": "TLSv1.3",
        "leaf_spki_sha256": _PIN,
        "leaf_not_after": _future_iso(),
        "hostname_matched": True,
        "keylog_disabled": True,
        "observed_host": "mcp.example.test",
    }


def _audit_events(registry):
    path = registry.audit_path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def setup(tmp_path, *, transport="https"):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "audit.jsonl", tmp_path / "reviews.jsonl")
    data = {
        "connector_id": f"mcp://docs/{transport}",
        "name": "Docs MCP",
        "transport": transport,
        "allowed_tools": ["docs.search"],
        "requires_human_approval": True,
        "env_secret_files": {"DOCS_TOKEN_FILE": str(tmp_path / "token_file")},
    }
    if transport == "stdio":
        data["command"] = ["python", "-m", "safe_mcp"]
    else:
        data["url"] = "https://mcp.example.test/docs"
    assert registry.register(data, confirm=True)["ok"] is True
    tape = TaskTapeStore(tmp_path / "tasks.jsonl", tmp_path / "checkpoints.jsonl")
    return registry, tape, data["connector_id"]


def test_mcp_capability_probe_creates_metadata_only_review(tmp_path):
    registry, tape, connector_id = setup(tmp_path)
    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id)
    assert result["ok"] is True
    assert result["server_started"] is False
    assert result["network_requested"] is False
    assert result["tool_called"] is False
    assert result["secret_files_read"] is False
    review = pending_mcp_probe_reviews(tape)[0]
    payload = review["payload"]
    assert payload["review_type"] == "mcp_capability_probe"
    assert payload["probe_mode"] == "dry_run_metadata_only"
    assert payload["url_host_only"] == "mcp.example.test"
    assert "list_tools request only after approval" in payload["probe_plan"]


def test_mcp_stdio_probe_stores_command_shape_not_full_execution(tmp_path):
    registry, tape, connector_id = setup(tmp_path, transport="stdio")
    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id)
    assert result["ok"] is True
    payload = pending_mcp_probe_reviews(tape)[0]["payload"]
    assert payload["transport"] == "stdio"
    assert payload["command_shape"]["argv0"] == "python"
    assert payload["command_shape"]["argv_values_stored"] is False
    assert payload["server_started"] is False


def test_mcp_probe_approve_reject_are_dry_run_only(tmp_path):
    registry, tape, connector_id = setup(tmp_path)
    first = request_mcp_capability_probe(registry, tape, connector_id=connector_id)
    missing = approve_mcp_probe_review(tape, first["task_id"], confirm=False)
    assert missing["error"] == "confirm_required"
    approved = approve_mcp_probe_review(tape, first["task_id"], confirm=True)
    assert approved["ok"] is True
    assert approved["server_started"] is False
    assert pending_mcp_probe_reviews(tape) == []

    second = request_mcp_capability_probe(registry, tape, connector_id=connector_id)
    rejected = reject_mcp_probe_review(tape, second["task_id"], reason="no")
    assert rejected["ok"] is True
    assert rejected["tool_called"] is False


def test_mcp_probe_rejects_real_probe(tmp_path):
    registry, tape, connector_id = setup(tmp_path)
    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id, dry_run=False)
    assert result["ok"] is False
    assert result["error"] == "real_probe_disabled"


# --- CPOS②: fail-closed TLS probe gate -------------------------------------


def test_probe_tls_policy_denies_without_observation(tmp_path):
    registry, tape, connector_id = setup_tls(tmp_path)

    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id)

    assert result["ok"] is False
    assert result["error"] == "tls_observation_required"
    assert result["decision"] == "tls_denied"
    assert result["server_started"] is False
    assert result["network_requested"] is False
    assert result["tool_called"] is False
    assert pending_mcp_probe_reviews(tape) == []
    # Denial is audited.
    assert any(e["event"] == "probe_denied" and e["decision"] == "tls_observation_required" for e in _audit_events(registry))


def test_probe_tls_policy_denies_on_failing_observation(tmp_path):
    registry, tape, connector_id = setup_tls(tmp_path)
    bad = good_observation()
    bad["leaf_spki_sha256"] = "cd" * 32  # SPKI mismatch

    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id, tls_observation=bad)

    assert result["ok"] is False
    assert result["error"] == "tls_probe_blocked"
    assert "tls_spki_mismatch" in result["tls_finding_codes"]
    assert result["server_started"] is False
    assert "cd" * 32 not in str(result)
    assert pending_mcp_probe_reviews(tape) == []
    assert any(e["event"] == "probe_denied" and e["decision"] == "tls_probe_blocked" for e in _audit_events(registry))


def test_probe_tls_gate_audits_denial_even_if_verify_cannot(tmp_path, monkeypatch):
    # Rare TOCTOU: the connector disappears between the probe's load and
    # verify_tls()'s own reload, so verify_tls returns connector_not_found
    # WITHOUT auditing. The gate must still deny fail-closed, audit it, keep all
    # safety flags False, and create no Task Tape task/review.
    registry, tape, connector_id = setup_tls(tmp_path)
    monkeypatch.setattr(
        registry, "verify_tls",
        lambda *a, **k: {"ok": False, "decision": "tls_denied", "error": "connector_not_found", "findings": []},
    )

    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id, tls_observation=good_observation())

    assert result["ok"] is False
    assert result["error"] == "tls_probe_blocked"
    for flag in ("execute_automatically", "server_started", "network_requested", "tool_called", "secret_files_read"):
        assert result[flag] is False
    assert pending_mcp_probe_reviews(tape) == []
    assert list(tape.events()) == []
    assert any(e["event"] == "probe_denied" and e["decision"] == "tls_probe_blocked" for e in _audit_events(registry))


def test_probe_tls_policy_proceeds_on_passing_observation(tmp_path):
    registry, tape, connector_id = setup_tls(tmp_path)

    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id, tls_observation=good_observation())

    assert result["ok"] is True
    assert result["status"] == "pending_review"
    payload = pending_mcp_probe_reviews(tape)[0]["payload"]
    assert payload["tls_verification"]["ok"] is True
    assert payload["tls_verification"]["decision"] == "tls_allowed"
    # Observation values must not leak into the payload.
    assert _PIN not in str(payload)
    assert "mcp.example.test" not in str(payload["tls_verification"])


def test_probe_stdio_connector_is_not_tls_gated(tmp_path):
    # Backward-compat: stdio has no TLS, so no observation is required and the
    # probe records tls_verification = None.
    registry, tape, connector_id = setup(tmp_path, transport="stdio")

    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id)

    assert result["ok"] is True
    assert pending_mcp_probe_reviews(tape)[0]["payload"]["tls_verification"] is None


def test_probe_remote_without_policy_needs_no_observation(tmp_path):
    # A remote connector with no tls_policy is not gated (absent policy is a
    # definition-time warning only).
    registry, tape, connector_id = setup(tmp_path)

    result = request_mcp_capability_probe(registry, tape, connector_id=connector_id)

    assert result["ok"] is True
    assert pending_mcp_probe_reviews(tape)[0]["payload"]["tls_verification"] is None

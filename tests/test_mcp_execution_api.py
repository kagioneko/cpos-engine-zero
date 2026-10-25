from datetime import datetime, timedelta, timezone

from agents.main_agent import MainAgent
from cpos.mcp_registry import MCPRegistry
from cpos.task_tape import TaskTapeStore
import server

_PIN = "ab" * 32


def _future_iso(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def configure_agent(tmp_path):
    test_agent = MainAgent()
    test_agent.project_root = str(tmp_path)
    test_agent.task_tape_path = str(tmp_path / "tapes" / "task_runs.jsonl")
    test_agent.task_checkpoint_path = str(tmp_path / "tapes" / "task_checkpoints.jsonl")
    test_agent.task_tape = TaskTapeStore(test_agent.task_tape_path, test_agent.task_checkpoint_path)
    server.agent = test_agent
    return test_agent


def register_connector(tmp_path):
    registry = MCPRegistry(tmp_path / "cpos" / "mcp_connectors.json", tmp_path / "cpos" / "mcp_audit.jsonl", tmp_path / "cpos" / "mcp_reviews.jsonl")
    result = registry.register(
        {
            "connector_id": "mcp://docs/search",
            "name": "Docs Search MCP",
            "transport": "https",
            "url": "https://mcp.example.test/docs",
            "allowed_tools": ["docs.search"],
            "requires_human_approval": True,
            "env_secret_files": {"DOCS_TOKEN_FILE": str(tmp_path / "docs_token_file")},
        },
        confirm=True,
    )
    assert result["ok"] is True


def test_mcp_execution_api_dry_run_review_approve_reject(tmp_path):
    configure_agent(tmp_path)
    register_connector(tmp_path)
    client = server.app.test_client()

    dry = client.post(
        "/mcp/executions/dry-run",
        json={"connector_id": "mcp://docs/search", "tool_name": "docs.search", "arguments": {"query": "hello"}},
    )
    assert dry.status_code == 200
    payload = dry.get_json()
    assert payload["status"] == "pending_review"
    assert payload["tool_executed"] is False
    task_id = payload["task_id"]

    listed = client.get("/mcp/executions")
    assert listed.status_code == 200
    assert listed.get_json()["count"] == 1

    missing_confirm = client.post(f"/mcp/executions/{task_id}/approve", json={})
    assert missing_confirm.status_code == 400
    assert missing_confirm.get_json()["error"] == "confirm_required"

    approved = client.post(f"/mcp/executions/{task_id}/approve", json={"confirm": True, "reason": "ok"})
    assert approved.status_code == 200
    assert approved.get_json()["tool_executed"] is False
    assert client.get("/mcp/executions").get_json()["count"] == 0

    second = client.post(
        "/mcp/executions/dry-run",
        json={"connector_id": "mcp://docs/search", "tool_name": "docs.search", "arguments": {"query": "bye"}},
    )
    second_task_id = second.get_json()["task_id"]
    rejected = client.post(f"/mcp/executions/{second_task_id}/reject", json={"reason": "no"})
    assert rejected.status_code == 200
    assert rejected.get_json()["tool_executed"] is False


def test_mcp_execution_api_rejects_real_execution_and_secret_args(tmp_path):
    configure_agent(tmp_path)
    register_connector(tmp_path)
    client = server.app.test_client()

    real = client.post(
        "/mcp/executions/dry-run",
        json={"connector_id": "mcp://docs/search", "tool_name": "docs.search", "dry_run": False},
    )
    secret = client.post(
        "/mcp/executions/dry-run",
        json={"connector_id": "mcp://docs/search", "tool_name": "docs.search", "arguments": {"token": "no"}},
    )

    assert real.status_code == 400
    assert real.get_json()["error"] == "real_execution_disabled"
    assert secret.status_code == 400
    assert secret.get_json()["error"] == "secret_like_arguments_blocked"


def register_tls_connector(tmp_path):
    registry = MCPRegistry(tmp_path / "cpos" / "mcp_connectors.json", tmp_path / "cpos" / "mcp_audit.jsonl", tmp_path / "cpos" / "mcp_reviews.jsonl")
    result = registry.register(
        {
            "connector_id": "mcp://secure/search",
            "name": "Secure MCP",
            "transport": "https",
            "url": "https://mcp.example.test/docs",
            "allowed_tools": ["docs.search"],
            "requires_human_approval": True,
            "env_secret_files": {"DOCS_TOKEN_FILE": str(tmp_path / "docs_token_file")},
            "tls_policy": {
                "min_version": "TLSv1.2",
                "pinned_spki_sha256": [_PIN],
                "require_hostname_match": True,
                "forbid_key_logging": True,
            },
        },
        confirm=True,
    )
    assert result["ok"] is True


def test_mcp_execution_api_tls_gate_denies_without_observation(tmp_path):
    configure_agent(tmp_path)
    register_tls_connector(tmp_path)
    client = server.app.test_client()

    denied = client.post(
        "/mcp/executions/dry-run",
        json={"connector_id": "mcp://secure/search", "tool_name": "docs.search", "arguments": {"query": "x"}},
    )
    assert denied.status_code == 400
    assert denied.get_json()["error"] == "tls_observation_required"
    assert client.get("/mcp/executions").get_json()["count"] == 0


def test_mcp_execution_api_tls_gate_accepts_passing_observation(tmp_path):
    configure_agent(tmp_path)
    register_tls_connector(tmp_path)
    client = server.app.test_client()

    ok = client.post(
        "/mcp/executions/dry-run",
        json={
            "connector_id": "mcp://secure/search",
            "tool_name": "docs.search",
            "arguments": {"query": "x"},
            "tls_observation": {
                "negotiated_version": "TLSv1.3",
                "leaf_spki_sha256": _PIN,
                "leaf_not_after": _future_iso(),
                "hostname_matched": True,
                "keylog_disabled": True,
                "observed_host": "mcp.example.test",
            },
        },
    )
    assert ok.status_code == 200
    body = ok.get_json()
    assert body["status"] == "pending_review"
    assert body["event"]["payload"]["tls_verification"]["ok"] is True
    # Observation values must not be echoed back in the response.
    assert "mcp.example.test" not in str(body["event"]["payload"])
    assert _PIN not in str(body["event"]["payload"])


def test_mcp_execution_api_scope_mapping():
    with server.app.test_request_context("/mcp/executions", method="GET"):
        assert server.required_scope_for_request() == "read:mcp"
    with server.app.test_request_context("/mcp/executions/dry-run", method="POST"):
        assert server.required_scope_for_request() == "write:mcp"

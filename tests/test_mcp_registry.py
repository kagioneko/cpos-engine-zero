import json
from pathlib import Path

from cpos.hash_chain import verify_hash_chain
from cpos.mcp_registry import MCPRegistry, check_connector_definition


def valid_definition(secret_file):
    return {
        "connector_id": "mcp://github/read-only",
        "name": "GitHub Read Only MCP",
        "transport": "https",
        "url": "https://mcp.example.test/github",
        "allowed_tools": ["repo.search", "issues.read"],
        "blocked_tools": ["repo.write"],
        "sensitivity_level": "internal",
        "requires_human_approval": True,
        "env_secret_files": {"GITHUB_TOKEN_FILE": str(secret_file)},
        "tls_policy": {
            "min_version": "TLSv1.2",
            "pinned_spki_sha256": ["a" * 64],
            "require_hostname_match": True,
            "forbid_key_logging": True,
        },
        "metadata": {"owner": "security"},
    }


def test_mcp_definition_check_passes_safe_text_only_definition(tmp_path):
    secret_file = tmp_path / "github_token_file"
    data = valid_definition(secret_file)

    result = check_connector_definition(data)

    assert result["ok"] is True
    assert result["findings"] == []
    assert result["connector"]["url"] == "https://mcp.example.test/github"
    assert result["connector"]["env_secret_files"] == {"GITHUB_TOKEN_FILE": str(secret_file)}


def test_mcp_definition_check_rejects_http_raw_secrets_and_unapproved_dangerous_tools():
    data = {
        "connector_id": "bad",
        "name": "Bad MCP",
        "transport": "https",
        "url": "http://mcp.example.test/bad",
        "allowed_tools": ["shell.exec"],
        "requires_human_approval": False,
        "api_key": "not-allowed-here",
        "env": {"TOKEN": "also-not-allowed"},
    }

    result = check_connector_definition(data)

    assert result["ok"] is False
    codes = {finding["code"] for finding in result["findings"]}
    assert "https_required" in codes
    assert "raw_env_or_secrets_blocked" in codes
    assert "raw_secret_like_value" in codes
    assert "dangerous_tool_requires_approval" in codes


def test_mcp_definition_check_blocks_credentials_embedded_in_url(tmp_path):
    # user:pass@host is https and has a host, so it passes https_required and
    # url_host_required; it must be rejected on its own, or the credential lands
    # in the registry JSONL / hash-chained audit log / git (userinfo leak class).
    secret_file = tmp_path / "github_token_file"
    data = valid_definition(secret_file)
    data["url"] = "https://svcuser:dummycredential1234567890@mcp.example.test/github"

    result = check_connector_definition(data)

    codes = {finding["code"] for finding in result["findings"]}
    assert result["ok"] is False
    assert "url_userinfo_blocked" in codes
    assert "https_required" not in codes  # scheme is https; only the userinfo is wrong


def test_mcp_definition_check_allows_at_sign_outside_authority(tmp_path):
    # '@' in the path is not userinfo and must not trip url_userinfo_blocked.
    secret_file = tmp_path / "github_token_file"
    data = valid_definition(secret_file)
    data["url"] = "https://mcp.example.test/github@v2"

    result = check_connector_definition(data)

    codes = {finding["code"] for finding in result["findings"]}
    assert "url_userinfo_blocked" not in codes
    assert result["ok"] is True


def test_mcp_definition_check_requires_a_real_host(tmp_path):
    # netloc ":443" is non-empty but has no hostname; it must still be rejected.
    secret_file = tmp_path / "github_token_file"
    data = valid_definition(secret_file)
    data["url"] = "https://:443/github"

    result = check_connector_definition(data)

    codes = {finding["code"] for finding in result["findings"]}
    assert result["ok"] is False
    assert "url_host_required" in codes


def test_mcp_definition_check_blocks_bare_userinfo(tmp_path):
    # Even empty userinfo ('https://@host') is credential syntax in the URL.
    secret_file = tmp_path / "github_token_file"
    data = valid_definition(secret_file)
    data["url"] = "https://@mcp.example.test/github"

    result = check_connector_definition(data)

    codes = {finding["code"] for finding in result["findings"]}
    assert result["ok"] is False
    assert "url_userinfo_blocked" in codes


def test_mcp_definition_check_warns_on_secret_in_query(tmp_path):
    # A credential in the query string is the same leak class as userinfo, but
    # the name match is heuristic, so it is a (non-blocking) warning to review.
    secret_file = tmp_path / "github_token_file"
    data = valid_definition(secret_file)
    data["url"] = "https://mcp.example.test/github?access_token=dummycredential1234567890"

    result = check_connector_definition(data)

    review = [f for f in result["findings"] if f["code"] == "url_query_secret_review"]
    assert review and review[0]["severity"] == "warning"
    assert result["ok"] is True  # a warning alone does not block registration


def test_mcp_definition_check_allows_benign_and_blank_query(tmp_path):
    # Benign params - including compounds that merely CONTAIN a secret word
    # (max_tokens, tokenizer) - and a secret-like param with a blank value, are
    # all fine and must not raise url_query_secret_review.
    secret_file = tmp_path / "github_token_file"
    for url in (
        "https://mcp.example.test/github?page=2&per_page=50",
        "https://mcp.example.test/mcp?max_tokens=100&tokenizer=cl100k_base",
        "https://mcp.example.test/github?token=",
    ):
        data = valid_definition(secret_file)
        data["url"] = url
        result = check_connector_definition(data)
        codes = {finding["code"] for finding in result["findings"]}
        assert "url_query_secret_review" not in codes, url
        assert result["ok"] is True, url


def test_mcp_registry_requires_check_then_confirm_before_register(tmp_path):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl")
    data = valid_definition(tmp_path / "token_file")

    dry = registry.register(data, actor="UnitTest", confirm=False)
    assert dry["ok"] is False
    assert dry["error"] == "confirm_required_after_security_check"
    assert registry.load() == []

    registered = registry.register(data, actor="UnitTest", confirm=True)
    assert registered["ok"] is True
    connectors = registry.load()
    assert len(connectors) == 1
    assert connectors[0].connector_id == "mcp://github/read-only"
    assert verify_hash_chain(tmp_path / "mcp_audit.jsonl")["ok"] is True


def test_mcp_tool_evaluation_is_governed_and_audited(tmp_path):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl")
    registry.register(valid_definition(tmp_path / "token_file"), confirm=True)

    allowed_but_approval = registry.evaluate_tool_call("mcp://github/read-only", "repo.search", purpose="unit")
    blocked = registry.evaluate_tool_call("mcp://github/read-only", "repo.write", purpose="unit")
    missing = registry.evaluate_tool_call("mcp://github/read-only", "admin.delete", purpose="unit")

    assert allowed_but_approval["allowed"] is False
    assert allowed_but_approval["requires_human_approval"] is True
    assert allowed_but_approval["decision"] == "approval_required"
    assert blocked["decision"] == "tool_blocked"
    assert missing["decision"] == "tool_not_allowlisted"
    assert verify_hash_chain(tmp_path / "mcp_audit.jsonl")["ok"] is True


def test_mcp_cli_text_definition_check_and_register(tmp_path, capsys):
    from cpos.mcp_cli import main

    definition = tmp_path / "mcp.json"
    definition.write_text(json.dumps(valid_definition(tmp_path / "token_file")), encoding="utf-8")
    registry_path = tmp_path / "connectors.json"
    audit_path = tmp_path / "audit.jsonl"

    main(["--registry-path", str(registry_path), "--audit-path", str(audit_path), "check-definition", str(definition), "--json"])
    checked = json.loads(capsys.readouterr().out)
    assert checked["ok"] is True

    main(["--registry-path", str(registry_path), "--audit-path", str(audit_path), "register", str(definition), "--confirm", "--json"])
    registered = json.loads(capsys.readouterr().out)
    assert registered["ok"] is True

    main(["--registry-path", str(registry_path), "--audit-path", str(audit_path), "check-tool", "mcp://github/read-only", "repo.search", "--json"])
    evaluated = json.loads(capsys.readouterr().out)
    assert evaluated["decision"] == "approval_required"


def test_mcp_review_queue_stores_only_security_passed_definitions_and_approves(tmp_path):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl", tmp_path / "mcp_reviews.jsonl")
    unsafe = valid_definition(tmp_path / "token_file")
    unsafe["url"] = "http://mcp.example.test/github"

    rejected = registry.submit_review(unsafe, actor="UnitTest")
    assert rejected["ok"] is False
    assert rejected["error"] == "security_check_failed_not_stored"
    assert registry.reviews() == []

    submitted = registry.submit_review(valid_definition(tmp_path / "token_file"), actor="UnitTest")
    assert submitted["ok"] is True
    review_id = submitted["review"]["review_id"]
    assert registry.reviews(status="pending")[0]["review_id"] == review_id
    assert registry.load() == []

    needs_confirm = registry.approve_review(review_id, actor="Reviewer", confirm=False)
    assert needs_confirm["ok"] is False
    assert needs_confirm["error"] == "confirm_required"

    approved = registry.approve_review(review_id, actor="Reviewer", reason="safe", confirm=True)
    assert approved["ok"] is True
    assert registry.reviews(status="pending") == []
    assert registry.reviews(status="approved")[0]["review_id"] == review_id
    assert len(registry.load()) == 1
    assert registry.verify_review_integrity()["ok"] is True


def test_mcp_review_queue_rejects_pending_review(tmp_path):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl", tmp_path / "mcp_reviews.jsonl")
    submitted = registry.submit_review(valid_definition(tmp_path / "token_file"), actor="UnitTest")
    review_id = submitted["review"]["review_id"]

    rejected = registry.reject_review(review_id, actor="Reviewer", reason="not needed")

    assert rejected["ok"] is True
    assert registry.reviews(status="rejected")[0]["reason"] == "not needed"
    assert registry.load() == []


def test_tape_memory_mcp_definition_is_review_gated_and_secret_free():
    data = json.loads(Path("config/mcp/tape_memory_mcp.json").read_text(encoding="utf-8"))

    result = check_connector_definition(data)

    assert result["ok"] is True
    assert result["findings"] == []
    connector = result["connector"]
    assert connector["connector_id"] == "mcp://tape-memory/cpos-resume"
    assert connector["transport"] == "stdio"
    assert connector["command"][:2] == ["env", "TAPE_MEMORY_DIR=/home/mayutama/.tape-memory-mcp-cpos"]
    assert connector["requires_human_approval"] is True
    assert connector["env_secret_files"] == {}
    assert connector["allowed_tools"] == ["load_tape", "store_tape", "inspect_dictionary"]
    assert "extend_dictionary" in connector["blocked_tools"]
    assert connector["metadata"]["stores_raw_secrets"] is False
    assert connector["metadata"]["stores_raw_diffs"] is False
    assert connector["metadata"]["stores_raw_outputs"] is False

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from cpos.mcp_registry import MCPRegistry, check_connector_definition, load_observation_file
from cpos.mcp_tls_policy import (
    check_tls_policy_definition,
    parse_tls_policy,
    verify_tls_observation,
)

PIN = "ab" * 32  # 64 hex chars


def _future_iso(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def good_policy() -> dict:
    return {
        "min_version": "TLSv1.2",
        "pinned_spki_sha256": [PIN],
        "forbidden_issuers": ["eMudhra Technologies Limited"],
        "require_hostname_match": True,
        "forbid_key_logging": True,
    }


def good_observation() -> dict:
    return {
        "negotiated_version": "TLSv1.3",
        "leaf_spki_sha256": PIN.upper(),  # case-insensitive match
        "chain_issuers": [{"O": "Example CA", "CN": "Example Root"}],
        "leaf_not_after": _future_iso(),
        "hostname_matched": True,
        "keylog_disabled": True,
        "observed_host": "mcp.example.test",
    }


def connector(policy=None, url="https://mcp.example.test/github", transport="https"):
    return {"url": url, "transport": transport, "tls_policy": policy}


# --------------------------------------------------------------------------- #
# parse / static definition checks
# --------------------------------------------------------------------------- #

def test_parse_applies_defaults_for_missing_policy():
    effective = parse_tls_policy(None)
    assert effective["min_version"] == "TLSv1.2"
    assert effective["require_hostname_match"] is True
    assert effective["forbid_key_logging"] is True
    assert effective["pinned_spki_sha256"] == []


def test_check_policy_accepts_valid_block():
    assert check_tls_policy_definition(good_policy()) == []


def test_check_policy_none_is_silent():
    assert check_tls_policy_definition(None) == []


def test_check_policy_rejects_non_object():
    codes = {f["code"] for f in check_tls_policy_definition("TLSv1.3")}
    assert "tls_policy_invalid" in codes


def test_check_policy_rejects_weak_and_invalid_min_version():
    low = {f["code"] for f in check_tls_policy_definition({"min_version": "TLSv1.0"})}
    assert "tls_min_version_too_low" in low
    bad = {f["code"] for f in check_tls_policy_definition({"min_version": "SSLv3"})}
    assert "tls_min_version_invalid" in bad


def test_check_policy_pin_shapes():
    empty = {f["code"] for f in check_tls_policy_definition({"pinned_spki_sha256": []})}
    assert "tls_pins_empty" in empty  # warning, not error
    bad = {f["code"] for f in check_tls_policy_definition({"pinned_spki_sha256": ["nothex"]})}
    assert "tls_pin_malformed" in bad
    not_list = {f["code"] for f in check_tls_policy_definition({"pinned_spki_sha256": PIN})}
    assert "tls_pins_invalid" in not_list


def test_check_policy_forbidden_issuers_and_flags_and_unknown():
    bad_issuers = {f["code"] for f in check_tls_policy_definition({"forbidden_issuers": [""]})}
    assert "tls_forbidden_issuers_invalid" in bad_issuers
    bad_flag = {f["code"] for f in check_tls_policy_definition({"require_hostname_match": "yes"})}
    assert "tls_flag_invalid" in bad_flag
    unknown = {f["code"] for f in check_tls_policy_definition({"min_version": "TLSv1.2", "wat": 1})}
    assert "tls_policy_unknown_field" in unknown


# --------------------------------------------------------------------------- #
# runtime observation verification (fail-closed)
# --------------------------------------------------------------------------- #

def test_verify_denies_when_observation_missing():
    result = verify_tls_observation(connector(good_policy()), None)
    assert result["ok"] is False
    assert result["decision"] == "tls_denied"
    assert {f["code"] for f in result["findings"]} == {"tls_observation_required"}


def test_verify_allows_good_observation():
    result = verify_tls_observation(connector(good_policy()), good_observation())
    assert result["ok"] is True
    assert result["decision"] == "tls_allowed"
    assert result["findings"] == []


def test_verify_allows_with_default_policy_when_none_declared():
    # No declared policy -> defaults: TLSv1.2 floor, hostname + keylog required,
    # no pin. A clean observation should still pass.
    result = verify_tls_observation(connector(None), good_observation())
    assert result["ok"] is True


def test_verify_denies_low_or_unknown_version():
    obs = good_observation()
    obs["negotiated_version"] = "TLSv1.1"
    assert verify_tls_observation(connector(good_policy()), obs)["decision"] == "tls_denied"
    obs2 = good_observation()
    obs2["negotiated_version"] = "nonsense"
    codes = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs2)["findings"]}
    assert "tls_version_unknown" in codes


def test_verify_denies_spki_missing_and_mismatch():
    obs = good_observation()
    del obs["leaf_spki_sha256"]
    codes = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs)["findings"]}
    assert "tls_spki_missing" in codes
    obs2 = good_observation()
    obs2["leaf_spki_sha256"] = "cd" * 32
    codes2 = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs2)["findings"]}
    assert "tls_spki_mismatch" in codes2


def test_verify_denies_forbidden_issuer_and_missing_chain():
    obs = good_observation()
    obs["chain_issuers"] = [{"O": "eMudhra Technologies Limited", "CN": "eMudhra CA"}]
    codes = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs)["findings"]}
    assert "tls_issuer_forbidden" in codes
    obs2 = good_observation()
    obs2["chain_issuers"] = []
    codes2 = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs2)["findings"]}
    assert "tls_chain_issuers_missing" in codes2


def test_verify_denies_hostname_unverified_and_divergence():
    obs = good_observation()
    obs["hostname_matched"] = False
    codes = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs)["findings"]}
    assert "tls_hostname_unverified" in codes
    obs2 = good_observation()
    obs2["observed_host"] = "evil.example.test"
    codes2 = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs2)["findings"]}
    assert "tls_host_divergence" in codes2


def test_verify_denies_when_observed_host_missing_or_illtyped():
    # hostname_matched=True alone must NOT pass: a valid observed_host that
    # matches the connector URL host is also required (HIGH1).
    for bad in (None, 1, [], "", "   ", "x" * 300):
        obs = good_observation()
        if bad is None:
            del obs["observed_host"]
        else:
            obs["observed_host"] = bad
        result = verify_tls_observation(connector(good_policy()), obs)
        assert result["ok"] is False, bad
        assert "tls_observed_host_missing" in {f["code"] for f in result["findings"]}, bad


def test_verify_denies_connector_without_host():
    obs = good_observation()
    result = verify_tls_observation(connector(good_policy(), url="https:///nohost"), obs)
    assert result["ok"] is False
    assert "tls_expected_host_unknown" in {f["code"] for f in result["findings"]}


def test_verify_denies_malformed_chain_cannot_hide_forbidden_issuer():
    # HIGH2: a malformed chain entry must deny, not be silently skipped.
    for chain in (
        [{"O": "Good CA"}, "eMudhra Technologies Limited"],  # raw string entry
        [{"O": "Good CA", "CN": ["eMudhra Technologies Limited"]}],  # non-string attr
        "eMudhra Technologies Limited",  # not even a list
        [{"O": "x"}] * 65,  # oversized
    ):
        obs = good_observation()
        obs["chain_issuers"] = chain
        result = verify_tls_observation(connector(good_policy()), obs)
        assert result["ok"] is False, chain
        assert "tls_chain_malformed" in {f["code"] for f in result["findings"]}, chain


def test_verify_denies_invalid_policy_at_runtime():
    # MED3: the public primitive must not silently apply weakened defaults for a
    # policy that would be rejected at registration.
    bad_policy = {"min_version": "TLSv1.0", "require_hostname_match": None, "forbid_key_logging": 0}
    result = verify_tls_observation(connector(bad_policy), {"negotiated_version": "TLSv1.0"})
    assert result["ok"] is False
    assert result["decision"] == "tls_denied"
    assert "tls_min_version_too_low" in {f["code"] for f in result["findings"]}


def test_findings_do_not_echo_observation_values():
    # MED4: arbitrary OBSERVATION input must not be reflected into messages.
    # (The effective policy is operator config and may appear in result["policy"];
    # the marker here lives only in observation-supplied fields.)
    marker = "INJECT_MARKER_12345"
    obs = good_observation()
    obs["observed_host"] = marker  # -> host divergence, generic message
    obs["chain_issuers"] = [{"O": marker}]  # benign (not forbidden), not echoed
    result = verify_tls_observation(connector(good_policy()), obs)
    assert result["ok"] is False
    blob = json.dumps(result["findings"], ensure_ascii=False)
    assert marker not in blob


def test_verify_rejects_malformed_version_token():
    # LOW7: anchored grammar, so "TLSVTLSV1.3" is unknown, not coerced.
    obs = good_observation()
    obs["negotiated_version"] = "TLSVTLSV1.3"
    result = verify_tls_observation(connector(good_policy()), obs)
    assert result["ok"] is False
    assert "tls_version_unknown" in {f["code"] for f in result["findings"]}


def test_verify_version_normalization_is_not_superlinear():
    # round2 MED: a long whitespace-padded token must be rejected cheaply
    # (length cap gate), not explored by a backtracking regex.
    obs = good_observation()
    obs["negotiated_version"] = "TLS" + " " * 8000 + "X"
    result = verify_tls_observation(connector(good_policy()), obs)
    assert result["ok"] is False
    assert "tls_version_unknown" in {f["code"] for f in result["findings"]}


def test_oversized_version_token_never_reaches_regex(monkeypatch):
    # round3 LOW: asserting denial alone would also pass on the old quadratic
    # regex. Prove the length-cap gate rejects an oversized token BEFORE the
    # regex engine is ever consulted, so no backtracking can occur regardless of
    # the pattern. A sentinel records whether _VERSION_RE.match was called.
    from cpos import mcp_tls_policy as tp

    real = tp._VERSION_RE
    calls = {"n": 0}

    class _Guard:
        def match(self, s):
            calls["n"] += 1
            return real.match(s)

    monkeypatch.setattr(tp, "_VERSION_RE", _Guard())
    # An adversarial, pathological token: the gate must reject it untouched.
    assert tp._normalize_version("TLS" + " " * 1_000_000 + "X") is None
    assert calls["n"] == 0  # length gate fired first; regex never ran
    # Control: a well-formed token DOES reach the regex and normalizes.
    assert tp._normalize_version("TLSv1.2") == "TLSv1.2"
    assert calls["n"] == 1


def test_host_comparison_is_not_unicode_casefolded():
    # round2 HIGH: casefold() maps "ß" -> "ss"; distinct hosts must stay distinct.
    obs = good_observation()
    obs["observed_host"] = "fass.example.test"
    result = verify_tls_observation(connector(good_policy(), url="https://faß.example.test/x"), obs)
    assert result["ok"] is False
    assert "tls_host_divergence" in {f["code"] for f in result["findings"]}


def test_verify_denies_keylog_not_disabled():
    obs = good_observation()
    obs["keylog_disabled"] = False
    codes = {f["code"] for f in verify_tls_observation(connector(good_policy()), obs)["findings"]}
    assert "tls_keylog_not_disabled" in codes


def test_verify_expiry_expired_is_error_unknown_is_warning():
    obs = good_observation()
    obs["leaf_not_after"] = "2000-01-01T00:00:00Z"
    expired = verify_tls_observation(connector(good_policy()), obs)
    assert expired["ok"] is False
    assert "tls_certificate_expired" in {f["code"] for f in expired["findings"]}

    obs2 = good_observation()
    del obs2["leaf_not_after"]
    unknown = verify_tls_observation(connector(good_policy()), obs2)
    assert unknown["ok"] is True  # warning only
    assert "tls_expiry_unknown" in {f["code"] for f in unknown["findings"]}


# --------------------------------------------------------------------------- #
# registry integration
# --------------------------------------------------------------------------- #

def remote_definition(tmp_path, *, policy="__good__"):
    data = {
        "connector_id": "mcp://github/read-only",
        "name": "GitHub Read Only MCP",
        "transport": "https",
        "url": "https://mcp.example.test/github",
        "allowed_tools": ["repo.search"],
        "blocked_tools": [],
        "sensitivity_level": "internal",
        "requires_human_approval": True,
        "env_secret_files": {"GITHUB_TOKEN_FILE": str(tmp_path / "tok")},
    }
    if policy == "__good__":
        data["tls_policy"] = good_policy()
    elif policy is not None:
        data["tls_policy"] = policy
    return data


def test_definition_warns_when_remote_policy_absent():
    data = remote_definition_without_policy()
    result = check_connector_definition(data)
    assert result["ok"] is True  # warning does not block
    assert "tls_policy_absent" in {f["code"] for f in result["findings"]}


def remote_definition_without_policy():
    return {
        "connector_id": "mcp://x/y",
        "name": "X",
        "transport": "https",
        "url": "https://mcp.example.test/x",
        "allowed_tools": ["a.b"],
        "blocked_tools": [],
        "sensitivity_level": "internal",
        "requires_human_approval": True,
        "env_secret_files": {},
    }


def test_definition_rejects_bad_policy_block():
    data = remote_definition_without_policy()
    data["tls_policy"] = {"min_version": "TLSv1.0"}
    result = check_connector_definition(data)
    assert result["ok"] is False
    assert "tls_min_version_too_low" in {f["code"] for f in result["findings"]}


def test_stdio_tls_policy_is_warned_as_ignored():
    data = {
        "connector_id": "mcp://local/tool",
        "name": "Local",
        "transport": "stdio",
        "command": ["mcp-server"],
        "allowed_tools": ["a.b"],
        "blocked_tools": [],
        "sensitivity_level": "internal",
        "requires_human_approval": True,
        "env_secret_files": {},
        "tls_policy": good_policy(),
    }
    result = check_connector_definition(data)
    assert result["ok"] is True
    assert "stdio_tls_policy_ignored" in {f["code"] for f in result["findings"]}


def test_registry_verify_tls_happy_and_audited(tmp_path):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl", tmp_path / "mcp_reviews.jsonl")
    assert registry.register(remote_definition(tmp_path), confirm=True)["ok"] is True

    result = registry.verify_tls("mcp://github/read-only", good_observation())
    assert result["ok"] is True
    assert result["decision"] == "tls_allowed"

    audit = [row for row in registry_audit_rows(registry) if row.get("event") == "tls_observation_verified"]
    assert audit and audit[-1]["decision"] == "tls_allowed"


def test_registry_verify_tls_denies_and_handles_missing_and_stdio(tmp_path):
    registry = MCPRegistry(tmp_path / "connectors.json", tmp_path / "mcp_audit.jsonl", tmp_path / "mcp_reviews.jsonl")
    assert registry.register(remote_definition(tmp_path), confirm=True)["ok"] is True

    # missing connector
    missing = registry.verify_tls("mcp://nope", good_observation())
    assert missing["ok"] is False and missing["error"] == "connector_not_found"

    # fail-closed on absent observation
    denied = registry.verify_tls("mcp://github/read-only", None)
    assert denied["ok"] is False and denied["decision"] == "tls_denied"

    # stdio connector: TLS verification is not applicable
    stdio_def = {
        "connector_id": "mcp://local/tool",
        "name": "Local",
        "transport": "stdio",
        "command": ["mcp-server"],
        "allowed_tools": ["a.b"],
        "blocked_tools": [],
        "sensitivity_level": "internal",
        "requires_human_approval": True,
        "env_secret_files": {},
    }
    assert registry.register(stdio_def, confirm=True)["ok"] is True
    na = registry.verify_tls("mcp://local/tool", good_observation())
    assert na["ok"] is False and na["decision"] == "tls_not_applicable"


def test_load_observation_file_is_bounded_and_rejects_nonregular(tmp_path):
    good = tmp_path / "obs.json"
    good.write_text(json.dumps(good_observation()), encoding="utf-8")
    assert load_observation_file(good)["negotiated_version"] == "TLSv1.3"

    # a directory is not a regular file -> rejected (also covers FIFO/socket path)
    with pytest.raises(ValueError):
        load_observation_file(tmp_path)

    # oversized file -> rejected (bounded read of limit+1, excess refused)
    big = tmp_path / "big.json"
    big.write_text("0" * (256 * 1024 + 1), encoding="utf-8")
    with pytest.raises(ValueError):
        load_observation_file(big)


def test_load_observation_file_rejects_fifo_without_blocking(tmp_path):
    # round2 MED: fstat on the opened (O_NONBLOCK) fd rejects a FIFO rather than
    # blocking on open/read. If this test hangs, the non-blocking guarantee broke.
    import os as _os

    fifo = tmp_path / "f"
    _os.mkfifo(fifo)
    with pytest.raises(ValueError):
        load_observation_file(fifo)


def registry_audit_rows(registry):
    from cpos.hash_chain import read_jsonl

    return read_jsonl(registry.audit_path)


# --------------------------------------------------------------------------- #
# CPOS②: intermediate SPKI pinning
# --------------------------------------------------------------------------- #

INTER_PIN = "cd" * 32  # 64 hex chars, distinct from leaf PIN
OTHER_HASH = "ef" * 32


def _policy_with_intermediate(*pins):
    p = good_policy()
    p["pinned_intermediate_spki_sha256"] = list(pins)
    return p


def _obs_with_chain(*spki):
    obs = good_observation()
    obs["chain_spki_sha256"] = list(spki)
    return obs


def test_check_policy_accepts_intermediate_pins():
    assert check_tls_policy_definition(_policy_with_intermediate(INTER_PIN)) == []


def test_check_policy_rejects_non_list_intermediate_pins():
    bad = {**good_policy(), "pinned_intermediate_spki_sha256": "nope"}
    codes = {f["code"] for f in check_tls_policy_definition(bad)}
    assert "tls_intermediate_pins_invalid" in codes


def test_check_policy_rejects_malformed_intermediate_pin():
    codes = {f["code"] for f in check_tls_policy_definition(_policy_with_intermediate("xyz"))}
    assert "tls_intermediate_pin_malformed" in codes


def test_check_policy_warns_empty_intermediate_pins():
    findings = check_tls_policy_definition(_policy_with_intermediate())
    codes = {f["code"] for f in findings}
    assert "tls_intermediate_pins_empty" in codes
    # empty is a warning, not an error -> registration not blocked
    assert all(f["severity"] != "error" for f in findings)


def test_parse_normalizes_intermediate_pins():
    effective = parse_tls_policy(_policy_with_intermediate(INTER_PIN.upper(), "  " + OTHER_HASH + "  "))
    assert effective["pinned_intermediate_spki_sha256"] == [INTER_PIN, OTHER_HASH]


def test_verify_intermediate_pin_passes_when_present():
    policy = _policy_with_intermediate(INTER_PIN)
    # case-insensitive match, mixed with other chain entries
    obs = _obs_with_chain(OTHER_HASH, INTER_PIN.upper())
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is True
    assert result["decision"] == "tls_allowed"


def test_verify_intermediate_pin_denies_on_mismatch():
    policy = _policy_with_intermediate(INTER_PIN)
    obs = _obs_with_chain(OTHER_HASH, "12" * 32)
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is False
    codes = {f["code"] for f in result["findings"]}
    assert "tls_intermediate_spki_mismatch" in codes


def test_verify_intermediate_pin_denies_when_chain_absent():
    # fail-closed: policy pins an intermediate but observation omits the chain
    policy = _policy_with_intermediate(INTER_PIN)
    obs = good_observation()  # no chain_spki_sha256
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is False
    codes = {f["code"] for f in result["findings"]}
    assert "tls_intermediate_chain_malformed" in codes


def test_verify_intermediate_pin_denies_on_empty_chain():
    policy = _policy_with_intermediate(INTER_PIN)
    obs = _obs_with_chain()  # present but empty
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is False
    codes = {f["code"] for f in result["findings"]}
    assert "tls_intermediate_spki_missing" in codes


def test_verify_intermediate_pin_denies_on_malformed_chain_entry():
    # a non-hex entry makes the whole chain untrusted -> deny, never skip
    policy = _policy_with_intermediate(INTER_PIN)
    obs = _obs_with_chain(INTER_PIN, "not-a-hash")
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is False
    codes = {f["code"] for f in result["findings"]}
    assert "tls_intermediate_chain_malformed" in codes


def test_verify_intermediate_pin_denies_on_oversized_chain():
    policy = _policy_with_intermediate(INTER_PIN)
    obs = _obs_with_chain(*([INTER_PIN] * 65))  # over _MAX_CHAIN_ENTRIES
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is False
    codes = {f["code"] for f in result["findings"]}
    assert "tls_intermediate_chain_malformed" in codes


def test_verify_without_intermediate_pin_ignores_chain_spki():
    # backward-compat: a policy that does not pin intermediates must not require
    # chain_spki_sha256; the field's absence is fine.
    result = verify_tls_observation(connector(good_policy()), good_observation())
    assert result["ok"] is True


def test_verify_findings_never_echo_chain_spki_values():
    policy = _policy_with_intermediate(INTER_PIN)
    obs = _obs_with_chain(OTHER_HASH)
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is False
    # the mismatching observed hash must not be echoed into finding messages
    assert OTHER_HASH not in json.dumps(result["findings"])


# --- intermediate pinning: non-blocking regression coverage (Codex round 4) ---


@pytest.mark.parametrize("bad_chain", [
    "not-a-list",
    {"spki": INTER_PIN},
    None,
    [INTER_PIN, None],
    [INTER_PIN, True],
    [INTER_PIN, 123],
    [INTER_PIN, {"nested": "x"}],
])
def test_verify_intermediate_denies_on_non_string_or_non_list_chain(bad_chain):
    policy = _policy_with_intermediate(INTER_PIN)
    obs = good_observation()
    obs["chain_spki_sha256"] = bad_chain
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is False
    assert "tls_intermediate_chain_malformed" in {f["code"] for f in result["findings"]}


def test_verify_intermediate_passes_at_chain_size_bound():
    # exactly _MAX_CHAIN_ENTRIES (64) well-formed entries incl. the pin -> ok
    policy = _policy_with_intermediate(INTER_PIN)
    filler = [f"{i:064x}" for i in range(63)]
    obs = _obs_with_chain(*(filler + [INTER_PIN]))
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is True


def test_verify_intermediate_matches_despite_surrounding_whitespace():
    policy = _policy_with_intermediate(INTER_PIN)
    obs = _obs_with_chain("  " + INTER_PIN.upper() + "  ")
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is True


def test_verify_intermediate_or_matches_any_pinned():
    # multiple pins: presence of any one in the chain passes
    policy = _policy_with_intermediate(INTER_PIN, OTHER_HASH)
    obs = _obs_with_chain("12" * 32, OTHER_HASH)
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is True


def test_verify_runtime_denies_on_invalid_intermediate_policy():
    # a malformed intermediate pin is an error at definition time; the verifier
    # must also deny fail-closed rather than silently drop the bad pin.
    bad_policy = {**good_policy(), "pinned_intermediate_spki_sha256": ["xyz"]}
    result = verify_tls_observation(connector(bad_policy), _obs_with_chain(INTER_PIN))
    assert result["ok"] is False
    assert "tls_intermediate_pin_malformed" in {f["code"] for f in result["findings"]}


def test_verify_empty_intermediate_pins_ignore_bad_chain():
    # backward-compat: an empty pin list enforces nothing, so even a malformed
    # chain_spki_sha256 does not block (no intermediate pin is in effect).
    policy = _policy_with_intermediate()  # empty list
    obs = good_observation()
    obs["chain_spki_sha256"] = "garbage"
    result = verify_tls_observation(connector(policy), obs)
    assert result["ok"] is True

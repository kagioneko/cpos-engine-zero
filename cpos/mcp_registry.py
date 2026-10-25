from __future__ import annotations

import argparse
import json
import os
import re
import stat
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .hash_chain import append_chained_jsonl, read_jsonl, verify_hash_chain
from .mcp_tls_policy import check_tls_policy_definition, verify_tls_observation
from .pointer_os import utc_now

VALID_TRANSPORTS = {"stdio", "https", "sse"}
VALID_STATUSES = {"active", "disabled", "revoked"}
VALID_SENSITIVITY = {"public", "internal", "private", "restricted"}
SECRETISH_KEYS = re.compile(r"(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)", re.I)
# Credential-ish *query parameter* names, bounded so a benign compound like
# max_tokens / tokenizer / password_policy does not match. Heuristic -> warning,
# not a hard block (unlike unambiguous user:pass@ userinfo).
URL_QUERY_SECRET = re.compile(
    r"(?:^|[._-])(access[._-]?token|client[._-]?secret|api[._-]?key|apikey|private[._-]?key"
    r"|token|secret|password|passwd|credential|signature|auth|sig|key)$",
    re.I,
)
SHELL_META = re.compile(r"[;&|`$<>]")
DANGEROUS_TOOLS = re.compile(r"(shell|exec|command|terminal|ssh|delete|remove|write_file|filesystem)", re.I)


@dataclass
class MCPConnector:
    connector_id: str
    name: str
    transport: str
    allowed_tools: list[str]
    command: list[str] = field(default_factory=list)
    url: str | None = None
    blocked_tools: list[str] = field(default_factory=list)
    sensitivity_level: str = "internal"
    requires_human_approval: bool = True
    env_secret_files: dict[str, str] = field(default_factory=dict)
    status: str = "active"
    created_at: str = field(default_factory=utc_now)
    tls_policy: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MCPConnector":
        allowed = data.get("allowed_tools") or []
        blocked = data.get("blocked_tools") or []
        command = data.get("command") or []
        env_secret_files = data.get("env_secret_files") or {}
        return cls(
            connector_id=str(data.get("connector_id", "")),
            name=str(data.get("name", "")),
            transport=str(data.get("transport", "")),
            command=[str(x) for x in command] if isinstance(command, list) else command,
            url=data.get("url"),
            allowed_tools=[str(x) for x in allowed] if isinstance(allowed, list) else allowed,
            blocked_tools=[str(x) for x in blocked] if isinstance(blocked, list) else blocked,
            sensitivity_level=str(data.get("sensitivity_level", "internal")),
            requires_human_approval=bool(data.get("requires_human_approval", True)),
            env_secret_files={str(k): str(v) for k, v in env_secret_files.items()} if isinstance(env_secret_files, dict) else env_secret_files,
            status=str(data.get("status", "active")),
            created_at=str(data.get("created_at") or utc_now()),
            tls_policy=data.get("tls_policy"),
            metadata=data.get("metadata") or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "url": self.url,
            "allowed_tools": self.allowed_tools,
            "blocked_tools": self.blocked_tools,
            "sensitivity_level": self.sensitivity_level,
            "requires_human_approval": self.requires_human_approval,
            "env_secret_files": self.env_secret_files,
            "status": self.status,
            "created_at": self.created_at,
            "tls_policy": self.tls_policy,
            "metadata": self.metadata,
        }


def load_definition_text(path: str | Path) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


# Maximum bytes the CLI will read from an observation file. A TLS observation is
# a small metadata object; anything larger is rejected rather than slurped.
_MAX_OBSERVATION_BYTES = 256 * 1024


def load_observation_file(path: str | Path) -> dict[str, Any]:
    """Read a TLS observation JSON file for the CLI, with a bounded read.

    Opened first with O_NONBLOCK, then validated by ``fstat`` on the *opened*
    descriptor (not a pre-open ``stat`` on the path) so there is no stat/read
    race: a non-regular target (FIFO/socket/device/dir) is rejected on the fd we
    actually hold, and O_NONBLOCK keeps *opening* a FIFO from blocking (it does
    not bound arbitrary filesystem latency on a regular file). The read is
    bounded to ``_MAX_OBSERVATION_BYTES + 1`` bytes and any excess is rejected
    *after* that bounded read but before decoding, so a file that grows after
    opening cannot exhaust memory."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("observation path must be a regular file")
        chunks: list[bytes] = []
        remaining = _MAX_OBSERVATION_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > _MAX_OBSERVATION_BYTES:
        raise ValueError("observation file is too large")
    return json.loads(data.decode("utf-8"))


def review_id_for(connector_id: str, timestamp: str) -> str:
    digest = hashlib.sha256(f"{connector_id}\n{timestamp}".encode("utf-8")).hexdigest()[:16]
    return f"mcp_review_{digest}"


def _finding(severity: str, code: str, message: str, field: str | None = None) -> dict[str, str]:
    item = {"severity": severity, "code": code, "message": message}
    if field:
        item["field"] = field
    return item


def check_connector_definition(data: dict[str, Any]) -> dict[str, Any]:
    """Static text-only security check. Does not execute or connect to MCP servers."""
    findings: list[dict[str, str]] = []

    if not isinstance(data, dict):
        return {"ok": False, "findings": [_finding("error", "definition_not_object", "definition must be a JSON object")], "connector": None}

    connector = MCPConnector.from_dict(data)
    if not connector.connector_id:
        findings.append(_finding("error", "connector_id_required", "connector_id is required", "connector_id"))
    if not connector.name:
        findings.append(_finding("error", "name_required", "name is required", "name"))
    if connector.transport not in VALID_TRANSPORTS:
        findings.append(_finding("error", "invalid_transport", f"transport must be one of {sorted(VALID_TRANSPORTS)}", "transport"))
    if connector.status not in VALID_STATUSES:
        findings.append(_finding("error", "invalid_status", f"status must be one of {sorted(VALID_STATUSES)}", "status"))
    if connector.sensitivity_level not in VALID_SENSITIVITY:
        findings.append(_finding("error", "invalid_sensitivity", f"sensitivity_level must be one of {sorted(VALID_SENSITIVITY)}", "sensitivity_level"))

    if "env" in data or "secrets" in data:
        findings.append(_finding("error", "raw_env_or_secrets_blocked", "raw env/secrets fields are blocked; use env_secret_files with Vault-rendered files", "env"))
    if not isinstance(connector.env_secret_files, dict):
        findings.append(_finding("error", "env_secret_files_invalid", "env_secret_files must be a map of ENV_NAME -> secret file path", "env_secret_files"))
    else:
        for key, value in connector.env_secret_files.items():
            if not key or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
                findings.append(_finding("error", "invalid_env_name", "env_secret_files keys must be uppercase environment variable names", f"env_secret_files.{key}"))
            if not value:
                findings.append(_finding("error", "secret_file_required", "secret file path is required", f"env_secret_files.{key}"))
            if SECRETISH_KEYS.search(value) and not str(value).startswith(("/run/", "/var/run/", "/tmp/", "/home/")):
                findings.append(_finding("warning", "secret_path_review", "secret file path looks sensitive; verify it is a file path, not a secret value", f"env_secret_files.{key}"))

    # Recursively catch likely raw secret fields outside approved file pointers.
    def scan_raw_secrets(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if path.startswith("env_secret_files."):
                    continue
                if SECRETISH_KEYS.search(str(key)) and isinstance(value, str) and value.strip():
                    findings.append(_finding("error", "raw_secret_like_value", "secret-like fields must not contain values in connector definitions", path))
                scan_raw_secrets(value, path)
        elif isinstance(obj, list):
            for idx, value in enumerate(obj):
                scan_raw_secrets(value, f"{prefix}[{idx}]")

    scan_raw_secrets(data)

    if connector.transport == "stdio":
        if not isinstance(connector.command, list) or not connector.command:
            findings.append(_finding("error", "stdio_command_required", "stdio transport requires command as an argv list", "command"))
        else:
            for idx, part in enumerate(connector.command):
                if SHELL_META.search(part):
                    findings.append(_finding("error", "shell_meta_blocked", "command argv must not contain shell metacharacters", f"command[{idx}]"))
            if connector.command[0] in {"sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh"}:
                findings.append(_finding("error", "shell_wrapper_blocked", "shell wrappers are blocked for MCP stdio definitions", "command[0]"))
        if connector.url:
            findings.append(_finding("warning", "stdio_url_ignored", "url is ignored for stdio transport", "url"))
        if connector.tls_policy is not None:
            findings.append(_finding("warning", "stdio_tls_policy_ignored", "tls_policy is ignored for stdio transport (no TLS connection)", "tls_policy"))
    else:
        if connector.command:
            findings.append(_finding("warning", "remote_command_ignored", "command is ignored for remote MCP transports", "command"))
        if not connector.url:
            findings.append(_finding("error", "url_required", "https/sse transport requires an HTTPS URL", "url"))
        else:
            parsed = urlparse(str(connector.url))
            if parsed.scheme != "https":
                findings.append(_finding("error", "https_required", "MCP remote connectors must use https:// only", "url"))
            # `netloc` is non-empty for `https://:443`, which has no hostname;
            # require an actual host so a portspec-only authority is rejected.
            if not parsed.hostname:
                findings.append(_finding("error", "url_host_required", "MCP URL must include a host", "url"))
            # A credential embedded in the URL authority (user:pass@host) would be
            # persisted to the registry JSONL, the hash-chained audit log and git,
            # and echoed by anything that logs the URL. Credentials belong in
            # env_secret_files (Vault-rendered), never in the connector URL.
            # `is not None` rejects all userinfo syntax, including a bare
            # `https://@host` whose components are empty.
            if parsed.username is not None or parsed.password is not None:
                findings.append(_finding("error", "url_userinfo_blocked", "credentials must not be embedded in the URL (user:pass@host); use env_secret_files instead", "url"))
            # A credential can also hide in the query string (?access_token=...),
            # the same leak class as userinfo. This is a name heuristic (bounded
            # match, so max_tokens / tokenizer do not trip it), so it is a
            # warning to review, not a hard block: flag a secret-like parameter
            # that carries a value; a blank value (?token=) is not a leak.
            for q_name, q_value in parse_qsl(parsed.query, keep_blank_values=True):
                if URL_QUERY_SECRET.search(q_name) and q_value.strip():
                    findings.append(_finding("warning", "url_query_secret_review", "a query parameter looks like a credential; put credentials in env_secret_files, not the URL", "url"))
                    break
        # TLS policy is declarative here (no connection is made). Validate its
        # shape if present; recommend declaring one otherwise. Runtime
        # enforcement happens later via verify_tls_observation().
        if connector.tls_policy is None:
            findings.append(_finding("warning", "tls_policy_absent", "remote connector declares no tls_policy; SPKI pinning and a TLS floor are recommended", "tls_policy"))
        else:
            findings.extend(check_tls_policy_definition(connector.tls_policy))

    if not isinstance(connector.allowed_tools, list) or not connector.allowed_tools:
        findings.append(_finding("error", "allowed_tools_required", "allowed_tools must be an explicit non-empty allowlist", "allowed_tools"))
    else:
        for tool in connector.allowed_tools:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", tool):
                findings.append(_finding("error", "invalid_tool_name", "tool names may contain letters, numbers, dot, colon, underscore, dash", "allowed_tools"))
            if DANGEROUS_TOOLS.search(tool) and not connector.requires_human_approval:
                findings.append(_finding("error", "dangerous_tool_requires_approval", "dangerous-looking tools require human approval", "requires_human_approval"))
    if isinstance(connector.blocked_tools, list):
        overlap = sorted(set(connector.allowed_tools) & set(connector.blocked_tools)) if isinstance(connector.allowed_tools, list) else []
        if overlap:
            findings.append(_finding("error", "allow_block_overlap", f"tools cannot be both allowed and blocked: {overlap}", "blocked_tools"))
    else:
        findings.append(_finding("error", "blocked_tools_invalid", "blocked_tools must be a list", "blocked_tools"))

    if connector.sensitivity_level in {"private", "restricted"} and not connector.requires_human_approval:
        findings.append(_finding("error", "sensitive_requires_approval", "private/restricted connectors require human approval", "requires_human_approval"))

    ok = not any(f["severity"] == "error" for f in findings)
    return {"ok": ok, "findings": findings, "connector": connector.to_dict()}


class MCPRegistry:
    def __init__(self, registry_path: str | Path, audit_path: str | Path, review_path: str | Path | None = None):
        self.registry_path = Path(registry_path)
        self.audit_path = Path(audit_path)
        self.review_path = Path(review_path) if review_path is not None else self.registry_path.with_name("mcp_reviews.jsonl")

    def load(self) -> list[MCPConnector]:
        if not self.registry_path.exists():
            return []
        raw = json.loads(self.registry_path.read_text(encoding="utf-8") or "[]")
        return [MCPConnector.from_dict(item) for item in raw]

    def save(self, connectors: list[MCPConnector]) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [connector.to_dict() for connector in connectors]
        self.registry_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def audit(self, event: str, *, actor: str, connector_id: str | None = None, decision: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        safe_metadata = metadata or {}
        return append_chained_jsonl(self.audit_path, {
            "event": event,
            "actor": actor,
            "connector_id": connector_id,
            "decision": decision,
            "metadata": safe_metadata,
            "timestamp": utc_now(),
        })

    def check_definition(self, data: dict[str, Any], *, actor: str = "MCPRegistry") -> dict[str, Any]:
        result = check_connector_definition(data)
        connector_id = None
        if isinstance(result.get("connector"), dict):
            connector_id = result["connector"].get("connector_id")
        self.audit("definition_checked", actor=actor, connector_id=connector_id, decision="passed" if result["ok"] else "failed", metadata={"finding_codes": [f["code"] for f in result["findings"]]})
        return result

    def register(self, data: dict[str, Any], *, actor: str = "MCPRegistry", confirm: bool = False) -> dict[str, Any]:
        result = self.check_definition(data, actor=actor)
        if not result["ok"]:
            return {**result, "ok": False, "error": "security_check_failed"}
        if not confirm:
            return {**result, "ok": False, "error": "confirm_required_after_security_check"}
        connector = MCPConnector.from_dict(result["connector"])
        connectors = [item for item in self.load() if item.connector_id != connector.connector_id]
        connectors.append(connector)
        self.save(connectors)
        self.audit("connector_registered", actor=actor, connector_id=connector.connector_id, decision="registered", metadata={"transport": connector.transport, "sensitivity_level": connector.sensitivity_level})
        return {"ok": True, "connector": connector.to_dict(), "findings": result["findings"]}

    def disable(self, connector_id: str, *, actor: str = "MCPRegistry", reason: str = "manual_disable") -> dict[str, Any]:
        connectors = self.load()
        for connector in connectors:
            if connector.connector_id == connector_id:
                connector.status = "disabled"
                connector.metadata = dict(connector.metadata)
                connector.metadata["disabled_reason"] = reason
                connector.metadata["disabled_at"] = utc_now()
                self.save(connectors)
                self.audit("connector_disabled", actor=actor, connector_id=connector_id, decision="disabled", metadata={"reason": reason})
                return {"ok": True, "connector": connector.to_dict()}
        return {"ok": False, "error": "connector_not_found", "connector_id": connector_id}

    def evaluate_tool_call(self, connector_id: str, tool_name: str, *, actor: str = "MCPRegistry", purpose: str = "tool_check") -> dict[str, Any]:
        connector = next((item for item in self.load() if item.connector_id == connector_id), None)
        if connector is None:
            return {"ok": False, "allowed": False, "error": "connector_not_found", "connector_id": connector_id}
        if connector.status != "active":
            decision = "connector_not_active"
            allowed = False
        elif tool_name in connector.blocked_tools:
            decision = "tool_blocked"
            allowed = False
        elif tool_name not in connector.allowed_tools:
            decision = "tool_not_allowlisted"
            allowed = False
        else:
            decision = "approval_required" if connector.requires_human_approval else "allowed"
            allowed = not connector.requires_human_approval
        self.audit("tool_call_evaluated", actor=actor, connector_id=connector_id, decision=decision, metadata={"tool_name": tool_name, "purpose": purpose})
        return {
            "ok": True,
            "connector_id": connector_id,
            "tool_name": tool_name,
            "allowed": allowed,
            "requires_human_approval": connector.requires_human_approval if decision == "approval_required" else False,
            "decision": decision,
            "purpose": purpose,
        }

    def verify_tls(self, connector_id: str, observation: dict[str, Any] | None, *, actor: str = "MCPRegistry") -> dict[str, Any]:
        """Judge a TLS observation for a registered connector against its policy,
        fail-closed, and audit the decision. CPOS does not open the connection;
        the observation is supplied by whatever did."""
        connector = next((item for item in self.load() if item.connector_id == connector_id), None)
        if connector is None:
            return {"ok": False, "decision": "tls_denied", "error": "connector_not_found", "connector_id": connector_id}
        if connector.transport == "stdio":
            return {"ok": False, "decision": "tls_not_applicable", "error": "tls_not_applicable_for_stdio", "connector_id": connector_id}
        result = verify_tls_observation(connector, observation)
        self.audit(
            "tls_observation_verified",
            actor=actor,
            connector_id=connector_id,
            decision=result["decision"],
            metadata={"finding_codes": [f["code"] for f in result["findings"]], "ok": result["ok"]},
        )
        return {"connector_id": connector_id, **result}

    def submit_review(self, data: dict[str, Any], *, actor: str = "MCPRegistry") -> dict[str, Any]:
        result = self.check_definition(data, actor=actor)
        if not result["ok"]:
            # Do not persist unsafe definitions. Findings are returned and audited only.
            return {**result, "ok": False, "error": "security_check_failed_not_stored"}
        connector = MCPConnector.from_dict(result["connector"])
        timestamp = utc_now()
        review_id = review_id_for(connector.connector_id, timestamp)
        row = {
            "event": "mcp_review_submitted",
            "review_id": review_id,
            "connector_id": connector.connector_id,
            "status": "pending",
            "actor": actor,
            "connector": connector.to_dict(),
            "findings": result["findings"],
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        append_chained_jsonl(self.review_path, row)
        self.audit("review_submitted", actor=actor, connector_id=connector.connector_id, decision="pending", metadata={"review_id": review_id})
        return {"ok": True, "review": row}

    def review_events(self) -> list[dict[str, Any]]:
        return read_jsonl(self.review_path)

    def reviews(self, status: str | None = None) -> list[dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for row in self.review_events():
            review_id = row.get("review_id")
            if review_id:
                clean = {key: value for key, value in row.items() if key != "_chain"}
                latest[str(review_id)] = clean
        rows = list(latest.values())
        if status:
            rows = [row for row in rows if row.get("status") == status]
        return sorted(rows, key=lambda row: str(row.get("updated_at") or row.get("created_at") or ""), reverse=True)

    def approve_review(self, review_id: str, *, actor: str = "MCPRegistry", reason: str | None = None, confirm: bool = False) -> dict[str, Any]:
        if not confirm:
            return {"ok": False, "error": "confirm_required", "review_id": review_id}
        review = next((row for row in self.reviews() if row.get("review_id") == review_id), None)
        if review is None:
            return {"ok": False, "error": "review_not_found", "review_id": review_id}
        if review.get("status") != "pending":
            return {"ok": False, "error": "review_not_pending", "review_id": review_id, "status": review.get("status")}
        connector_data = review.get("connector") or {}
        registered = self.register(connector_data, actor=actor, confirm=True)
        if not registered.get("ok"):
            return {"ok": False, "error": "registration_failed", "review_id": review_id, "registration": registered}
        timestamp = utc_now()
        row = dict(review)
        row.update({"event": "mcp_review_approved", "status": "approved", "approved_by": actor, "reason": reason, "updated_at": timestamp})
        append_chained_jsonl(self.review_path, row)
        self.audit("review_approved", actor=actor, connector_id=review.get("connector_id"), decision="approved", metadata={"review_id": review_id, "reason": reason})
        return {"ok": True, "review": row, "connector": registered.get("connector")}

    def reject_review(self, review_id: str, *, actor: str = "MCPRegistry", reason: str = "manual_reject") -> dict[str, Any]:
        review = next((row for row in self.reviews() if row.get("review_id") == review_id), None)
        if review is None:
            return {"ok": False, "error": "review_not_found", "review_id": review_id}
        if review.get("status") != "pending":
            return {"ok": False, "error": "review_not_pending", "review_id": review_id, "status": review.get("status")}
        timestamp = utc_now()
        row = dict(review)
        row.update({"event": "mcp_review_rejected", "status": "rejected", "rejected_by": actor, "reason": reason, "updated_at": timestamp})
        append_chained_jsonl(self.review_path, row)
        self.audit("review_rejected", actor=actor, connector_id=review.get("connector_id"), decision="rejected", metadata={"review_id": review_id, "reason": reason})
        return {"ok": True, "review": row}

    def verify_review_integrity(self) -> dict[str, Any]:
        return verify_hash_chain(self.review_path)

    def verify_audit_integrity(self) -> dict[str, Any]:
        return verify_hash_chain(self.audit_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Text-first MCP connector registry with static security checks. Never stores raw secrets.")
    parser.add_argument("--registry-path", default="cpos/mcp_connectors.json")
    parser.add_argument("--audit-path", default="cpos/mcp_audit.jsonl")
    parser.add_argument("--review-path", default="cpos/mcp_reviews.jsonl")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-definition")
    check.add_argument("definition")
    check.add_argument("--json", action="store_true")
    register = sub.add_parser("register")
    register.add_argument("definition")
    register.add_argument("--confirm", action="store_true")
    register.add_argument("--actor", default="MCPRegistryCLI")
    register.add_argument("--json", action="store_true")
    list_cmd = sub.add_parser("list")
    list_cmd.add_argument("--json", action="store_true")
    disable = sub.add_parser("disable")
    disable.add_argument("connector_id")
    disable.add_argument("--reason", default="manual_disable")
    disable.add_argument("--actor", default="MCPRegistryCLI")
    disable.add_argument("--json", action="store_true")
    tool = sub.add_parser("check-tool")
    tool.add_argument("connector_id")
    tool.add_argument("tool_name")
    tool.add_argument("--purpose", default="cli_tool_check")
    tool.add_argument("--actor", default="MCPRegistryCLI")
    tool.add_argument("--json", action="store_true")
    verify_tls = sub.add_parser("verify-tls")
    verify_tls.add_argument("connector_id")
    verify_tls.add_argument("observation", help="path to a JSON file holding the TLS observation metadata")
    verify_tls.add_argument("--actor", default="MCPRegistryCLI")
    verify_tls.add_argument("--json", action="store_true")
    submit = sub.add_parser("submit-review")
    submit.add_argument("definition")
    submit.add_argument("--actor", default="MCPRegistryCLI")
    submit.add_argument("--json", action="store_true")
    reviews = sub.add_parser("reviews")
    reviews.add_argument("--status")
    reviews.add_argument("--json", action="store_true")
    approve = sub.add_parser("approve-review")
    approve.add_argument("review_id")
    approve.add_argument("--confirm", action="store_true")
    approve.add_argument("--reason")
    approve.add_argument("--actor", default="MCPRegistryCLI")
    approve.add_argument("--json", action="store_true")
    reject = sub.add_parser("reject-review")
    reject.add_argument("review_id")
    reject.add_argument("--reason", default="manual_reject")
    reject.add_argument("--actor", default="MCPRegistryCLI")
    reject.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify-audit")
    verify.add_argument("--json", action="store_true")
    verify_reviews = sub.add_parser("verify-reviews")
    verify_reviews.add_argument("--json", action="store_true")
    return parser


def _print(payload: Any, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if isinstance(payload, list):
        for item in payload:
            print(f"{item.get('connector_id')} status={item.get('status')} transport={item.get('transport')} approval={item.get('requires_human_approval')}")
        return
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    registry = MCPRegistry(args.registry_path, args.audit_path, args.review_path)
    if args.command == "check-definition":
        result = registry.check_definition(load_definition_text(args.definition), actor="MCPRegistryCLI")
        _print(result, as_json=args.json)
        if not result["ok"]:
            raise SystemExit(1)
        return
    if args.command == "register":
        result = registry.register(load_definition_text(args.definition), actor=args.actor, confirm=args.confirm)
        _print(result, as_json=args.json)
        if not result["ok"]:
            raise SystemExit(1)
        return
    if args.command == "list":
        _print([item.to_dict() for item in registry.load()], as_json=args.json)
        return
    if args.command == "disable":
        result = registry.disable(args.connector_id, actor=args.actor, reason=args.reason)
        _print(result, as_json=args.json)
        if not result["ok"]:
            raise SystemExit(1)
        return
    if args.command == "check-tool":
        result = registry.evaluate_tool_call(args.connector_id, args.tool_name, actor=args.actor, purpose=args.purpose)
        _print(result, as_json=args.json)
        if not result.get("ok"):
            raise SystemExit(1)
        return
    if args.command == "verify-tls":
        try:
            observation = load_observation_file(args.observation)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            _print({"ok": False, "decision": "tls_denied", "error": "observation_unreadable", "detail": type(exc).__name__}, as_json=args.json)
            raise SystemExit(1)
        result = registry.verify_tls(args.connector_id, observation, actor=args.actor)
        _print(result, as_json=args.json)
        if not result.get("ok"):
            raise SystemExit(1)
        return
    if args.command == "submit-review":
        result = registry.submit_review(load_definition_text(args.definition), actor=args.actor)
        _print(result, as_json=args.json)
        if not result.get("ok"):
            raise SystemExit(1)
        return
    if args.command == "reviews":
        _print(registry.reviews(status=args.status), as_json=args.json)
        return
    if args.command == "approve-review":
        result = registry.approve_review(args.review_id, actor=args.actor, reason=args.reason, confirm=args.confirm)
        _print(result, as_json=args.json)
        if not result.get("ok"):
            raise SystemExit(1)
        return
    if args.command == "reject-review":
        result = registry.reject_review(args.review_id, actor=args.actor, reason=args.reason)
        _print(result, as_json=args.json)
        if not result.get("ok"):
            raise SystemExit(1)
        return
    if args.command == "verify-audit":
        result = registry.verify_audit_integrity()
        _print(result, as_json=args.json)
        if not result.get("ok"):
            raise SystemExit(1)
        return
    if args.command == "verify-reviews":
        result = registry.verify_review_integrity()
        _print(result, as_json=args.json)
        if not result.get("ok"):
            raise SystemExit(1)
        return


if __name__ == "__main__":
    main()

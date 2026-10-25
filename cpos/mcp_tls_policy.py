"""Declarative TLS policy and fail-closed policy-checking of TLS observations for
MCP connectors.

IMPORTANT trust boundary — read before trusting this module's name: CPOS does
NOT perform TLS itself and does NOT independently verify certificates. It never
opens a socket, never validates a certificate signature or trust chain, and
cannot authenticate an observation or bind it to a specific handshake. All
evidence here is *asserted by the component that actually made the connection*
("the producer"). Fabricated passing metadata would pass. What this module gives
you is a way to (a) attach a declarative TLS policy to a remote connector and
validate its shape statically, and (b) check a producer-supplied TLS observation
against that policy, **fail-closed**: a missing observation, a missing/ill-typed
required field, an invalid policy, or any policy violation denies. It is a policy
gate over trusted producer-supplied metadata, not a certificate verifier.

Nothing here reads secret files, performs network I/O, or starts a process.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

# TLS versions we are willing to reason about, weakest -> strongest. Anything
# outside this set in an observation is treated as unknown and denied; a policy
# may only *raise* the floor to one of the >= 1.2 entries.
_TLS_ORDER = {"TLSv1.0": 0, "TLSv1.1": 1, "TLSv1.2": 2, "TLSv1.3": 3}
_MIN_ALLOWED_FLOOR = "TLSv1.2"
# Exact, anchored, UNAMBIGUOUS grammar: an optional "TLS"/"TLSv" prefix (no
# internal whitespace, so there is no backtracking) then 1.0-1.3. Rejects
# malformed tokens like "TLSVTLSV1.3". A length cap in _normalize_version is the
# first gate so an adversarial long string never reaches the engine at all.
_VERSION_RE = re.compile(r"\A(?:TLSV?)?(1\.[0-3])\Z", re.IGNORECASE)
_MAX_VERSION_LEN = 12  # longest valid spelling is "TLSv1.3" (7 chars)
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")

# Bounds so an oversized or adversarial observation cannot blow up normalization.
_MAX_CHAIN_ENTRIES = 64
_MAX_HOST_LEN = 253  # DNS name maximum

DEFAULT_MIN_VERSION = "TLSv1.2"
DEFAULT_REQUIRE_HOSTNAME_MATCH = True
DEFAULT_FORBID_KEY_LOGGING = True
DEFAULT_REQUIRE_OCSP_STAPLE = False
# Clock-skew tolerance for an OCSP staple's produced_at: a little in the future
# is normal clock drift, far in the future is not a staple we should trust.
_OCSP_SKEW_SECONDS = 300

_KNOWN_POLICY_KEYS = {
    "min_version",
    "pinned_spki_sha256",
    "pinned_intermediate_spki_sha256",
    "forbidden_issuers",
    "require_hostname_match",
    "forbid_key_logging",
    "require_ocsp_staple",
    "max_ocsp_staple_age_seconds",
}


def _finding(severity: str, code: str, message: str, field: str | None = None) -> dict[str, str]:
    item = {"severity": severity, "code": code, "message": message}
    if field:
        item["field"] = field
    return item


def _normalize_version(value: Any) -> str | None:
    """Map a TLS version string to a canonical ``TLSvX.Y`` token, or None.

    Uses an anchored grammar (not a global prefix strip), so only well-formed
    spellings like ``TLSv1.2`` / ``TLS1.2`` / ``1.2`` are accepted.
    """
    if not isinstance(value, str):
        return None
    token = value.strip()
    if len(token) > _MAX_VERSION_LEN:
        return None
    match = _VERSION_RE.match(token)
    if not match:
        return None
    canonical = f"TLSv{match.group(1)}"
    return canonical if canonical in _TLS_ORDER else None


def _collect_issuer_names(chain: Any) -> tuple[list[str], bool]:
    """Collect normalized issuer O/CN names from a cert chain observation.

    Returns ``(names, well_formed)``. ``well_formed`` is False if the chain is
    not a list, is over the size bound, contains a non-dict entry, or an O/CN
    attribute that is present but not a string. A caller that forbids issuers
    MUST deny when ``well_formed`` is False, so a malformed entry cannot smuggle
    a forbidden issuer past the check.
    """
    if not isinstance(chain, list):
        return ([], False)
    if len(chain) > _MAX_CHAIN_ENTRIES:
        return ([], False)
    names: list[str] = []
    well_formed = True
    for entry in chain:
        if not isinstance(entry, dict):
            well_formed = False
            continue
        for key in ("O", "CN"):
            if key not in entry:
                continue
            value = entry[key]
            if not isinstance(value, str):
                well_formed = False
                continue
            if value.strip():
                names.append(value.strip().casefold())
    return (names, well_formed)


def _collect_chain_spki(chain: Any) -> tuple[set[str], bool]:
    """Collect lowercased hex SPKI sha256 hashes from a ``chain_spki_sha256``
    observation (the SPKI hashes of the certs the producer saw in the presented
    chain).

    Returns ``(hashes, well_formed)``. ``well_formed`` is False if the value is
    not a list, is over the size bound, or contains an entry that is not a
    64-char hex sha256. A caller that pins intermediates MUST deny when
    ``well_formed`` is False, so a malformed entry cannot hide a missing pin.
    """
    if not isinstance(chain, list):
        return (set(), False)
    if len(chain) > _MAX_CHAIN_ENTRIES:
        return (set(), False)
    hashes: set[str] = set()
    well_formed = True
    for entry in chain:
        if not isinstance(entry, str):
            well_formed = False
            continue
        token = entry.strip().lower()
        if not _HEX64.match(token):
            well_formed = False
            continue
        hashes.add(token)
    return (hashes, well_formed)


def parse_tls_policy(policy: Any) -> dict[str, Any]:
    """Return the effective policy with defaults applied. Shape is NOT validated
    here (see ``check_tls_policy_definition``). ``verify_tls_observation`` runs
    that validation first and denies on error, so by the time this is used the
    policy is known well-formed."""
    policy = policy if isinstance(policy, dict) else {}
    pins = policy.get("pinned_spki_sha256") or []
    inter = policy.get("pinned_intermediate_spki_sha256") or []
    forbidden = policy.get("forbidden_issuers") or []
    max_age = policy.get("max_ocsp_staple_age_seconds")
    return {
        "min_version": _normalize_version(policy.get("min_version")) or DEFAULT_MIN_VERSION,
        "pinned_spki_sha256": [str(p).strip().lower() for p in pins] if isinstance(pins, list) else [],
        "pinned_intermediate_spki_sha256": [str(p).strip().lower() for p in inter] if isinstance(inter, list) else [],
        "forbidden_issuers": [str(i).strip().casefold() for i in forbidden if str(i).strip()] if isinstance(forbidden, list) else [],
        "require_hostname_match": bool(policy.get("require_hostname_match", DEFAULT_REQUIRE_HOSTNAME_MATCH)),
        "forbid_key_logging": bool(policy.get("forbid_key_logging", DEFAULT_FORBID_KEY_LOGGING)),
        "require_ocsp_staple": bool(policy.get("require_ocsp_staple", DEFAULT_REQUIRE_OCSP_STAPLE)),
        # Only a positive int (never a bool) is a meaningful max age; anything
        # else means "no freshness bound".
        "max_ocsp_staple_age_seconds": max_age if isinstance(max_age, int) and not isinstance(max_age, bool) and max_age > 0 else None,
    }


def check_tls_policy_definition(policy: Any) -> list[dict[str, str]]:
    """Static validation of a connector's ``tls_policy`` block. No connection is
    made. Returns findings (errors block registration). ``None`` means no policy
    was declared -- the caller decides whether to warn."""
    findings: list[dict[str, str]] = []
    if policy is None:
        return findings
    if not isinstance(policy, dict):
        findings.append(_finding("error", "tls_policy_invalid", "tls_policy must be an object", "tls_policy"))
        return findings

    for key in policy:
        if key not in _KNOWN_POLICY_KEYS:
            # Do not interpolate the raw key into the message; name it only via
            # the structured field path.
            findings.append(_finding("warning", "tls_policy_unknown_field", "an unknown tls_policy field is ignored", "tls_policy"))

    if "min_version" in policy:
        canonical = _normalize_version(policy.get("min_version"))
        if canonical is None:
            findings.append(_finding("error", "tls_min_version_invalid", f"min_version must be one of {sorted(_TLS_ORDER)}", "tls_policy.min_version"))
        elif _TLS_ORDER[canonical] < _TLS_ORDER[_MIN_ALLOWED_FLOOR]:
            findings.append(_finding("error", "tls_min_version_too_low", f"min_version must not be weaker than {_MIN_ALLOWED_FLOOR}", "tls_policy.min_version"))

    if "pinned_spki_sha256" in policy:
        pins = policy.get("pinned_spki_sha256")
        if not isinstance(pins, list):
            findings.append(_finding("error", "tls_pins_invalid", "pinned_spki_sha256 must be a list of lowercase hex sha256 strings", "tls_policy.pinned_spki_sha256"))
        elif not pins:
            findings.append(_finding("warning", "tls_pins_empty", "pinned_spki_sha256 is empty; no SPKI pin is enforced", "tls_policy.pinned_spki_sha256"))
        else:
            for pin in pins:
                if not isinstance(pin, str) or not _HEX64.match(pin.strip().lower()):
                    findings.append(_finding("error", "tls_pin_malformed", "each SPKI pin must be a 64-char hex sha256 of the DER SubjectPublicKeyInfo", "tls_policy.pinned_spki_sha256"))

    if "pinned_intermediate_spki_sha256" in policy:
        inter = policy.get("pinned_intermediate_spki_sha256")
        if not isinstance(inter, list):
            findings.append(_finding("error", "tls_intermediate_pins_invalid", "pinned_intermediate_spki_sha256 must be a list of lowercase hex sha256 strings", "tls_policy.pinned_intermediate_spki_sha256"))
        elif not inter:
            findings.append(_finding("warning", "tls_intermediate_pins_empty", "pinned_intermediate_spki_sha256 is empty; no intermediate SPKI pin is enforced", "tls_policy.pinned_intermediate_spki_sha256"))
        else:
            for pin in inter:
                if not isinstance(pin, str) or not _HEX64.match(pin.strip().lower()):
                    findings.append(_finding("error", "tls_intermediate_pin_malformed", "each intermediate SPKI pin must be a 64-char hex sha256 of the DER SubjectPublicKeyInfo", "tls_policy.pinned_intermediate_spki_sha256"))

    if "forbidden_issuers" in policy:
        forbidden = policy.get("forbidden_issuers")
        if not isinstance(forbidden, list) or any(not isinstance(i, str) or not i.strip() for i in forbidden):
            findings.append(_finding("error", "tls_forbidden_issuers_invalid", "forbidden_issuers must be a list of non-empty issuer O/CN strings", "tls_policy.forbidden_issuers"))

    for flag in ("require_hostname_match", "forbid_key_logging", "require_ocsp_staple"):
        if flag in policy and not isinstance(policy.get(flag), bool):
            findings.append(_finding("error", "tls_flag_invalid", f"{flag} must be a boolean", f"tls_policy.{flag}"))

    if "max_ocsp_staple_age_seconds" in policy:
        max_age = policy.get("max_ocsp_staple_age_seconds")
        if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age <= 0:
            findings.append(_finding("error", "tls_ocsp_max_age_invalid", "max_ocsp_staple_age_seconds must be a positive integer number of seconds", "tls_policy.max_ocsp_staple_age_seconds"))

    return findings


def verify_tls_observation(connector: Any, observation: Any, *, connector_url: str | None = None) -> dict[str, Any]:
    """Check a producer-supplied TLS observation against a connector's policy,
    fail-closed. See the module docstring for the trust boundary: this does not
    verify certificates, it enforces policy over metadata the producer asserts.

    ``connector`` may be a mapping or an object exposing ``tls_policy`` / ``url``.

    Observation fields (absence of one the policy needs is an error):
      - ``negotiated_version``: e.g. "TLSv1.3"
      - ``leaf_spki_sha256``: hex sha256 of the DER SubjectPublicKeyInfo
      - ``chain_spki_sha256``: list of hex sha256 SPKI of the certs in the
        presented chain (used for intermediate pinning)
      - ``chain_issuers``: list of {"O":..., "CN":...} issuer names
      - ``leaf_not_after``: ISO-8601 leaf expiry (``Z`` or offset)
      - ``hostname_matched``: bool, cert matched the host
      - ``keylog_disabled``: bool, no TLS key log was written
      - ``observed_host``: the host actually connected to
      - ``ocsp_stapled``: bool, an OCSP response was stapled to the handshake
      - ``ocsp_status``: "good" / "revoked" / "unknown" (producer's OCSP result)
      - ``ocsp_produced_at`` / ``ocsp_next_update``: ISO-8601 staple timestamps
    """
    raw_policy = _attr(connector, "tls_policy")
    url = connector_url if connector_url is not None else _attr(connector, "url")

    # Fail-closed on an invalid policy: the public primitive must not silently
    # apply weakened defaults for a policy that would be rejected at registration.
    policy_findings = check_tls_policy_definition(raw_policy)
    policy_errors = [f for f in policy_findings if f["severity"] == "error"]
    if policy_errors:
        return {"ok": False, "decision": "tls_denied", "findings": policy_errors, "policy": None}

    policy = parse_tls_policy(raw_policy)
    # Carry forward any non-error policy findings (e.g. empty-pin warning).
    findings: list[dict[str, str]] = [f for f in policy_findings if f["severity"] != "error"]

    if not isinstance(observation, dict) or not observation:
        findings.append(_finding("error", "tls_observation_required", "a TLS observation is required to verify the connection", "observation"))
        return {"ok": False, "decision": "tls_denied", "findings": findings, "policy": policy}

    # --- negotiated protocol version ---
    negotiated = _normalize_version(observation.get("negotiated_version"))
    if negotiated is None:
        findings.append(_finding("error", "tls_version_unknown", "negotiated_version is missing or not a recognized TLS version", "observation.negotiated_version"))
    elif _TLS_ORDER[negotiated] < _TLS_ORDER[policy["min_version"]]:
        findings.append(_finding("error", "tls_version_too_low", "negotiated TLS version is weaker than the policy minimum", "observation.negotiated_version"))

    # --- SPKI pinning ---
    if policy["pinned_spki_sha256"]:
        observed_pin = observation.get("leaf_spki_sha256")
        if not isinstance(observed_pin, str) or not observed_pin.strip():
            findings.append(_finding("error", "tls_spki_missing", "policy pins SPKI but observation has no leaf_spki_sha256", "observation.leaf_spki_sha256"))
        elif observed_pin.strip().lower() not in policy["pinned_spki_sha256"]:
            findings.append(_finding("error", "tls_spki_mismatch", "leaf SPKI does not match any pinned_spki_sha256 (possible MITM or cert change)", "observation.leaf_spki_sha256"))

    # --- forbidden issuers (e.g. a revoked/compromised intermediate CA) ---
    if policy["forbidden_issuers"]:
        observed_issuers, well_formed = _collect_issuer_names(observation.get("chain_issuers"))
        if not well_formed:
            # A malformed/oversized chain cannot be trusted to not hide a
            # forbidden issuer -> deny rather than skip.
            findings.append(_finding("error", "tls_chain_malformed", "chain_issuers is missing, malformed, or too large to evaluate", "observation.chain_issuers"))
        elif not observed_issuers:
            findings.append(_finding("error", "tls_chain_issuers_missing", "policy forbids issuers but observation carries no chain_issuers to check", "observation.chain_issuers"))
        elif set(observed_issuers) & set(policy["forbidden_issuers"]):
            findings.append(_finding("error", "tls_issuer_forbidden", "certificate chain includes a forbidden issuer", "observation.chain_issuers"))

    # --- intermediate SPKI pinning (pin a known-good issuing CA key) ---
    # Leaf pinning alone breaks on legitimate leaf-key rotation; pinning the
    # issuing CA's SPKI survives that while still rejecting a chain built by a
    # different (rogue) intermediate. At least one pinned intermediate SPKI must
    # appear among the chain SPKIs the producer reports.
    if policy["pinned_intermediate_spki_sha256"]:
        chain_spki, well_formed = _collect_chain_spki(observation.get("chain_spki_sha256"))
        if not well_formed:
            # A malformed/oversized/absent chain cannot be trusted to not hide a
            # missing pin -> deny rather than skip.
            findings.append(_finding("error", "tls_intermediate_chain_malformed", "chain_spki_sha256 is missing, malformed, or too large to evaluate", "observation.chain_spki_sha256"))
        elif not chain_spki:
            findings.append(_finding("error", "tls_intermediate_spki_missing", "policy pins an intermediate SPKI but observation carries no chain_spki_sha256 to check", "observation.chain_spki_sha256"))
        elif not (set(policy["pinned_intermediate_spki_sha256"]) & chain_spki):
            findings.append(_finding("error", "tls_intermediate_spki_mismatch", "no pinned intermediate SPKI is present in the presented chain (possible rogue issuing CA)", "observation.chain_spki_sha256"))

    # --- hostname match: require both the asserted flag AND a matching host ---
    if policy["require_hostname_match"]:
        if observation.get("hostname_matched") is not True:
            findings.append(_finding("error", "tls_hostname_unverified", "observation does not assert hostname_matched is true", "observation.hostname_matched"))
        observed_host = observation.get("observed_host")
        if not isinstance(observed_host, str) or not observed_host.strip() or len(observed_host.strip()) > _MAX_HOST_LEN:
            # hostname_matched=true alone does not bind the connection to the
            # connector's intended host -> require the host and compare it.
            findings.append(_finding("error", "tls_observed_host_missing", "observation must carry a valid observed_host when hostname match is required", "observation.observed_host"))
        else:
            expected_host = urlparse(str(url)).hostname if url else None
            if not expected_host:
                findings.append(_finding("error", "tls_expected_host_unknown", "connector URL has no host to match the observation against", "url"))
            # Compare with ASCII-style lower(), NOT casefold(): casefold maps
            # e.g. "ß" -> "ss", so distinct hosts (faß vs fass) would collide.
            # lower() does not do that folding, so distinct hosts stay distinct.
            elif observed_host.strip().lower() != expected_host.strip().lower():
                findings.append(_finding("error", "tls_host_divergence", "observed_host does not match the connector URL host", "observation.observed_host"))

    # --- key logging ---
    if policy["forbid_key_logging"] and observation.get("keylog_disabled") is not True:
        findings.append(_finding("error", "tls_keylog_not_disabled", "observation does not assert keylog_disabled is true (TLS key logging must be off)", "observation.keylog_disabled"))

    # --- expiry: expired is a hard error; unknown is a reviewable warning ---
    not_after_raw = observation.get("leaf_not_after")
    if not_after_raw is None:
        findings.append(_finding("warning", "tls_expiry_unknown", "observation has no leaf_not_after; certificate expiry could not be verified", "observation.leaf_not_after"))
    else:
        not_after = _parse_iso(not_after_raw)
        if not_after is None:
            findings.append(_finding("warning", "tls_expiry_unparseable", "leaf_not_after is not a parseable ISO-8601 timestamp", "observation.leaf_not_after"))
        elif not_after <= datetime.now(timezone.utc):
            findings.append(_finding("error", "tls_certificate_expired", "leaf certificate is expired", "observation.leaf_not_after"))

    # --- revocation (OCSP staple assertion from the producer) ---
    # A revoked status is ALWAYS fatal, even when the policy does not require a
    # staple: if the producer went to the trouble of telling us the cert is
    # revoked, never proceed. Requiring a staple additionally demands a fresh
    # "good" status. CPOS does not fetch OCSP/CRL itself (it never connects);
    # this governs a revocation result the producer asserts.
    now = datetime.now(timezone.utc)
    ocsp_status = observation.get("ocsp_status")
    if ocsp_status == "revoked":
        findings.append(_finding("error", "tls_certificate_revoked", "observation reports the certificate as revoked (OCSP)", "observation.ocsp_status"))

    if policy["require_ocsp_staple"]:
        if observation.get("ocsp_stapled") is not True:
            findings.append(_finding("error", "tls_ocsp_staple_required", "policy requires a stapled OCSP response but observation does not assert ocsp_stapled is true", "observation.ocsp_stapled"))
        elif ocsp_status != "good":
            # "revoked" is already flagged above; here catch unknown/missing/ill-typed.
            if ocsp_status != "revoked":
                findings.append(_finding("error", "tls_ocsp_status_not_good", "policy requires a good OCSP status but the stapled status is missing, unknown, or unrecognized", "observation.ocsp_status"))
        else:
            # status is good; enforce freshness if a max age is set.
            max_age = policy["max_ocsp_staple_age_seconds"]
            if max_age is not None:
                produced = _parse_iso(observation.get("ocsp_produced_at"))
                if produced is None:
                    findings.append(_finding("error", "tls_ocsp_produced_at_missing", "a max OCSP staple age is set but observation has no parseable ocsp_produced_at", "observation.ocsp_produced_at"))
                else:
                    age = (now - produced).total_seconds()
                    if age < -_OCSP_SKEW_SECONDS:
                        # Produced well in the future -> not a staple we trust; a
                        # negative age must never slip past the max-age check.
                        findings.append(_finding("error", "tls_ocsp_produced_at_in_future", "ocsp_produced_at is in the future beyond clock-skew tolerance", "observation.ocsp_produced_at"))
                    elif age > max_age:
                        findings.append(_finding("error", "tls_ocsp_staple_stale", "stapled OCSP response is older than the policy maximum", "observation.ocsp_produced_at"))
                # next_update is optional, but if PRESENT it must be valid: a
                # malformed value must deny, not be silently ignored.
                if "ocsp_next_update" in observation:
                    next_update = _parse_iso(observation.get("ocsp_next_update"))
                    if next_update is None:
                        findings.append(_finding("error", "tls_ocsp_next_update_invalid", "ocsp_next_update is present but not a parseable ISO-8601 timestamp", "observation.ocsp_next_update"))
                    elif next_update <= now:
                        findings.append(_finding("error", "tls_ocsp_staple_expired", "stapled OCSP response is past its next_update", "observation.ocsp_next_update"))

    ok = not any(f["severity"] == "error" for f in findings)
    return {"ok": ok, "decision": "tls_allowed" if ok else "tls_denied", "findings": findings, "policy": policy}


def _attr(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed

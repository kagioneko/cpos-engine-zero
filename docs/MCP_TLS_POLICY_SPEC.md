# MCP TLS Policy & Observation Checking

Status: round 5 — declarative policy + fail-closed verification **primitive**,
wired into both runtime gates, with leaf **and** intermediate (issuing-CA) SPKI
pinning and producer-asserted OCSP revocation gating. `request_mcp_execution` and `request_mcp_capability_probe` each
consult a TLS observation for a remote connector that declares a `tls_policy`:
a missing or policy-failing observation denies the request fail-closed (see
"Runtime gates" below). CPOS still never opens a socket; a reference *producer*
that does (`examples/tls_observer.py`) lives outside the package.

## Why

CPOS hardened the *definition-time* check of MCP connectors (https-only,
host required, credentials rejected in the URL authority, and a heuristic
*warning* on credential-looking query parameters). That protects what is
written down, not what happens on the wire. The 2026-10 wave
of transport-interception issues — a compromised intermediate CA (eMudhra),
TLS key-log exfiltration (`SSLKEYLOGFILE`), downgrade and MITM — is a *runtime*
threat class. This adds the governance primitive for it.

CPOS never opens a socket. The registry, probe and execution adapters are all
metadata-only, and this module keeps that contract:

- A **declarative TLS policy** can be attached to a remote (https/sse)
  connector. It is validated statically during connector review — no
  connection is made.
- **`verify_tls_observation`** checks a TLS *observation* — handshake metadata
  that whatever actually performed the connection (the "producer") presents
  back — against the policy, **fail-closed**. A missing observation, a
  missing/ill-typed required field, an invalid policy, or any policy violation
  **denies**.

### Trust boundary (read this before trusting the name)

This is a **policy gate over producer-supplied metadata, not a certificate
verifier**. CPOS does **not** perform the TLS handshake, does **not** validate
certificate signatures or trust chains, and **cannot** authenticate an
observation or bind it to a specific handshake. Every field is *asserted by the
producer*; fabricated passing metadata would pass. The security value is real
only when the producer is a trusted component that genuinely performed the
checks it reports (negotiated version, SPKI hash, hostname match, key-log off).
CPOS holds that producer-supplied evidence to the connector's declared policy
and fails closed when it falls short.

## Policy block (`tls_policy` on a connector definition)

Remote transports only (`https`, `sse`). Ignored for `stdio` (warned).

| field | type | default | meaning |
|---|---|---|---|
| `min_version` | string | `TLSv1.2` | Minimum negotiated version. May only *raise* the floor; `< TLSv1.2` is rejected at definition time. |
| `pinned_spki_sha256` | list[hex] | none | Leaf SPKI pins: lowercase hex SHA-256 of the DER `SubjectPublicKeyInfo`. Public-key pinning survives certificate renewal as long as the key is unchanged. |
| `pinned_intermediate_spki_sha256` | list[hex] | none | Intermediate (issuing-CA) SPKI pins, same hex format. At least one must appear among the chain's SPKIs. Pinning the issuing CA's key survives legitimate leaf-key rotation while still rejecting a chain built by a different (rogue) intermediate. |
| `forbidden_issuers` | list[str] | none | Issuer `O`/`CN` names to reject anywhere in the chain (e.g. a revoked CA). Exact, case-insensitive name match — operator supplies the exact name, no substring heuristics. |
| `require_hostname_match` | bool | `true` | The observation must assert the certificate matched the host. |
| `forbid_key_logging` | bool | `true` | The observation must assert no TLS key log was written. |
| `require_ocsp_staple` | bool | `false` | The observation must assert a stapled OCSP response with a `good` status. Opt-in, since not every endpoint staples. |
| `max_ocsp_staple_age_seconds` | int | none | When set (with `require_ocsp_staple`), the staple's `ocsp_produced_at` must be within this age and its `ocsp_next_update` must not be in the past. |

A remote connector with no `tls_policy` is accepted but **warned**
(`tls_policy_absent`) — pinning and a floor are recommended.

## Observation schema (supplied by the connecting component)

```json
{
  "negotiated_version": "TLSv1.3",
  "leaf_spki_sha256": "<hex sha256 of DER SubjectPublicKeyInfo>",
  "chain_spki_sha256": ["<hex sha256 SPKI of each cert in the presented chain>"],
  "chain_issuers": [{"O": "Example CA", "CN": "Example Root"}],
  "leaf_not_after": "2026-12-31T23:59:59Z",
  "hostname_matched": true,
  "keylog_disabled": true,
  "observed_host": "mcp.example.test",
  "ocsp_stapled": true,
  "ocsp_status": "good",
  "ocsp_produced_at": "2026-10-25T00:00:00Z",
  "ocsp_next_update": "2026-10-26T00:00:00Z"
}
```

Fail-closed rules:

- Invalid policy (would be rejected at registration) → the policy errors, deny — the runtime does not silently apply weakened defaults.
- No observation / not an object → `tls_observation_required` (deny).
- Version missing or unrecognized → `tls_version_unknown` (deny); below floor → `tls_version_too_low`. The version grammar is anchored, so malformed tokens (e.g. `TLSVTLSV1.3`) are unrecognized, not coerced.
- Policy pins SPKI but observation lacks it → `tls_spki_missing`; no match → `tls_spki_mismatch` (deny).
- Policy pins an intermediate SPKI but the chain is missing/malformed/oversized → `tls_intermediate_chain_malformed`; well-formed but empty → `tls_intermediate_spki_missing`; no pinned intermediate present in the chain → `tls_intermediate_spki_mismatch` (all deny). As with issuer matching, a chain that cannot be evaluated is denied, never skipped. At definition time an invalid list → `tls_intermediate_pins_invalid`, a malformed pin → `tls_intermediate_pin_malformed`, an empty list → `tls_intermediate_pins_empty` (warning only).
- Policy forbids issuers but the chain is missing/malformed/oversized → `tls_chain_malformed`; well-formed but empty → `tls_chain_issuers_missing`; a forbidden issuer present → `tls_issuer_forbidden` (all deny). A malformed chain is denied, never skipped, so it cannot hide a forbidden issuer.
- `require_hostname_match`: `hostname_matched` not exactly `true` → `tls_hostname_unverified`; a missing/ill-typed `observed_host` → `tls_observed_host_missing`; a connector URL with no host → `tls_expected_host_unknown`; `observed_host` ≠ URL host → `tls_host_divergence` (all deny). The asserted flag alone is not enough — a valid `observed_host` matching the connector URL host is also required.
- `forbid_key_logging` and `keylog_disabled` not exactly `true` → `tls_keylog_not_disabled` (deny).
- Revocation (OCSP staple asserted by the producer; CPOS never fetches OCSP/CRL itself): an `ocsp_status` of `revoked` → `tls_certificate_revoked` (deny) **always**, even without `require_ocsp_staple` — a producer-reported revocation is never overridden. With `require_ocsp_staple`: a missing/false `ocsp_stapled` → `tls_ocsp_staple_required`; a status that is not `good` (unknown/missing) → `tls_ocsp_status_not_good`. With `max_ocsp_staple_age_seconds` set: a missing/unparseable `ocsp_produced_at` → `tls_ocsp_produced_at_missing`; one more than a small clock-skew in the future → `tls_ocsp_produced_at_in_future`; one older than the max → `tls_ocsp_staple_stale`; an `ocsp_next_update` that is present but unparseable → `tls_ocsp_next_update_invalid`, or in the past → `tls_ocsp_staple_expired` (all deny). At definition time a non-bool `require_ocsp_staple` → `tls_flag_invalid`, a non-positive-int `max_ocsp_staple_age_seconds` → `tls_ocsp_max_age_invalid`.
- Expired leaf → `tls_certificate_expired` (deny). Expiry absent/unparseable → warning only (`tls_expiry_unknown` / `tls_expiry_unparseable`): CPOS flags that it could not verify expiry rather than assuming either way.
- Finding messages never echo observation-supplied values (hosts, issuer names); they name the offending field by its structured path only.

## CLI

```
python -m cpos.mcp_registry verify-tls <connector_id> <observation.json> [--json]
```

Loads the registered connector, runs `verify_tls_observation`, appends a
`tls_observation_verified` row to the hash-chained audit log, and exits non-zero
on deny. `stdio` connectors return `tls_not_applicable`. The observation file is
read with a bounded read: it is opened `O_NONBLOCK` (so *opening* a
FIFO/socket cannot hang) and validated with `fstat` on the opened descriptor —
a non-regular path (FIFO/socket/device/dir) is rejected before any read. A
regular file is then read up to 256 KiB + 1 bytes and rejected as too large
*after* that bounded read but before decoding, so it cannot exhaust memory.
(`O_NONBLOCK` guards the open against a blocking special file; it does not bound
arbitrary filesystem latency when reading a regular file.)

## Runtime gates

Both runtime entry points — tool execution (`request_mcp_execution`) and
capability probing (`request_mcp_capability_probe`) — enforce the policy with
the same fail-closed TLS gate, each still a metadata-only dry-run (CPOS never
runs the tool, never starts a server, and never opens the socket):

- The gate applies **only** to a remote (non-`stdio`) connector that declares a
  `tls_policy`. A `stdio` connector, or a remote connector with no policy, is
  not gated here — an absent policy is a definition-time warning, not a
  runtime block.
- For a gated connector, a **missing** observation denies with
  `tls_observation_required`; an observation that **fails** the policy denies
  with `tls_execution_blocked` (execution) or `tls_probe_blocked` (probe) and
  the structured `tls_finding_codes`. Both are fail-closed and are audited
  (`execution_request_denied` / `probe_denied`, plus `tls_observation_verified`
  from the verifier); every fail-closed denial is audited even in the rare
  window where the connector disappears before the verifier can audit, and no
  dry-run task/review is scheduled on a denial.
- On a passing observation the dry-run proceeds and its Task Tape payload
  carries a `tls_verification` summary — the decision and finding codes and the
  boolean result **only**, never observation-supplied values (host, SPKI, …).
- HTTP: `POST /mcp/executions/dry-run` and `POST /mcp/probes/dry-run` each
  accept an optional `tls_observation` object alongside the usual fields.

## Producing an observation (outside CPOS)

`examples/tls_observer.py` is a reference *producer*: it opens a socket, performs
the TLS handshake with the stdlib `ssl`, and extracts the SPKI hashes, issuer
names, and expiry with `cryptography`, emitting an observation JSON in exactly
the shape above. CPOS never runs this itself — it lives in `examples/` precisely
because it connects. Its output pipes straight into `verify-tls`:

```
python examples/tls_observer.py mcp.example.test 443 > obs.json
python -m cpos.mcp_registry verify-tls <connector_id> obs.json
```

It never writes a TLS key log and refuses to run if `SSLKEYLOGFILE` is set, so
`keylog_disabled` cannot be silently false. With `--insecure` it skips
verification and therefore reports `hostname_matched: false` — a producer must
never assert a match it did not make. `--timeout` bounds the TCP connect and
handshake (DNS resolution is governed by the OS resolver).

By default it reports the **leaf** only, so `chain_spki_sha256` carries the leaf
certificate alone: the stdlib exposes no portable full-chain accessor before
Python 3.13. Pass `--full-chain` to populate `chain_spki_sha256` /
`chain_issuers` with the full chain — this is what
`pinned_intermediate_spki_sha256` needs:

```
python examples/tls_observer.py mcp.example.test 443 --full-chain > obs.json
```

Here openssl `s_client -showcerts` is used only to *fetch* the certificates the
peer presents on the wire (which the stdlib cannot expose pre-3.13). That raw
bag is not trusted: the producer then **cryptographically builds and verifies**
the path from the handshake-verified leaf to a trust anchor and reports the
SPKIs/issuers of that **verified path only**. A hostile server therefore cannot
slip an unrelated appended CA's SPKI into `chain_spki_sha256` — a cert that is
not on the valid path is never reported, so intermediate pinning over the
reported chain cannot be fooled. Verification failure, an untrusted anchor,
`--insecure` (incompatible), or openssl being missing/slow/erroring are all
clean fail-closed errors, never a silent degrade to leaf-only; the fetch is
bounded in time, output size, and certificate count. The same trust boundary
applies: CPOS's gate is only as strong as the producer that genuinely performed
these checks.

## Scope / non-goals

- CPOS still does not connect. Producing a real observation (doing the TLS
  handshake, computing the SPKI hash, confirming the key log is off) is the job
  of the executing component, not CPOS. A reference producer lives at
  `examples/tls_observer.py` (see "Producing an observation" below) — it is
  deliberately *outside* the CPOS package because it opens a socket.
- Revocation: CPOS does not fetch CRL/OCSP (it never connects). It can gate a
  revocation result the *producer* staples and asserts (`require_ocsp_staple` /
  `max_ocsp_staple_age_seconds`, and a `revoked` status always denies), but it
  cannot discover revocation on its own. `forbidden_issuers` remains a coarse,
  operator-driven block for known-bad CAs, not a revocation service.
- Full-chain policy covers issuer-name matching, leaf SPKI pinning, and
  intermediate (issuing-CA) SPKI pinning. It still matches a producer-reported
  chain against pins/names and does not itself build or cryptographically
  verify the chain (same trust boundary as the rest of the module).
- The execution gate judges a producer-supplied observation; it does not bind
  that observation to a specific live handshake (same trust boundary as the
  verifier). A trusted producer that genuinely performed the TLS checks is still
  required for the gate to carry real security value.

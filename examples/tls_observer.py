#!/usr/bin/env python3
"""TLS observation producer — OUTSIDE the CPOS trust boundary.

⚠️  This example OPENS A SOCKET and performs a real TLS handshake. CPOS itself
never does this. The whole point of ``cpos.mcp_tls_policy`` is that CPOS judges a
TLS *observation* supplied by a trusted producer and never connects on its own.
This module is a reference *producer*: it connects to a host, inspects the TLS
handshake and certificate chain, and emits an observation JSON in exactly the
shape ``cpos.mcp_tls_policy.verify_tls_observation`` consumes. Its output is the
evidence CPOS then checks against a connector's declared ``tls_policy``.

Trust boundary: the security value of the CPOS gate is only as good as this
producer. Run it as (or inside) the trusted component that genuinely performs
the connection you want governed; a compromised producer can fabricate a passing
observation, exactly as the spec's trust-boundary note says.

Dependencies: the standard-library ``ssl`` for the handshake and
``cryptography`` (already a project dependency) to extract SPKI hashes, issuer
names, and expiry from the DER certificates. It never writes a TLS key log and
refuses to run if ``SSLKEYLOGFILE`` is set, so a stray key log cannot silently
make ``keylog_disabled`` false. No secrets are read or printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import socket
import ssl
import sys
from datetime import timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

_DEFAULT_TIMEOUT = 10.0


class TLSObserverError(RuntimeError):
    """The observation could not be produced (connection, handshake, or a
    refusal such as SSLKEYLOGFILE being set). Fail loudly rather than emit a
    half-populated observation the gate might misread."""


def _spki_sha256(cert: x509.Certificate) -> str:
    """Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo — the same quantity
    ``pinned_spki_sha256`` / ``pinned_intermediate_spki_sha256`` pin."""
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _issuer_name(cert: x509.Certificate) -> dict[str, str]:
    out: dict[str, str] = {}
    for oid, key in ((NameOID.ORGANIZATION_NAME, "O"), (NameOID.COMMON_NAME, "CN")):
        attrs = cert.issuer.get_attributes_for_oid(oid)
        if attrs:
            value = attrs[0].value
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            out[key] = str(value)
    return out


def observe_tls(
    host: str,
    port: int,
    *,
    server_hostname: str | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    cafile: str | None = None,
    insecure: bool = False,
) -> dict[str, Any]:
    """Connect to ``host:port``, perform a TLS handshake, and return an
    observation dict shaped for ``verify_tls_observation``.

    ``insecure=True`` skips certificate/hostname verification. Because the
    connection was then NOT verified, the observation reports
    ``hostname_matched: False`` — the producer must not assert a match it did not
    make. Use it only to inspect an endpoint, never to feed a gate you trust.

    ``timeout`` (seconds, finite and > 0) is applied to the TCP connect and then
    to the TLS handshake as separate budgets, so the worst-case wall-clock is a
    small multiple of it, not a single total. It does NOT bound DNS name
    resolution, which is governed by the OS resolver.

    This reference producer reports the **leaf** certificate's SPKI and issuer.
    ``chain_spki_sha256`` therefore carries the leaf only: the stdlib does not
    expose the intermediate chain portably (pre-3.13 has no accessor at all), so
    rather than ship an untested, version-specific accessor that could silently
    degrade, full-chain capture is left to a production producer (e.g. one built
    on a newer runtime's ``get_unverified_chain`` or on OpenSSL). Intermediate
    pinning (``pinned_intermediate_spki_sha256``) needs such a producer.
    """
    if os.environ.get("SSLKEYLOGFILE"):
        # Refuse rather than silently report keylog_disabled while OpenSSL writes
        # a key log for this very process.
        raise TLSObserverError("refusing to run with SSLKEYLOGFILE set; a TLS key log would be written")

    # Validate the timeout before it reaches socket calls, where a bad value
    # raises a bare ValueError/OverflowError whose traceback would leak source
    # paths. The float() conversion is itself guarded: an enormous int (e.g.
    # 10**1000) overflows when turned into a float, so normalize that too.
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TLSObserverError("timeout must be a finite number greater than 0")
    try:
        timeout_f = float(timeout)
    except (OverflowError, ValueError) as exc:
        raise TLSObserverError("timeout is out of range") from exc
    if not math.isfinite(timeout_f) or timeout_f <= 0:
        raise TLSObserverError("timeout must be a finite number greater than 0")
    timeout = timeout_f

    sni = server_hostname or host

    # Build the context inside the guard so a bad --cafile surfaces as a clean
    # TLSObserverError (class name only) instead of a traceback that would echo
    # the file path to stderr.
    try:
        context = ssl.create_default_context(cafile=cafile)
    except (OSError, ssl.SSLError) as exc:
        raise TLSObserverError(f"could not load CA material: {type(exc).__name__}") from exc
    # We never enable key logging; leave context.keylog_filename unset.
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                negotiated = ssock.version()
                leaf_der = ssock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, OverflowError) as exc:
        # Name the failure class only; never echo host/cert bytes or paths.
        # OverflowError: a finite but absurdly large timeout the C socket layer
        # cannot represent — normalize it instead of leaking a traceback.
        raise TLSObserverError(f"TLS handshake failed: {type(exc).__name__}") from exc

    if not leaf_der:
        raise TLSObserverError("no peer certificate was presented")

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except ValueError as exc:
        raise TLSObserverError(f"peer certificate could not be parsed: {type(exc).__name__}") from exc
    not_after = leaf.not_valid_after_utc.astimezone(timezone.utc).replace(microsecond=0)

    return {
        "negotiated_version": negotiated,
        "leaf_spki_sha256": _spki_sha256(leaf),
        "chain_spki_sha256": [_spki_sha256(leaf)],
        "chain_issuers": [_issuer_name(leaf)],
        "leaf_not_after": not_after.isoformat().replace("+00:00", "Z"),
        # When verification is on, the handshake only succeeds if the cert
        # matched the host; insecure mode made no such check.
        "hostname_matched": not insecure,
        "keylog_disabled": True,
        "observed_host": sni,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Produce a CPOS TLS observation JSON by connecting to a host (opens a socket; outside the CPOS trust boundary).",
    )
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--server-hostname", default=None, help="SNI / name to verify (defaults to host)")
    parser.add_argument("--cafile", default=None, help="PEM CA bundle to trust instead of the system store")
    parser.add_argument(
        "--timeout",
        type=float,
        default=_DEFAULT_TIMEOUT,
        help="seconds (finite, > 0); bounds the TCP connect and the TLS handshake separately, not DNS",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip verification (reports hostname_matched=false; never feed a trusted gate)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        observation = observe_tls(
            args.host,
            args.port,
            server_hostname=args.server_hostname,
            timeout=args.timeout,
            cafile=args.cafile,
            insecure=args.insecure,
        )
    except TLSObserverError as exc:
        # Error text names the failure class only, never certificate or host
        # bytes echoed back.
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    # stdout is pure JSON so it can be piped straight into `verify-tls`.
    print(json.dumps(observation, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

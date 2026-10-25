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
import select
import socket
import ssl
import subprocess  # nosec B404 - used with an argv list and no shell (see _fetch_presented_certs)
import sys
import time
from datetime import timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

_DEFAULT_TIMEOUT = 10.0
# Bounds for the full-chain capture so a hostile or broken peer cannot make the
# producer parse an unbounded amount of output.
_MAX_CHAIN_ENTRIES = 16
_MAX_OPENSSL_STDOUT = 1 << 20  # 1 MiB of s_client output is far more than any real chain
_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_PEM_END = "-----END CERTIFICATE-----"


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


def _safe_arg(value: str, label: str) -> str:
    """Reject values that could be mistaken for an openssl option or smuggle a
    control character. Inputs go into an argv list (never a shell), so this
    guards against *option* injection (e.g. a host of ``-foo``), not shell
    injection."""
    if not isinstance(value, str) or not value or value.startswith("-"):
        raise TLSObserverError(f"invalid {label}")
    if any(ord(ch) < 0x20 or ch in "\x7f" for ch in value):
        raise TLSObserverError(f"invalid {label}")
    return value


def _extract_pem_blocks(text: str, limit: int) -> list[str]:
    """Pull PEM certificate blocks out of openssl output with a single linear
    line scan (no regex), so a malformed blob cannot trigger quadratic
    backtracking. Stops after ``limit`` blocks."""
    blocks: list[str] = []
    current: list[str] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == _PEM_BEGIN:
            current = [line]
        elif stripped == _PEM_END and current is not None:
            current.append(line)
            blocks.append("\n".join(current))
            current = None
            if len(blocks) >= limit:
                break
        elif current is not None:
            current.append(line)
    return blocks


def _run_bounded(argv: list[str], timeout: float) -> tuple[bytes, int]:
    """Run ``argv`` (no shell) and return ``(stdout_bytes, returncode)`` with
    BOTH memory and wall-clock bounded: stdout is read incrementally and capped
    at ``_MAX_OPENSSL_STDOUT + 1`` bytes, stderr is discarded (not buffered), and
    a per-read deadline kills the process. Avoids ``subprocess.run`` /
    ``communicate`` which buffer stdout and stderr in memory without limit."""
    try:
        proc = subprocess.Popen(  # nosec B603 - fixed argv, validated inputs, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        # FileNotFoundError (openssl absent), PermissionError, etc. — class name
        # only, never the path.
        raise TLSObserverError(f"could not run openssl s_client: {type(exc).__name__}") from exc

    chunks: list[bytes] = []
    total = 0
    cap = _MAX_OPENSSL_STDOUT + 1
    deadline = time.monotonic() + timeout
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while total <= cap:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TLSObserverError("openssl s_client timed out")
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                raise TLSObserverError("openssl s_client timed out")
            data = os.read(fd, 65536)
            if not data:  # EOF
                break
            chunks.append(data)
            total += len(data)
    finally:
        proc.stdout.close() if proc.stdout else None
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
    return (b"".join(chunks), proc.returncode if proc.returncode is not None else -1)


def _fetch_presented_certs(host: str, port: int, sni: str, timeout: float) -> list[x509.Certificate]:
    """Fetch the certificates the peer *presents* on the wire via
    ``openssl s_client -showcerts``.

    openssl is only a portable way to SEE the certs (the stdlib ``ssl`` module
    cannot expose intermediates before Python 3.13). The returned list is the
    raw, UNVERIFIED bag as sent — it is NOT trusted here; the caller feeds it to
    ``_build_verified_chain`` which cryptographically builds and verifies the
    actual path. Failures (openssl missing/unrunnable, timeout, no/oversized
    output) raise ``TLSObserverError`` rather than silently degrading.
    """
    _safe_arg(host, "host")
    _safe_arg(sni, "server hostname")
    argv = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", sni,
        "-showcerts",
    ]
    stdout, returncode = _run_bounded(argv, timeout)
    if len(stdout) > _MAX_OPENSSL_STDOUT:
        raise TLSObserverError("openssl output was implausibly large")
    text = stdout.decode("utf-8", errors="replace")
    blocks = _extract_pem_blocks(text, _MAX_CHAIN_ENTRIES + 1)
    if not blocks:
        # Surface a nonzero exit here so it is not silently ignored.
        raise TLSObserverError(f"openssl presented no certificates (exit {returncode})")
    if len(blocks) > _MAX_CHAIN_ENTRIES:
        raise TLSObserverError("peer presented an implausibly long chain")
    certs: list[x509.Certificate] = []
    for block in blocks:
        try:
            certs.append(x509.load_pem_x509_certificate(block.encode("ascii", errors="ignore")))
        except ValueError as exc:
            raise TLSObserverError(f"a presented certificate could not be parsed: {type(exc).__name__}") from exc
    return certs


def _load_trust_anchors(cafile: str | None) -> list[x509.Certificate]:
    """Load trust anchors from ``cafile`` (PEM, possibly many) or the system
    store. Chain verification is only as meaningful as these anchors."""
    try:
        if cafile is not None:
            with open(cafile, "rb") as fh:
                return list(x509.load_pem_x509_certificates(fh.read()))
        system_der = ssl.create_default_context().get_ca_certs(binary_form=True)
        return [x509.load_der_x509_certificate(d) for d in system_der]
    except (OSError, ValueError) as exc:
        raise TLSObserverError(f"could not load trust anchors: {type(exc).__name__}") from exc


def _build_verified_chain(
    leaf: x509.Certificate, presented: list[x509.Certificate], sni: str, cafile: str | None
) -> list[x509.Certificate]:
    """Build and cryptographically verify the path from ``leaf`` to a trust
    anchor, using ``presented`` as candidate intermediates. Returns the VERIFIED
    path (leaf..anchor).

    This is the fix for the core pitfall: membership in the raw presented bag is
    meaningless (a hostile server can append any CA's cert), so intermediate
    pinning must run over a chain that actually verifies. Only certificates on
    the valid path are reported; an unrelated appended cert never appears.
    Verification failure is fail-closed.
    """
    intermediates = [c for c in presented if _spki_sha256(c) != _spki_sha256(leaf)]
    anchors = _load_trust_anchors(cafile)
    try:
        verifier = PolicyBuilder().store(Store(anchors)).build_server_verifier(x509.DNSName(sni))
        return list(verifier.verify(leaf, intermediates))
    except VerificationError as exc:
        raise TLSObserverError(f"presented chain did not verify: {type(exc).__name__}") from exc
    except ValueError as exc:
        # e.g. sni is not a DNS name the verifier accepts.
        raise TLSObserverError(f"chain verification could not be set up: {type(exc).__name__}") from exc


def observe_tls(
    host: str,
    port: int,
    *,
    server_hostname: str | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    cafile: str | None = None,
    insecure: bool = False,
    capture_chain: bool = False,
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

    By default this reports the **leaf** certificate only, so
    ``chain_spki_sha256`` carries the leaf alone: the stdlib does not expose the
    intermediate chain portably (pre-3.13 has no accessor). With
    ``capture_chain=True`` the producer runs ``openssl s_client -showcerts`` to
    fetch the certs the peer presents, then **cryptographically builds and
    verifies** the path from the (handshake-verified) leaf to a trust anchor and
    reports the SPKIs/issuers of that VERIFIED path — which is what
    ``pinned_intermediate_spki_sha256`` needs. Only certs on the valid path are
    reported, so a hostile server cannot get an unrelated appended cert's SPKI
    into ``chain_spki_sha256``. Verification failure is fail-closed.
    ``capture_chain`` is incompatible with ``insecure`` (a verified chain
    requires verification).
    """
    if os.environ.get("SSLKEYLOGFILE"):
        # Refuse rather than silently report keylog_disabled while OpenSSL writes
        # a key log for this very process.
        raise TLSObserverError("refusing to run with SSLKEYLOGFILE set; a TLS key log would be written")

    if capture_chain and insecure:
        raise TLSObserverError("capture_chain requires verification; it cannot be combined with insecure")

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
    leaf_spki = _spki_sha256(leaf)

    if capture_chain:
        presented = _fetch_presented_certs(host, port, sni, timeout)
        verified_chain = _build_verified_chain(leaf, presented, sni, cafile)
        chain_spki = [_spki_sha256(c) for c in verified_chain]
        chain_issuers = [_issuer_name(c) for c in verified_chain]
    else:
        chain_spki = [leaf_spki]
        chain_issuers = [_issuer_name(leaf)]

    return {
        "negotiated_version": negotiated,
        "leaf_spki_sha256": leaf_spki,
        "chain_spki_sha256": chain_spki,
        "chain_issuers": chain_issuers,
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
    parser.add_argument(
        "--full-chain",
        action="store_true",
        help="capture the full presented chain via openssl s_client (needed for intermediate pinning)",
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
            capture_chain=args.full_chain,
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

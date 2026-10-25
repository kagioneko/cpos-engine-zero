#!/usr/bin/env python3
"""OCSP response verification for the TLS observation producer — OUTSIDE CPOS.

The lesson from the earlier ``openssl s_client -status`` attempt: a producer must
not report an OCSP ``good`` it did not *cryptographically verify*. Scraping a
tool's text output is spoofable. This module verifies a DER-encoded OCSP response
properly with ``cryptography.x509.ocsp`` before any status is trusted:

1. the response status is ``successful``;
2. the response signature is valid, signed directly by the certificate's issuer
   (its declared algorithm must match the issuer key family). A response that
   carries a delegated responder certificate is rejected fail-closed: validating
   a delegated responder is a full X.509 path-validation problem better left to a
   dedicated layer than hand-rolled here;
3. the single response's CertID (issuer name hash, issuer key hash, serial)
   matches the exact leaf/issuer pair being checked;
4. the response is temporally valid (``this_update`` not in the future beyond a
   small skew, ``next_update`` not in the past).

Every failure raises ``OCSPVerifyError`` (fail-closed). On success it returns the
observation's ``ocsp_*`` fields. CPOS still re-checks those against the policy;
this is the producer doing the work it is trusted to have done.

This is a verification core. Fetching the response over the network (parsing the
leaf's AIA OCSP URL and POSTing an OCSP request) is a thin separate layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import Certificate, SubjectKeyIdentifier
from cryptography.x509.oid import SignatureAlgorithmOID as _SAO
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequestBuilder,
    OCSPResponse,
    OCSPResponseStatus,
    load_der_ocsp_response,
)

# Clock-skew tolerance for an OCSP response's this_update being slightly ahead.
_OCSP_SKEW_SECONDS = 300

# Signature algorithm OIDs we accept per key family. The declared algorithm must
# match the signer's key type, so a response cannot claim one scheme while the
# key is another (algorithm-confusion). Weak (MD5/SHA1) and RSASSA-PSS (needs
# different padding than this verifier applies) are intentionally excluded.
_RSA_PKCS1_OIDS = frozenset({
    _SAO.RSA_WITH_SHA224, _SAO.RSA_WITH_SHA256, _SAO.RSA_WITH_SHA384, _SAO.RSA_WITH_SHA512,
    _SAO.RSA_WITH_SHA3_224, _SAO.RSA_WITH_SHA3_256, _SAO.RSA_WITH_SHA3_384, _SAO.RSA_WITH_SHA3_512,
})
_ECDSA_OIDS = frozenset({
    _SAO.ECDSA_WITH_SHA224, _SAO.ECDSA_WITH_SHA256, _SAO.ECDSA_WITH_SHA384, _SAO.ECDSA_WITH_SHA512,
    _SAO.ECDSA_WITH_SHA3_224, _SAO.ECDSA_WITH_SHA3_256, _SAO.ECDSA_WITH_SHA3_384, _SAO.ECDSA_WITH_SHA3_512,
})


def _require_sig_alg_for_key(oid: Any, public_key: Any) -> None:
    """Reject a signature whose declared algorithm does not match the signer key
    family (prevents algorithm substitution)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        ok = oid in _RSA_PKCS1_OIDS
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        ok = oid in _ECDSA_OIDS
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        ok = oid == _SAO.ED25519
    elif isinstance(public_key, ed448.Ed448PublicKey):
        ok = oid == _SAO.ED448
    else:
        raise OCSPVerifyError("unsupported signer key type")
    if not ok:
        raise OCSPVerifyError("OCSP signature algorithm does not match the signer key type")
_STATUS_NAMES = {
    OCSPCertStatus.GOOD: "good",
    OCSPCertStatus.REVOKED: "revoked",
    OCSPCertStatus.UNKNOWN: "unknown",
}


class OCSPVerifyError(RuntimeError):
    """The OCSP response could not be verified; never report a status from it."""


def _verify_signature(public_key: Any, signature: bytes, data: bytes, hash_algo: Any) -> None:
    """Verify ``signature`` over ``data`` with ``public_key``; raise
    OCSPVerifyError on any failure (bad signature, unsupported key/alg)."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_algo is None:
                raise OCSPVerifyError("missing signature hash algorithm")
            public_key.verify(signature, data, padding.PKCS1v15(), hash_algo)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_algo is None:
                raise OCSPVerifyError("missing signature hash algorithm")
            public_key.verify(signature, data, ec.ECDSA(hash_algo))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        else:
            raise OCSPVerifyError("unsupported signer key type")
    except InvalidSignature as exc:
        raise OCSPVerifyError("OCSP signature is invalid") from exc
    except (UnsupportedAlgorithm, ValueError, TypeError) as exc:
        raise OCSPVerifyError(f"OCSP signature could not be checked: {type(exc).__name__}") from exc


def _responder_signer(response: OCSPResponse, issuer: Certificate):
    """Return ``(public_key, signer_cert)`` for the response signer.

    Only the ISSUER-DIRECT case is supported: the issuer signed the response
    itself. A response that carries a delegated responder certificate is
    rejected fail-closed. Verifying a delegated responder correctly is a full
    X.509 path-validation problem (issuer link, validity, EKU/KeyUsage, critical
    extensions, inner/outer AlgorithmIdentifier consistency, …) that is unsafe to
    hand-roll and that `cryptography` offers no ready OCSP-responder validator
    for; doing it by halves would be worse than not accepting it. Supporting
    delegated responders is deferred to a proper path-validation layer."""
    if response.certificates:
        raise OCSPVerifyError("delegated OCSP responder certificates are not supported (issuer-direct responses only)")
    return issuer.public_key(), issuer


def _check_responder_id(response: OCSPResponse, signer: Certificate) -> None:
    """The response's ResponderID (by name or by key hash) must identify the
    certificate we verified the signature against — not some other party."""
    if response.responder_name is not None:
        if response.responder_name != signer.subject:
            raise OCSPVerifyError("OCSP responderID name does not match the signer certificate")
        return
    if response.responder_key_hash is not None:
        expected = SubjectKeyIdentifier.from_public_key(signer.public_key()).digest
        if response.responder_key_hash != expected:
            raise OCSPVerifyError("OCSP responderID key hash does not match the signer certificate")
        return
    raise OCSPVerifyError("OCSP response carries no responderID")


def _reject_unhandled_critical_extensions(response: OCSPResponse) -> None:
    """RFC 6960: a client must reject a response bearing a critical extension it
    does not process. This verifier processes none, so any critical one denies."""
    for ext_set in (response.extensions, response.single_extensions):
        for ext in ext_set:
            if ext.critical:
                raise OCSPVerifyError("OCSP response has an unhandled critical extension")


def _check_certid(response: OCSPResponse, leaf: Certificate, issuer: Certificate) -> None:
    """The response must be ABOUT this leaf under this issuer. Rebuild the CertID
    with cryptography (so we compute the hashes exactly as it does) and compare."""
    try:
        request = OCSPRequestBuilder().add_certificate(leaf, issuer, response.hash_algorithm).build()
    except Exception as exc:  # noqa: BLE001 - any build failure is fail-closed
        raise OCSPVerifyError(f"could not compute the expected CertID: {type(exc).__name__}") from exc
    if (
        request.serial_number != response.serial_number
        or request.issuer_key_hash != response.issuer_key_hash
        or request.issuer_name_hash != response.issuer_name_hash
    ):
        raise OCSPVerifyError("OCSP response CertID does not match the target certificate")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def verify_ocsp_der(
    der_response: bytes, leaf: Certificate, issuer: Certificate, *, now: datetime | None = None
) -> dict[str, Any]:
    """Verify a DER OCSP response for ``leaf`` under ``issuer`` and return the
    observation's ``ocsp_*`` fields. Fail-closed: raises ``OCSPVerifyError`` on
    any verification failure. A ``revoked`` status is returned (not raised) so
    the caller/gate can deny on it explicitly."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:  # treat a naive now as UTC rather than crash on compare
        now = now.replace(tzinfo=timezone.utc)
    try:
        response = load_der_ocsp_response(der_response)
    except ValueError as exc:
        raise OCSPVerifyError(f"OCSP response could not be parsed: {type(exc).__name__}") from exc

    # Field access on a parseable-but-odd response is wrapped so any surprise is
    # a clean fail-closed error, never a leaked traceback.
    try:
        if response.response_status != OCSPResponseStatus.SUCCESSFUL:
            raise OCSPVerifyError(f"OCSP response status is not successful: {response.response_status.name}")

        # Reject a response bearing a critical extension we do not process.
        _reject_unhandled_critical_extensions(response)

        # (2) signature by the issuer (issuer-direct only), and the responderID
        # must name that same signer.
        signer_key, signer_cert = _responder_signer(response, issuer)
        _check_responder_id(response, signer_cert)
        _require_sig_alg_for_key(response.signature_algorithm_oid, signer_key)
        _verify_signature(signer_key, response.signature, response.tbs_response_bytes, response.signature_hash_algorithm)

        # (3) the response is about exactly this leaf/issuer.
        _check_certid(response, leaf, issuer)

        # (4) temporal validity.
        this_update = response.this_update_utc
        next_update = response.next_update_utc
        status = response.certificate_status
    except OCSPVerifyError:
        raise
    except Exception as exc:  # noqa: BLE001 - any unexpected field error is fail-closed
        raise OCSPVerifyError(f"OCSP response could not be evaluated: {type(exc).__name__}") from exc

    if this_update is None:
        raise OCSPVerifyError("OCSP response has no this_update")
    if (this_update - now).total_seconds() > _OCSP_SKEW_SECONDS:
        raise OCSPVerifyError("OCSP this_update is in the future beyond clock-skew tolerance")
    if next_update is not None and next_update <= now:
        raise OCSPVerifyError("OCSP response is past its next_update")

    # NOTE: this does NOT set ocsp_stapled — whether the verified response was
    # actually stapled to the handshake (vs fetched out-of-band) is a fact only
    # the transport layer knows. The caller sets ocsp_stapled accordingly.
    out: dict[str, Any] = {"ocsp_status": _STATUS_NAMES.get(status, "unknown"), "ocsp_produced_at": _iso(this_update)}
    if next_update is not None:
        out["ocsp_next_update"] = _iso(next_update)
    return out

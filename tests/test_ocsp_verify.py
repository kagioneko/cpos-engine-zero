"""Hermetic tests for the producer-side OCSP response verifier.

No network: issuer, leaf, a delegated responder, and signed OCSP responses are
all built in-test with cryptography, then verified. This exercises the security
properties the earlier text-scraping attempt could not guarantee (real
signature, responder authorization, CertID match, validity).
"""
from __future__ import annotations

import datetime as dt
import importlib.util
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPResponderEncoding,
    OCSPResponseBuilder,
)

from cpos.mcp_tls_policy import verify_tls_observation

_SPEC = importlib.util.spec_from_file_location(
    "ocsp_verify", Path(__file__).resolve().parent.parent / "examples" / "ocsp_verify.py"
)
ocsp_verify = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ocsp_verify)

NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(subject_cn, issuer_name, subject_key, signer_key, *, ca=False, eku=None,
          not_before=None, not_after=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (NOW - dt.timedelta(minutes=5)))
        .not_valid_after(not_after or (NOW + dt.timedelta(days=30)))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(signer_key, hashes.SHA256())


def _issuer_and_leaf():
    issuer_key = _key()
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer CA")])
    issuer = _cert("Test Issuer CA", issuer_name, issuer_key, issuer_key, ca=True)
    leaf_key = _key()
    leaf = _cert("leaf.example.test", issuer_name, leaf_key, issuer_key)
    return issuer_key, issuer, leaf


def _build_response(leaf, issuer, signer_cert, signer_key, *, status=OCSPCertStatus.GOOD,
                    this_update=None, next_update=None, revocation_time=None, responder_certs=None):
    this_update = this_update or NOW
    next_update = next_update if next_update is not None else NOW + dt.timedelta(days=1)
    b = OCSPResponseBuilder().add_response(
        cert=leaf, issuer=issuer, algorithm=hashes.SHA256(),
        cert_status=status, this_update=this_update, next_update=next_update,
        revocation_time=revocation_time, revocation_reason=None,
    ).responder_id(OCSPResponderEncoding.NAME, signer_cert)
    if responder_certs:
        b = b.certificates(responder_certs)
    resp = b.sign(signer_key, hashes.SHA256())
    return resp.public_bytes(serialization.Encoding.DER)


def test_verify_good_issuer_signed():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    der = _build_response(leaf, issuer, issuer, issuer_key)
    out = ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)
    assert out["ocsp_status"] == "good"
    # the verifier does not know (and must not assert) that this was stapled
    assert "ocsp_stapled" not in out
    assert out["ocsp_produced_at"].endswith("Z")
    assert out["ocsp_next_update"].endswith("Z")


def test_verify_revoked_is_returned_not_raised():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    der = _build_response(leaf, issuer, issuer, issuer_key, status=OCSPCertStatus.REVOKED,
                          revocation_time=NOW - dt.timedelta(days=1))
    out = ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)
    assert out["ocsp_status"] == "revoked"


def test_verify_rejects_bad_signature():
    # Build a valid issuer-signed response, then verify it against a DIFFERENT
    # issuer key (same subject name). The direct-signature check uses that wrong
    # key and must reject it before anything else.
    issuer_key, issuer, leaf = _issuer_and_leaf()
    der = _build_response(leaf, issuer, issuer, issuer_key)
    imposter_key = _key()
    imposter_issuer = _cert("Test Issuer CA", issuer.subject, imposter_key, imposter_key, ca=True)
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(der, leaf, imposter_issuer, now=NOW)


def test_verify_rejects_certid_mismatch():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    # response is built for `leaf`, but we verify against a DIFFERENT leaf.
    der = _build_response(leaf, issuer, issuer, issuer_key)
    other_leaf = _cert("other.example.test", issuer.subject, _key(), issuer_key)
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(der, other_leaf, issuer, now=NOW)


def test_verify_rejects_expired_next_update():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    der = _build_response(leaf, issuer, issuer, issuer_key,
                          this_update=NOW - dt.timedelta(days=2), next_update=NOW - dt.timedelta(days=1))
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)


def test_verify_rejects_future_this_update():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    der = _build_response(leaf, issuer, issuer, issuer_key,
                          this_update=NOW + dt.timedelta(hours=1), next_update=NOW + dt.timedelta(days=1))
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)


def test_verify_rejects_unsuccessful_response():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    from cryptography.x509.ocsp import OCSPResponseStatus
    der = OCSPResponseBuilder.build_unsuccessful(OCSPResponseStatus.TRY_LATER).public_bytes(serialization.Encoding.DER)
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)


def test_verify_rejects_garbage_bytes():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(b"not-a-der-ocsp-response", leaf, issuer, now=NOW)


def test_verify_rejects_any_delegated_responder():
    # Delegated responders are not supported: even a well-formed one (issued by
    # the issuer, OCSPSigning EKU) is rejected fail-closed rather than validated
    # by hand. This closes the whole class of responder-cert path-validation
    # pitfalls.
    issuer_key, issuer, leaf = _issuer_and_leaf()
    r_key = _key()
    r_cert = _cert("Delegated OCSP Responder", issuer.subject, r_key, issuer_key,
                   eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
    der = _build_response(leaf, issuer, r_cert, r_key, responder_certs=[r_cert])
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)


def test_verify_rejects_critical_response_extension():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    b = OCSPResponseBuilder().add_response(
        cert=leaf, issuer=issuer, algorithm=hashes.SHA256(),
        cert_status=OCSPCertStatus.GOOD, this_update=NOW, next_update=NOW + dt.timedelta(days=1),
        revocation_time=None, revocation_reason=None,
    ).responder_id(OCSPResponderEncoding.NAME, issuer).add_extension(x509.OCSPNonce(b"x" * 16), critical=True)
    der = b.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)


def test_require_sig_alg_for_key_rejects_family_mismatch():
    from cryptography.x509.oid import SignatureAlgorithmOID as SAO
    rsa_key = _key().public_key()
    ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    # RSA key declared as ECDSA -> reject; EC key declared as RSA -> reject.
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify._require_sig_alg_for_key(SAO.ECDSA_WITH_SHA256, rsa_key)
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify._require_sig_alg_for_key(SAO.RSA_WITH_SHA256, ec_key)
    # weak / PSS also rejected for RSA
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify._require_sig_alg_for_key(SAO.RSA_WITH_SHA1, rsa_key)
    with pytest.raises(ocsp_verify.OCSPVerifyError):
        ocsp_verify._require_sig_alg_for_key(SAO.RSASSA_PSS, rsa_key)
    # matching family is accepted (no raise)
    ocsp_verify._require_sig_alg_for_key(SAO.RSA_WITH_SHA256, rsa_key)
    ocsp_verify._require_sig_alg_for_key(SAO.ECDSA_WITH_SHA256, ec_key)


def test_verify_accepts_naive_now_as_utc():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    der = _build_response(leaf, issuer, issuer, issuer_key)
    naive = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)  # deliberately naive UTC
    out = ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=naive)
    assert out["ocsp_status"] == "good"


def test_verified_good_feeds_cpos_gate_end_to_end():
    issuer_key, issuer, leaf = _issuer_and_leaf()
    der = _build_response(leaf, issuer, issuer, issuer_key)
    ocsp = ocsp_verify.verify_ocsp_der(der, leaf, issuer, now=NOW)
    leaf_spki = __import__("hashlib").sha256(
        leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    obs = {
        "negotiated_version": "TLSv1.3", "leaf_spki_sha256": leaf_spki,
        "leaf_not_after": (NOW + dt.timedelta(days=10)).isoformat().replace("+00:00", "Z"),
        "hostname_matched": True, "keylog_disabled": True, "observed_host": "leaf.example.test",
        # the transport layer attests this verified result came from a staple
        "ocsp_stapled": True,
        **ocsp,
    }
    connector = {
        "url": "https://leaf.example.test/mcp", "transport": "https",
        "tls_policy": {"pinned_spki_sha256": [leaf_spki], "require_ocsp_staple": True, "max_ocsp_staple_age_seconds": 86400},
    }
    assert verify_tls_observation(connector, obs)["ok"] is True

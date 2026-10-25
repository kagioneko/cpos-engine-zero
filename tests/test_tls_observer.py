"""Hermetic tests for the reference TLS observation producer.

These spin up a localhost TLS server with an in-test self-signed certificate —
no external network is touched. Blocking socket work runs under bounded waits
(a daemon thread with a timed join), never an unbounded accept/connect, so a bug
cannot hang the suite or block interpreter exit.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cpos.mcp_tls_policy import verify_tls_observation

# Load the example module by path (examples/ is a namespace dir, not a package).
_SPEC = importlib.util.spec_from_file_location(
    "tls_observer", Path(__file__).resolve().parent.parent / "examples" / "tls_observer.py"
)
tls_observer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(tls_observer)

_HANDSHAKE_TIMEOUT = 5.0


def _make_self_signed(tmp_path, cn="localhost"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    expected_spki = hashlib.sha256(
        cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()
    return cert_path, key_path, expected_spki


def _make_ca_and_leaf(tmp_path, cn="localhost"):
    """Build a CA and a leaf signed by it. The chain PEM is leaf-then-CA for
    load_cert_chain, so the server presents an intermediate the producer can
    capture. Returns a dict of paths, cert objects and SPKIs."""
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_ski, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    chain_pem = tmp_path / "chain.pem"
    chain_pem.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM))
    leaf_key_pem = tmp_path / "leaf_key.pem"
    leaf_key_pem.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ca_pem = tmp_path / "ca.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return {
        "chain_pem": chain_pem, "leaf_key": leaf_key_pem, "ca_pem": ca_pem,
        "leaf_cert": leaf_cert, "ca_cert": ca_cert,
        "leaf_spki": _spki_of(leaf_cert), "ca_spki": _spki_of(ca_cert),
    }


def _spki_of(cert):
    return hashlib.sha256(
        cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()


class _OneShotTLSServer:
    """Serve TLS connections on 127.0.0.1 (up to a small bound) then close. The
    accept loop runs in a daemon thread bounded by a timeout so it can never
    hang the test or block interpreter exit. Serving several (not one) lets a
    single test drive both the stdlib handshake and an openssl s_client."""

    def __init__(self, cert_path, key_path, max_conns=8):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(cert_path), str(key_path))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self._sock.settimeout(_HANDSHAKE_TIMEOUT)
        self.port = self._sock.getsockname()[1]
        self._max_conns = max_conns
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        for _ in range(self._max_conns):
            try:
                conn, _ = self._sock.accept()
            except (OSError, socket.timeout):
                return  # socket closed at __exit__, or no more clients
            conn.settimeout(_HANDSHAKE_TIMEOUT)  # bound the accepted socket too
            with conn:
                try:
                    tconn = self._ctx.wrap_socket(conn, server_side=True)
                    tconn.recv(16)
                    tconn.close()
                except (ssl.SSLError, OSError):
                    pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._sock.close()
        self._thread.join(timeout=_HANDSHAKE_TIMEOUT)


def _observe_bounded(**kwargs):
    # Run the (blocking) observe on a DAEMON thread with a bounded join. A plain
    # ThreadPoolExecutor is unsuitable here: its worker threads are non-daemon
    # and concurrent.futures joins them via an atexit hook, so a hung worker
    # would block interpreter exit even after shutdown(wait=False). A daemon
    # thread is abandoned cleanly at exit and the join is time-bounded.
    box: dict[str, object] = {}

    def _run():
        try:
            box["result"] = tls_observer.observe_tls(**kwargs)
        except BaseException as exc:  # noqa: BLE001 - surfaced to the caller below
            box["error"] = exc

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout=_HANDSHAKE_TIMEOUT + 2)
    if worker.is_alive():
        raise AssertionError("observe_tls did not return within the bounded wait")
    if "error" in box:
        raise box["error"]
    return box["result"]


def test_observer_emits_schema_compatible_observation(tmp_path):
    cert_path, key_path, expected_spki = _make_self_signed(tmp_path)
    with _OneShotTLSServer(cert_path, key_path) as srv:
        obs = _observe_bounded(
            host="127.0.0.1", port=srv.port, server_hostname="localhost", cafile=str(cert_path)
        )
    assert obs["negotiated_version"].startswith("TLSv1.")
    assert obs["leaf_spki_sha256"] == expected_spki
    assert expected_spki in obs["chain_spki_sha256"]
    assert obs["hostname_matched"] is True
    assert obs["keylog_disabled"] is True
    assert obs["observed_host"] == "localhost"
    assert obs["leaf_not_after"].endswith("Z")
    assert obs["chain_issuers"] and obs["chain_issuers"][0].get("CN") == "localhost"


def test_observer_output_passes_the_cpos_gate_end_to_end(tmp_path):
    # The money test: a real producer observation, checked by the real primitive.
    cert_path, key_path, expected_spki = _make_self_signed(tmp_path)
    with _OneShotTLSServer(cert_path, key_path) as srv:
        obs = _observe_bounded(
            host="127.0.0.1", port=srv.port, server_hostname="localhost", cafile=str(cert_path)
        )
    connector = {
        "url": "https://localhost/mcp",
        "transport": "https",
        "tls_policy": {
            "min_version": "TLSv1.2",
            "pinned_spki_sha256": [expected_spki],
            "require_hostname_match": True,
            "forbid_key_logging": True,
        },
    }
    result = verify_tls_observation(connector, obs)
    assert result["ok"] is True, result["findings"]
    assert result["decision"] == "tls_allowed"


def test_observer_gate_denies_when_pin_does_not_match(tmp_path):
    cert_path, key_path, _ = _make_self_signed(tmp_path)
    with _OneShotTLSServer(cert_path, key_path) as srv:
        obs = _observe_bounded(
            host="127.0.0.1", port=srv.port, server_hostname="localhost", cafile=str(cert_path)
        )
    connector = {
        "url": "https://localhost/mcp",
        "transport": "https",
        "tls_policy": {"pinned_spki_sha256": ["ab" * 32]},  # wrong pin
    }
    result = verify_tls_observation(connector, obs)
    assert result["ok"] is False
    assert "tls_spki_mismatch" in {f["code"] for f in result["findings"]}


def test_observer_insecure_reports_hostname_not_matched(tmp_path):
    cert_path, key_path, _ = _make_self_signed(tmp_path)
    with _OneShotTLSServer(cert_path, key_path) as srv:
        obs = _observe_bounded(
            host="127.0.0.1", port=srv.port, server_hostname="localhost", insecure=True
        )
    # Not verified -> must not assert a hostname match.
    assert obs["hostname_matched"] is False


def test_observer_refuses_to_run_with_keylog_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    with pytest.raises(tls_observer.TLSObserverError):
        tls_observer.observe_tls("127.0.0.1", 1, timeout=0.5)


def test_observer_bad_cafile_raises_clean_error_without_path_leak(tmp_path):
    missing = tmp_path / "nope" / "ca.pem"
    with pytest.raises(tls_observer.TLSObserverError) as exc:
        tls_observer.observe_tls("127.0.0.1", 1, cafile=str(missing), timeout=0.5)
    # the error names the failure class only, never the offending path
    assert str(missing) not in str(exc.value)


@pytest.mark.parametrize("bad_timeout", [-1, 0, float("nan"), float("inf"), "5", True, 10 ** 1000])
def test_observer_rejects_invalid_timeout_cleanly(bad_timeout):
    # invalid timeouts must become a clean TLSObserverError, never a bare
    # ValueError traceback leaking source paths.
    with pytest.raises(tls_observer.TLSObserverError):
        tls_observer.observe_tls("127.0.0.1", 1, timeout=bad_timeout)


@pytest.mark.parametrize("huge", [1e20, 1e308])
def test_observer_huge_but_finite_timeout_is_normalized(huge):
    # Finite and > 0 so it passes validation, but too large for the C socket
    # layer -> must surface as a clean TLSObserverError, not an OverflowError
    # traceback. Point at a closed local port so it fails fast.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    with pytest.raises(tls_observer.TLSObserverError):
        tls_observer.observe_tls("127.0.0.1", closed_port, timeout=huge)


def test_observer_raises_on_connection_failure():
    # Closed port on localhost -> bounded failure, not a hang.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    with pytest.raises(tls_observer.TLSObserverError):
        _observe_bounded(host="127.0.0.1", port=closed_port, server_hostname="localhost", timeout=1.0)


# --- full-chain capture via openssl (intermediate pinning, CPOS②) -----------

import shutil  # noqa: E402

_OPENSSL = shutil.which("openssl")
_needs_openssl = pytest.mark.skipif(_OPENSSL is None, reason="openssl not available")


@_needs_openssl
def test_full_chain_capture_includes_verified_intermediate(tmp_path):
    ca = _make_ca_and_leaf(tmp_path)
    with _OneShotTLSServer(ca["chain_pem"], ca["leaf_key"]) as srv:
        obs = _observe_bounded(
            host="127.0.0.1", port=srv.port, server_hostname="localhost",
            cafile=str(ca["ca_pem"]), capture_chain=True,
        )
    # the verified path carries both the leaf and the issuing CA SPKI
    assert ca["leaf_spki"] in obs["chain_spki_sha256"]
    assert ca["ca_spki"] in obs["chain_spki_sha256"]
    assert obs["leaf_spki_sha256"] == ca["leaf_spki"]


@_needs_openssl
def test_full_chain_end_to_end_intermediate_pinning(tmp_path):
    # The money test: producer captures + verifies the chain; the primitive
    # accepts it against a policy pinning the ISSUING CA's SPKI as intermediate.
    ca = _make_ca_and_leaf(tmp_path)
    with _OneShotTLSServer(ca["chain_pem"], ca["leaf_key"]) as srv:
        obs = _observe_bounded(
            host="127.0.0.1", port=srv.port, server_hostname="localhost",
            cafile=str(ca["ca_pem"]), capture_chain=True,
        )
    connector = {
        "url": "https://localhost/mcp",
        "transport": "https",
        "tls_policy": {
            "min_version": "TLSv1.2",
            "pinned_spki_sha256": [ca["leaf_spki"]],
            "pinned_intermediate_spki_sha256": [ca["ca_spki"]],
            "require_hostname_match": True,
            "forbid_key_logging": True,
        },
    }
    result = verify_tls_observation(connector, obs)
    assert result["ok"] is True, result["findings"]

    # and a policy pinning a WRONG intermediate is denied fail-closed
    connector["tls_policy"]["pinned_intermediate_spki_sha256"] = ["cd" * 32]
    denied = verify_tls_observation(connector, obs)
    assert denied["ok"] is False
    assert "tls_intermediate_spki_mismatch" in {f["code"] for f in denied["findings"]}


def test_build_verified_chain_excludes_unrelated_appended_cert(tmp_path):
    # P1 regression: a hostile server can APPEND any CA's cert to the presented
    # bag. Verification must drop it -> its SPKI must NOT appear in the result,
    # so intermediate pinning over the reported chain cannot be fooled.
    ca = _make_ca_and_leaf(tmp_path)
    unrelated = _make_ca_and_leaf(tmp_path / "other")  # a totally separate CA+leaf
    presented = [ca["leaf_cert"], ca["ca_cert"], unrelated["ca_cert"]]
    chain = tls_observer._build_verified_chain(
        ca["leaf_cert"], presented, "localhost", str(ca["ca_pem"])
    )
    spkis = {_spki_of(c) for c in chain}
    assert ca["leaf_spki"] in spkis
    assert ca["ca_spki"] in spkis
    assert unrelated["ca_spki"] not in spkis  # the appended cert was filtered out


def test_build_verified_chain_fails_closed_on_untrusted_anchor(tmp_path):
    # If the issuing CA is not a trust anchor, verification must fail closed.
    ca = _make_ca_and_leaf(tmp_path)
    other = _make_ca_and_leaf(tmp_path / "other")
    with pytest.raises(tls_observer.TLSObserverError):
        tls_observer._build_verified_chain(
            ca["leaf_cert"], [ca["leaf_cert"], ca["ca_cert"]], "localhost", str(other["ca_pem"])
        )


def test_capture_chain_rejects_insecure(tmp_path):
    cert_path, key_path, _ = _make_self_signed(tmp_path)
    with pytest.raises(tls_observer.TLSObserverError):
        tls_observer.observe_tls(
            "127.0.0.1", 1, server_hostname="localhost", insecure=True, capture_chain=True, timeout=0.5
        )


def test_full_chain_missing_openssl_is_clean_error(tmp_path, monkeypatch):
    def _boom(*a, **k):
        raise FileNotFoundError("openssl")
    monkeypatch.setattr(tls_observer.subprocess, "Popen", _boom)
    cert_path, key_path, _ = _make_self_signed(tmp_path)
    with _OneShotTLSServer(cert_path, key_path) as srv:
        with pytest.raises(tls_observer.TLSObserverError):
            _observe_bounded(
                host="127.0.0.1", port=srv.port, server_hostname="localhost",
                cafile=str(cert_path), capture_chain=True,
            )


def test_full_chain_timeout_is_clean_error(tmp_path, monkeypatch):
    # Force select() to report no data so _run_bounded hits its deadline branch.
    monkeypatch.setattr(tls_observer.select, "select", lambda *a, **k: ([], [], []))
    cert_path, key_path, _ = _make_self_signed(tmp_path)
    with _OneShotTLSServer(cert_path, key_path) as srv:
        with pytest.raises(tls_observer.TLSObserverError):
            _observe_bounded(
                host="127.0.0.1", port=srv.port, server_hostname="localhost",
                cafile=str(cert_path), capture_chain=True, timeout=1.0,
            )


def test_run_bounded_caps_stdout_size():
    # A command that floods stdout must be truncated near the cap, not buffered
    # without limit. `yes` streams forever; the bounded reader stops at the cap.
    import shutil as _sh
    if _sh.which("yes") is None:
        pytest.skip("yes not available")
    out, _ = tls_observer._run_bounded(["yes", "AAAAAAAA"], timeout=3.0)
    assert len(out) <= tls_observer._MAX_OPENSSL_STDOUT + 1 + 65536


def test_extract_pem_blocks_is_linear_and_bounded():
    # many BEGIN markers with no END must not hang or over-collect
    junk = (tls_observer._PEM_BEGIN + "\n") * 100000
    assert tls_observer._extract_pem_blocks(junk, 16) == []
    one = f"{tls_observer._PEM_BEGIN}\nAAAA\n{tls_observer._PEM_END}\n"
    assert len(tls_observer._extract_pem_blocks(one * 50, 16)) == 16  # stops at the limit


@pytest.mark.parametrize("bad", ["-connect", "", "a\nb", "x\x00y"])
def test_safe_arg_rejects_option_like_or_control(bad):
    with pytest.raises(tls_observer.TLSObserverError):
        tls_observer._safe_arg(bad, "host")

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


class _OneShotTLSServer:
    """Serve exactly one TLS connection on 127.0.0.1 then close. The accept runs
    in a daemon thread bounded by a timeout so it can never hang the test."""

    def __init__(self, cert_path, key_path):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(cert_path), str(key_path))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self._sock.settimeout(_HANDSHAKE_TIMEOUT)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            conn.settimeout(_HANDSHAKE_TIMEOUT)  # bound the accepted socket too
            with conn:
                try:
                    tconn = self._ctx.wrap_socket(conn, server_side=True)
                    tconn.recv(16)
                    tconn.close()
                except (ssl.SSLError, OSError):
                    pass
        except (OSError, socket.timeout):
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

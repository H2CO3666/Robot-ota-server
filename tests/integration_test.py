#!/usr/bin/env python3
"""End-to-end test for the robot-side offline OTA server.

It generates its own PKI and device key, builds and signs manifests, encrypts
firmware with AES-256-GCM and exercises the HTTP flow (including restart and
crash recovery). Nothing outside the temporary directory is touched.
"""

import argparse
import base64
import datetime
import hashlib
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

DOMAIN_PREFIX = b"ROBOT_OFFLINE_OTA_MANIFEST_V1"


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def make_cert(subject_name, public_key, issuer_name, issuer_key, ca):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc() - datetime.timedelta(days=1))
        .not_valid_after(now_utc() + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=not ca,
                key_cert_sign=ca,
                crl_sign=ca,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
    )
    if issuer_key is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
    return builder.sign(issuer_key if issuer_key is not None else public_key,
                        hashes.SHA256())


class Pki:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
        self.root_cert = make_cert(root_name, self.root_key.public_key(),
                                   root_name, self.root_key, True)

        self.signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signer_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Test Manifest Signer")]
        )
        self.signer_cert = make_cert(signer_name, self.signer_key.public_key(),
                                     root_name, self.root_key, False)

        self.device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.device_spki_sha256 = sha256_hex(
            self.device_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        (self.directory / "plat_ca.pem").write_bytes(
            self.root_cert.public_bytes(serialization.Encoding.PEM)
        )
        (self.directory / "device_key.pem").write_bytes(
            self.device_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.signer_cert_der = self.signer_cert.public_bytes(
            serialization.Encoding.DER
        )

        # A certificate chain that does not lead to the configured root.
        self.rogue_root_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        rogue_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Root CA")]
        )
        self.rogue_root_cert = make_cert(
            rogue_name, self.rogue_root_key.public_key(), rogue_name,
            self.rogue_root_key, True
        )
        self.rogue_signer_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        rogue_signer_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Signer")]
        )
        rogue_signer_cert = make_cert(
            rogue_signer_name,
            self.rogue_signer_key.public_key(),
            rogue_name,
            self.rogue_root_key,
            False,
        )
        self.rogue_signer_der = rogue_signer_cert.public_bytes(
            serialization.Encoding.DER
        )

    def make_bundle(
        self,
        package_id=None,
        robot_sn="AS2_000001",
        product_id="AS2",
        hw_revision="REV_A",
        version="2.4.1",
        security_version=5,
        recipient_spki=None,
        wrap_key=None,
        signer_key=None,
        signer_der=None,
        plaintext=None,
    ):
        plaintext = plaintext if plaintext is not None else os.urandom(300_000)
        package_id = package_id or str(uuid.uuid4())
        recipient_spki = recipient_spki or self.device_spki_sha256
        wrap_key = wrap_key or self.device_key.public_key()
        signer_key = signer_key or self.signer_key
        signer_der = signer_der or self.signer_cert_der

        dek = os.urandom(32)
        nonce = os.urandom(12)
        sealed = AESGCM(dek).encrypt(nonce, plaintext, None)
        ciphertext, tag = sealed[:-16], sealed[-16:]
        wrapped_dek = wrap_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        manifest = {
            "schema_version": 1,
            "purpose": "ROBOT_OFFLINE_OTA",
            "package_id": package_id,
            "issued_at": "2026-10-21T00:00:00Z",
            "target": {
                "robot_sn": robot_sn,
                "recipient_spki_sha256": recipient_spki,
            },
            "firmware": {
                "artifact_id": "artifact-" + package_id[:8],
                "product_id": product_id,
                "hw_revision": hw_revision,
                "version": version,
                "security_version": security_version,
                "plaintext_size": len(plaintext),
                "plaintext_sha256": sha256_hex(plaintext),
            },
            "encryption": {
                "content_alg": "AES-256-GCM",
                "nonce_b64": b64(nonce),
                "tag_b64": b64(tag),
                "aad_scheme": "NONE",
                "key_wrap_alg": "RSA-OAEP-SHA256",
                "wrapped_dek_b64": b64(wrapped_dek),
            },
            "payload": {
                "ciphertext_size": len(ciphertext),
                "ciphertext_sha256": sha256_hex(ciphertext),
            },
        }
        canonical = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        signature = signer_key.sign(
            DOMAIN_PREFIX + b"\x00" + canonical,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        bundle = {
            "manifest": manifest,
            "signature_b64": b64(signature),
            "signer_cert_b64": b64(signer_der),
            "firmware_url": "https://cdn.example.com/firmware.enc",
        }
        return bundle, plaintext, ciphertext


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_config(directory, data_dir, port, security_version=5):
    config = {
        "data_dir": str(data_dir),
        "device": {
            "robot_sn": "AS2_000001",
            "product_id": "AS2",
            "hw_revision": "REV_A",
            "firmware_version": "2.4.0",
            "security_version": security_version,
            "max_plaintext_bytes": 16 * 1024 * 1024,
            "max_chunk_bytes": 100_000,
        },
        "crypto": {
            "key_provider": "software",
            "device_private_key_file": "device_key.pem",
            "plat_ca_file": "plat_ca.pem",
            "signature_scheme": "RSA_PKCS1_SHA256",
            "sign_domain_prefix": DOMAIN_PREFIX.decode("ascii"),
            "check_cert_validity": True,
        },
        "http": {
            "bind": "127.0.0.1",
            "port": port,
            "threads": 2,
            "max_body_bytes": 8 * 1024 * 1024,
            "idle_timeout_seconds": 30,
            "max_queued_connections": 16,
            "max_header_bytes": 65536,
        },
        "session": {"receiving_ttl_hours": 24},
        "install": {"engine": "disabled"},
    }
    path = Path(directory) / "server.json"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return path


class Server:
    def __init__(self, binary, config_path, log_path):
        self.binary = str(binary)
        self.config_path = str(config_path)
        self.log_path = Path(log_path)
        self.proc = None

    def start(self, port):
        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [self.binary, "--config", self.config_path, "--verbose"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        log.close()
        self._wait_ready(port)

    def _wait_ready(self, port):
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "server exited during startup:\n" + self.log_tail()
                )
            try:
                status, _, _ = request(port, "GET", "/ota/v1/device-info",
                                       timeout=0.5)
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise RuntimeError("server did not become ready:\n" + self.log_tail())

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    def crash(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def log_tail(self, lines=60):
        try:
            text = self.log_path.read_text(errors="replace").splitlines()
        except OSError:
            return "<no log>"
        return "\n".join(text[-lines:])


def request(port, method, path, body=None, headers=None, timeout=15,
            encode_chunked=False):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {},
                           encode_chunked=encode_chunked)
        response = connection.getresponse()
        data = response.read()
        return response.status, dict(response.getheaders()), data
    finally:
        connection.close()


def header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def request_json(port, method, path, payload=None, headers=None):
    body = None
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    status, response_headers, data = request(
        port, method, path, body=body, headers=request_headers
    )
    parsed = None
    if data:
        parsed = json.loads(data.decode("utf-8"))
    return status, response_headers, parsed


def create_session(port, bundle):
    return request_json(port, "POST", "/ota/v1/sessions", bundle)


def get_session(port, session_id):
    return request_json(port, "GET", f"/ota/v1/sessions/{session_id}")


def install(port, session_id, bundle):
    return request_json(port, "POST", f"/ota/v1/sessions/{session_id}/install",
                        bundle)


def patch(port, session_id, offset, data, chunked=False, extra_headers=None,
          omit_offset=False):
    headers = {
        "Content-Type": "application/octet-stream",
    }
    if not omit_offset:
        headers["Upload-Offset"] = str(offset)
    if extra_headers:
        headers.update(extra_headers)
    body = [data] if chunked else data
    status, response_headers, response_body = request(
        port,
        "PATCH",
        f"/ota/v1/sessions/{session_id}/payload",
        body=body,
        headers=headers,
        encode_chunked=chunked,
    )
    parsed = None
    if response_body:
        parsed = json.loads(response_body.decode("utf-8"))
    return status, response_headers, parsed


def poll_terminal(port, session_id, wanted, timeout=30):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, _, body = get_session(port, session_id)
        expect(status == 200, f"GET session returned {status}: {body}")
        last = body
        if body["state"] == wanted:
            return body
        if body["state"] in ("FAILED", "EXPIRED", "RECOVERY_REQUIRED"):
            raise AssertionError(
                f"session reached {body['state']} instead of {wanted}: {body}"
            )
        time.sleep(0.1)
    raise AssertionError(f"session did not reach {wanted}: {last}")


def upload(port, session_id, ciphertext, start=0, chunk_size=65536,
           chunked=False):
    offset = start
    while offset < len(ciphertext):
        chunk = ciphertext[offset:offset + chunk_size]
        status, headers, body = patch(port, session_id, offset, chunk,
                                      chunked=chunked)
        expect(status == 204,
               f"PATCH at {offset} returned {status}: {body!r}")
        server_offset = header(headers, "Upload-Offset")
        expect(server_offset is not None, "PATCH response lacks Upload-Offset")
        expect(int(server_offset) == offset + len(chunk),
               f"unexpected Upload-Offset {server_offset}, expected "
               f"{offset + len(chunk)}")
        offset += len(chunk)
    return offset


def error_code(body):
    return (body or {}).get("error", {}).get("code")


def scenario_full_flow(root, binary):
    """Happy path, restart persistence, install-disabled semantics, errors."""
    pki = Pki(root)
    port = free_port()
    config = write_config(root, root / "data", port)
    server = Server(binary, config, root / "server.log")
    server.start(port)
    try:
        status, _, info = request_json(port, "GET", "/ota/v1/device-info")
        expect(status == 200, f"device-info returned {status}")
        expect(info["robot_sn"] == "AS2_000001", "wrong robot_sn")
        expect(info["ota_api_version"] == 1, "wrong ota_api_version")
        expect(info["manifest_versions"] == [1], "wrong manifest_versions")
        expect(info["max_chunk_bytes"] == 100_000, "wrong max_chunk_bytes")

        bundle, plaintext, ciphertext = pki.make_bundle()

        # A bad signature is rejected before a session exists.
        bad_bundle = json.loads(json.dumps(bundle))
        signature = bytearray(base64.b64decode(bad_bundle["signature_b64"]))
        signature[0] ^= 0x01
        bad_bundle["signature_b64"] = b64(signature)
        status, _, body = create_session(port, bad_bundle)
        expect(status == 400, f"bad signature returned {status}")
        expect(error_code(body) == "SIGNATURE_INVALID",
               f"bad signature code: {body}")

        # A valid signature over the wrong target is rejected by binding.
        other_target, _, _ = pki.make_bundle(robot_sn="AS2_999999")
        status, _, body = create_session(port, other_target)
        expect(status == 400, f"wrong target returned {status}")
        expect(error_code(body) == "DEVICE_MISMATCH",
               f"wrong target code: {body}")

        # A signer outside the platform CA chain is rejected.
        rogue_bundle, _, _ = pki.make_bundle(
            signer_key=pki.rogue_signer_key,
            signer_der=pki.rogue_signer_der,
        )
        status, _, body = create_session(port, rogue_bundle)
        expect(status == 400, f"rogue signer returned {status}")
        expect(error_code(body) == "CERT_INVALID",
               f"rogue signer code: {body}")

        status, _, created = create_session(port, bundle)
        expect(status == 201, f"create returned {status}: {created}")
        expect(created["state"] == "RECEIVING", f"state: {created}")
        expect(created["offset"] == 0, "initial offset")
        expect(created["total"] == len(ciphertext), "total")
        expect(created["result"] is None, "initial result")
        session_id = created["session_id"]

        # Same package, same manifest: resume (200, same id).
        status, _, resumed = create_session(port, bundle)
        expect(status == 200, f"resume returned {status}: {resumed}")
        expect(resumed["session_id"] == session_id, "resume returned new id")

        # Same package, different manifest: conflict.
        conflict, _, _ = pki.make_bundle(package_id=bundle["manifest"]["package_id"])
        status, _, body = create_session(port, conflict)
        expect(status == 409, f"package conflict returned {status}")
        expect(error_code(body) == "PACKAGE_ID_CONFLICT",
               f"package conflict code: {body}")

        # Wrong and missing offsets.
        status, _, body = patch(port, session_id, 1, ciphertext[:10])
        expect(status == 409, f"wrong offset returned {status}")
        expect(error_code(body) == "OFFSET_MISMATCH",
               f"wrong offset code: {body}")
        status, _, body = patch(port, session_id, 0, ciphertext[:10],
                                omit_offset=True)
        expect(status == 400, f"missing offset returned {status}")
        expect(error_code(body) == "INVALID_REQUEST",
               f"missing offset code: {body}")

        # HEAD exposes the authoritative offset.
        status, headers, body = request(
            port, "HEAD", f"/ota/v1/sessions/{session_id}/payload"
        )
        expect(status == 204, f"HEAD returned {status}")
        expect(header(headers, "Upload-Offset") == "0", "HEAD offset")
        expect(body == b"", "HEAD must not return a body")

        # Expect: 100-continue is answered before the body is read.
        first = ciphertext[:10_000]
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(
                (
                    f"PATCH /ota/v1/sessions/{session_id}/payload HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Upload-Offset: 0\r\n"
                    f"Content-Length: {len(first)}\r\n"
                    "Expect: 100-continue\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            partial = b""
            while b"\r\n\r\n" not in partial:
                partial += sock.recv(4096)
            expect(partial.startswith(b"HTTP/1.1 100 Continue"),
                   f"missing 100-continue: {partial[:80]!r}")
            sock.sendall(first)
            response = b""
            while b"\r\n\r\n" not in response:
                response += sock.recv(4096)
            expect(response.startswith(b"HTTP/1.1 204"),
                   f"continue upload failed: {response[:80]!r}")

        offset = upload(port, session_id, ciphertext, start=len(first),
                        chunk_size=65536)
        expect(offset == len(ciphertext), "upload did not finish")

        ready = poll_terminal(port, session_id, "READY")
        expect(ready["offset"] == len(ciphertext), "READY offset")
        expect(ready["total"] == len(ciphertext), "READY total")

        # Payload is no longer accepted.
        status, _, body = patch(port, session_id, len(ciphertext), b"x")
        expect(status == 409, f"patch after READY returned {status}")
        expect(error_code(body) == "INVALID_STATE", f"patch code: {body}")

        # Install with a different manifest is rejected.
        different, _, _ = pki.make_bundle()
        status, _, body = install(port, session_id, different)
        expect(status == 409, f"install mismatch returned {status}")
        expect(error_code(body) == "MANIFEST_MISMATCH",
               f"install mismatch code: {body}")

        # This build deliberately does not execute installs.
        status, _, body = install(port, session_id, bundle)
        expect(status == 501, f"install returned {status}: {body}")
        expect(error_code(body) == "INSTALL_NOT_SUPPORTED",
               f"install code: {body}")
        status, _, body = get_session(port, session_id)
        expect(status == 200 and body["state"] == "READY",
               f"session changed after 501: {body}")

        # Restart: state and the verified firmware remain durable.
        server.stop()
        server.start(port)
        status, _, after = get_session(port, session_id)
        expect(status == 200, f"GET after restart returned {status}")
        expect(after["state"] == "READY", f"state after restart: {after}")
        expect(after["offset"] == len(ciphertext), "offset after restart")

        status, _, resumed = create_session(port, bundle)
        expect(status == 200 and resumed["session_id"] == session_id,
               f"resume after restart: {resumed}")
        status, _, body = install(port, session_id, bundle)
        expect(status == 501 and error_code(body) == "INSTALL_NOT_SUPPORTED",
               f"install after restart: {status} {body}")

        # Unknown session and endpoint.
        status, _, body = get_session(port, "ota_" + "0" * 32)
        expect(status == 404 and error_code(body) == "SESSION_NOT_FOUND",
               f"unknown session: {status} {body}")
        status, _, body = request_json(port, "GET", "/ota/v1/nope")
        expect(status == 404 and error_code(body) == "NOT_FOUND",
               f"unknown endpoint: {status} {body}")
        status, _, body = request_json(port, "GET", "/ota/v1/sessions")
        expect(status == 405, f"wrong method returned {status}")
        expect(error_code(body) == "METHOD_NOT_ALLOWED", "wrong method code")
    finally:
        server.stop()


def scenario_verification_failure(root, binary):
    """A bundle wrapped for another key reaches FAILED, never READY."""
    pki = Pki(root)
    port = free_port()
    config = write_config(root, root / "data", port)
    server = Server(binary, config, root / "server.log")
    server.start(port)
    try:
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bundle, _, ciphertext = pki.make_bundle(wrap_key=wrong_key.public_key())
        status, _, created = create_session(port, bundle)
        expect(status == 201, f"create returned {status}: {created}")
        session_id = created["session_id"]

        upload(port, session_id, ciphertext, chunk_size=40_000)
        deadline = time.time() + 30
        body = None
        while time.time() < deadline:
            status, _, body = get_session(port, session_id)
            expect(status == 200, f"GET returned {status}")
            if body["state"] == "FAILED":
                break
            time.sleep(0.1)
        expect(body["state"] == "FAILED", f"state after bad DEK: {body}")
        expect(body["result"]["code"] == "VERIFY_FAILED",
               f"result after bad DEK: {body}")

        status, _, body = install(port, session_id, bundle)
        expect(status == 200 and body["state"] == "FAILED",
               f"install from FAILED: {status} {body}")
    finally:
        server.stop()


def scenario_rollback_and_chunked(root, binary):
    """Anti-rollback and Transfer-Encoding: chunked uploads."""
    pki = Pki(root)
    port = free_port()
    config = write_config(root, root / "data", port, security_version=5)
    server = Server(binary, config, root / "server.log")
    server.start(port)
    try:
        old, _, _ = pki.make_bundle(security_version=4)
        status, _, body = create_session(port, old)
        expect(status == 400, f"rollback returned {status}: {body}")
        expect(error_code(body) == "VERSION_ROLLBACK",
               f"rollback code: {body}")

        bundle, _, ciphertext = pki.make_bundle(security_version=5)
        status, _, created = create_session(port, bundle)
        expect(status == 201, f"create returned {status}: {created}")
        session_id = created["session_id"]

        offset = 0
        while offset < len(ciphertext):
            chunk = ciphertext[offset:offset + 70_000]
            status, headers, body = patch(
                port, session_id, offset, chunk, chunked=True
            )
            expect(status == 204, f"chunked PATCH returned {status}: {body}")
            offset = int(header(headers, "Upload-Offset"))

        poll_terminal(port, session_id, "READY")

        second, _, _ = pki.make_bundle()
        # The first session is READY (active), so a new one is OTA_BUSY.
        status, _, body = create_session(port, second)
        expect(status == 409 and error_code(body) == "OTA_BUSY",
               f"busy create: {status} {body}")
    finally:
        server.stop()


def scenario_chunked_and_crash(root, binary):
    """A single multi-chunk request and SIGKILL durability."""
    pki = Pki(root)
    port = free_port()
    config = write_config(root, root / "data", port)
    server = Server(binary, config, root / "server.log")
    server.start(port)
    try:
        bundle, _, ciphertext = pki.make_bundle()
        status, _, created = create_session(port, bundle)
        expect(status == 201, f"create returned {status}: {created}")
        session_id = created["session_id"]

        # Send one HTTP request whose body is split into several chunked
        # transfer chunks. A PATCH may carry at most max_chunk_bytes.
        first_request = ciphertext[:90_000]
        chunks = [first_request[:30_000], first_request[30_000:60_000],
                  first_request[60_000:]]
        status, headers, body = request(
            port,
            "PATCH",
            f"/ota/v1/sessions/{session_id}/payload",
            body=chunks,
            headers={
                "Content-Type": "application/octet-stream",
                "Upload-Offset": "0",
            },
            encode_chunked=True,
        )
        expect(status == 204, f"multi-chunk PATCH returned {status}: {body!r}")
        expect(int(header(headers, "Upload-Offset")) == len(first_request),
               "multi-chunk offset")
        upload(port, session_id, ciphertext, start=len(first_request),
               chunk_size=90_000)
        poll_terminal(port, session_id, "READY")
    finally:
        server.stop()

    # Crash/resume scenario in a fresh directory.
    crash_root = root / "crash"
    crash_root.mkdir()
    pki2 = Pki(crash_root)
    port2 = free_port()
    config2 = write_config(crash_root, crash_root / "data", port2)
    server2 = Server(binary, config2, crash_root / "server.log")
    server2.start(port2)
    try:
        bundle2, _, ciphertext2 = pki2.make_bundle()
        status, _, created = create_session(port2, bundle2)
        expect(status == 201, f"create returned {status}: {created}")
        session_id2 = created["session_id"]

        first = ciphertext2[:90_000]
        status, headers, body = patch(port2, session_id2, 0, first)
        expect(status == 204, f"first PATCH returned {status}: {body!r}")
        expect(int(header(headers, "Upload-Offset")) == len(first),
               "first offset")

        server2.crash()
        server2 = Server(binary, config2, crash_root / "server.log")
        server2.start(port2)

        status, _, resumed = get_session(port2, session_id2)
        expect(status == 200, f"GET after crash returned {status}")
        expect(resumed["state"] == "RECEIVING", f"state after crash: {resumed}")
        expect(resumed["offset"] == len(first),
               f"offset after crash: {resumed}")

        upload(port2, session_id2, ciphertext2, start=len(first),
               chunk_size=50_000)
        poll_terminal(port2, session_id2, "READY")
    finally:
        server2.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--server",
        default=str(Path(__file__).resolve().parent.parent
                    / "build" / "robot-ota-server"),
        help="path to the robot-ota-server binary",
    )
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary directory")
    parser.add_argument("--only", default=None,
                        help="run one scenario: full, verify, rollback, crash")
    args = parser.parse_args()

    binary = Path(args.server).resolve()
    if not binary.is_file():
        print(f"server binary not found: {binary}", file=sys.stderr)
        return 2

    root = Path(tempfile.mkdtemp(prefix="robot-ota-it-"))
    scenarios = {
        "full": scenario_full_flow,
        "verify": scenario_verification_failure,
        "rollback": scenario_rollback_and_chunked,
        "crash": scenario_chunked_and_crash,
    }
    selected = [args.only] if args.only else list(scenarios)
    failed = False
    try:
        for name in selected:
            scenario_root = root / name
            scenario_root.mkdir(parents=True, exist_ok=True)
            print(f"== scenario: {name}")
            try:
                scenarios[name](scenario_root, binary)
            except Exception as exc:  # noqa: BLE001 - report and continue
                failed = True
                print(f"FAILED: {name}: {exc}", file=sys.stderr)
                log = scenario_root / "server.log"
                if log.exists():
                    print("--- server log tail ---", file=sys.stderr)
                    print("\n".join(log.read_text(errors="replace").splitlines()[-80:]),
                          file=sys.stderr)
                if args.only:
                    break
            else:
                print(f"PASSED: {name}")
    finally:
        if args.keep or failed:
            print(f"temporary directory kept: {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Build (and optionally upload) a real-KMS-signed offline OTA bundle.

The manifest signature comes from the real Unitree KMS through the
``/kms/v4/authkey/cloud/{sign,cert}`` endpoints. For the test purpose
``UNITREE_OTA_TEST`` the KMS signer certificate is issued by the test
``plat_ca`` contained in ``certs/fanxin.pem`` of the prototype directory,
so that CA is written next to the bundle for the robot-side server.

Typical use (KMS reachable through an SSH tunnel):

    ssh -N -L 127.0.0.1:13165:<KMS_HOST>:<KMS_PORT> root@<JUMP_HOST>
    python3 tools/real_kms_bundle.py --out out/real-kms

Ask the platform team for the KMS host, port and jump host; they are not
stored in this repository.

The tool prints the device SPKI hash, writes ``manifest.json``,
``manifest.sig``, ``signer_cert.der``, ``firmware.enc``, ``bundle.json`` and
a ready-to-use ``server.json`` for ``robot-ota-server``.
"""

import argparse
import base64
import datetime
import hashlib
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_DOMAIN_PREFIX = "ROBOT_OFFLINE_OTA_MANIFEST_V1"
DEFAULT_TEST_CA = (
    Path(__file__).resolve().parent.parent
    / "邹佳源离线ota原型"
    / "prototype"
    / "certs"
    / "fanxin.pem"
)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def utc_now_rfc3339():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_json(value):
    """RFC 8785 for the subset used here (ASCII keys/strings, integers)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def kms_post(base_url, path, payload, timeout=15):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise SystemExit(f"KMS HTTP {error.code} on {path}: {detail[:400]}")
    except urllib.error.URLError as error:
        raise SystemExit(
            f"cannot reach KMS at {base_url}: {error.reason}\n"
            "Is the SSH tunnel to the KMS still up?"
        )

    if not isinstance(body, dict):
        raise SystemExit(f"KMS returned a non-object response: {body!r}"[:400])
    if "code" in body:
        if str(body["code"]) != "0":
            raise SystemExit(
                f"KMS error code={body.get('code')} message={body.get('message')}"
            )
        return body.get("result") or {}
    return body


def load_pem_bundle(path):
    text = Path(path).read_text(encoding="utf-8")
    blocks = []
    marker = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    position = 0
    while True:
        start = text.find(marker, position)
        if start < 0:
            break
        stop = text.find(end, start)
        if stop < 0:
            break
        stop += len(end)
        blocks.append(x509.load_pem_x509_certificate(text[start:stop].encode()))
        position = stop
    if not blocks:
        raise SystemExit(f"no certificate found in {path}")
    return blocks


def pick_test_ca(path):
    for cert in load_pem_bundle(path):
        try:
            constraints = cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            continue
        if constraints.ca:
            return cert
    raise SystemExit(f"no CA certificate found in {path}")


def verify_issuer(leaf, ca):
    if leaf.issuer != ca.subject:
        return False
    try:
        ca.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def load_or_create_device_key(private_path, public_path):
    private_path = Path(private_path)
    public_path = Path(public_path)
    if private_path.exists():
        key = serialization.load_pem_private_key(
            private_path.read_bytes(), password=None
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SystemExit(f"{private_path} is not an RSA private key")
        print(f"device key   : reusing {private_path}")
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(private_path, 0o600)
        print(f"device key   : generated {private_path}")
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key


def load_public_key(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise SystemExit(f"{path} is not an RSA public key")
    return key


def spki_sha256_hex(public_key):
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(der), der


def synthetic_plaintext(size):
    seed = b"UNITREE_OFFLINE_OTA_SYNTHETIC_FIRMWARE_V1\n"
    repeats = (size + len(seed) - 1) // len(seed)
    return (seed * repeats)[:size]


def build_manifest(args, public_key, plaintext):
    recipient_spki_sha256, _ = spki_sha256_hex(public_key)
    dek = os.urandom(32)
    nonce = os.urandom(12)
    sealed = AESGCM(dek).encrypt(nonce, plaintext, None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    wrapped_dek = public_key.encrypt(
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
        "package_id": str(uuid.uuid4()),
        "issued_at": utc_now_rfc3339(),
        "target": {
            "robot_sn": args.robot_sn,
            "recipient_spki_sha256": recipient_spki_sha256,
        },
        "firmware": {
            "artifact_id": args.artifact_id,
            "product_id": args.product_id,
            "hw_revision": args.hw_revision,
            "version": args.version,
            "security_version": args.security_version,
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
    return manifest, ciphertext, dek, recipient_spki_sha256


def sign_with_kms(args, manifest):
    sign_input = (
        args.domain_prefix.encode("utf-8")
        + b"\x00"
        + canonical_json(manifest)
    )
    request_id = f"real-bundle-{uuid.uuid4()}"
    signed = kms_post(
        args.kms_url,
        "/kms/v4/authkey/cloud/sign",
        {
            "purpose": args.purpose,
            "alg": "RSA",
            "plainSignData": b64(sign_input),
            "requestId": request_id,
        },
    )
    signature = base64.b64decode(signed["signData"])
    if signed.get("sigAlg") != "SHA256WithRSA":
        raise SystemExit(f"unexpected sigAlg: {signed.get('sigAlg')}")
    if len(signature) != 256:
        raise SystemExit(f"unexpected signature length: {len(signature)}")

    cert_body = kms_post(
        args.kms_url,
        "/kms/v4/authkey/cloud/cert",
        {"purpose": args.purpose, "alg": "RSA"},
    )
    if cert_body.get("keyId") != signed.get("keyId"):
        raise SystemExit("KMS sign/cert keyId mismatch")
    if cert_body.get("signerCertHash") != signed.get("signerCertHash"):
        raise SystemExit("KMS sign/cert signerCertHash mismatch")

    cert_der = base64.b64decode(cert_body["cert"])
    cert_hash = base64.b64encode(hashlib.sha256(cert_der).digest()).decode("ascii")
    if cert_hash != cert_body.get("signerCertHash"):
        raise SystemExit("signerCertHash does not match the returned certificate")

    leaf = x509.load_der_x509_certificate(cert_der)
    ca = pick_test_ca(args.test_ca)
    if not verify_issuer(leaf, ca):
        raise SystemExit(
            "KMS signer certificate is not issued by the configured test CA"
        )
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc):
        raise SystemExit("KMS signer certificate is outside its validity window")

    try:
        leaf.public_key().verify(
            signature,
            sign_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as error:
        raise SystemExit(f"local signature verification failed: {error}")

    return {
        "signature": signature,
        "cert_der": cert_der,
        "sign_input": sign_input,
        "key_id": signed.get("keyId"),
        "sig_alg": signed.get("sigAlg"),
        "signer_cert_hash": cert_body.get("signerCertHash"),
        "leaf": leaf,
    }


def write_server_config(out_dir, args, ca_pem_path):
    config = {
        "data_dir": "data",
        "log": {"dir": "log"},
        "device": {
            "robot_sn": args.robot_sn,
            "product_id": args.product_id,
            "hw_revision": args.hw_revision,
            "firmware_version": args.device_firmware_version,
            "security_version": 0,
            "max_plaintext_bytes": 16 * 1024 * 1024,
            "max_chunk_bytes": args.chunk_bytes,
        },
        "crypto": {
            "key_provider": "software",
            "device_private_key_file": "device_key.pem",
            "plat_ca_file": ca_pem_path.name,
            "signature_scheme": "RSA_PKCS1_SHA256",
            "sign_domain_prefix": args.domain_prefix,
            "check_cert_validity": True,
        },
        "http": {
            "bind": "127.0.0.1",
            "port": args.server_port,
            "threads": 2,
            "max_body_bytes": 8 * 1024 * 1024,
            "idle_timeout_seconds": 30,
            "max_queued_connections": 16,
            "max_header_bytes": 65536,
        },
        "session": {"receiving_ttl_hours": 24, "ready_ttl_hours": 24},
        "install": {"engine": "disabled"},
    }
    path = out_dir / "server.json"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return path


def http_json(port, method, path, payload=None, headers=None, timeout=15):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        body = None
        all_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            all_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=all_headers)
        response = connection.getresponse()
        data = response.read()
        parsed = json.loads(data.decode("utf-8")) if data else None
        return response.status, dict(response.getheaders()), parsed
    finally:
        connection.close()


def upload_and_verify(out_dir, args, ciphertext, plaintext_sha256):
    port = args.server_port
    bundle = json.loads((out_dir / "bundle.json").read_text(encoding="utf-8"))
    status, headers, body = http_json(port, "POST", "/ota/v1/sessions", bundle)
    if status not in (200, 201):
        raise SystemExit(f"session creation failed: HTTP {status} {body}")
    session_id = body["session_id"]
    state = body["state"]
    offset = int(body.get("offset") or 0)
    total = int(body.get("total") or len(ciphertext))
    print(
        f"session      : {session_id} state={state} offset={offset}/{total} "
        f"(HTTP {status})"
    )

    if state == "RECEIVING":
        chunk = args.chunk_bytes
        while offset < len(ciphertext):
            piece = ciphertext[offset:offset + chunk]
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            try:
                connection.request(
                    "PATCH",
                    f"/ota/v1/sessions/{session_id}/payload",
                    body=piece,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Upload-Offset": str(offset),
                        "Content-Length": str(len(piece)),
                    },
                )
                response = connection.getresponse()
                response_body = response.read()
                if response.status != 204:
                    raise SystemExit(
                        f"chunk at {offset} failed: HTTP {response.status} "
                        f"{response_body[:300]!r}"
                    )
                new_offset = response.getheader("Upload-Offset")
                if new_offset is None:
                    raise SystemExit("PATCH response is missing Upload-Offset")
                offset = int(new_offset)
            finally:
                connection.close()
        print(f"upload       : {offset} bytes in {chunk}-byte chunks")

    deadline = time.time() + args.verify_timeout
    last = None
    while time.time() < deadline:
        status, _, last = http_json(port, "GET", f"/ota/v1/sessions/{session_id}")
        if status != 200:
            raise SystemExit(f"session query failed: HTTP {status} {last}")
        if last["state"] in ("READY", "FAILED", "RECOVERY_REQUIRED", "EXPIRED"):
            break
        time.sleep(0.5)
    print(f"session state: {last['state']} result={last.get('result')}")
    if last["state"] != "READY":
        raise SystemExit(f"robot-side verification did not reach READY: {last}")

    firmware_path = out_dir / "data" / "sessions" / session_id / "firmware.bin"
    if not firmware_path.exists():
        raise SystemExit(f"decrypted firmware not found at {firmware_path}")
    decrypted = firmware_path.read_bytes()
    decrypted_sha256 = sha256_hex(decrypted)
    print(f"decrypted    : {len(decrypted)} bytes sha256={decrypted_sha256}")
    if len(decrypted) != len(ciphertext):
        raise SystemExit("decrypted size does not match the ciphertext size")
    if decrypted_sha256 != plaintext_sha256:
        raise SystemExit("decrypted plaintext hash does not match the manifest")
    print("decrypt      : OK (plaintext SHA-256 matches the manifest)")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kms-url", default="http://127.0.0.1:13165",
        help="KMS base URL (default: SSH tunnel on 127.0.0.1:13165)",
    )
    parser.add_argument("--purpose", default="UNITREE_OTA_TEST")
    parser.add_argument("--out", default="out/real-kms-bundle")
    parser.add_argument("--robot-sn", default="AS2_000001")
    parser.add_argument("--product-id", default="AS2")
    parser.add_argument("--hw-revision", default="REV_A")
    parser.add_argument("--version", default="2.5.0")
    parser.add_argument("--device-firmware-version", default="2.4.0")
    parser.add_argument("--security-version", type=int, default=5)
    parser.add_argument("--artifact-id", default="AS2_FW_2.5.0_REAL_KMS")
    parser.add_argument(
        "--domain-prefix", default=DEFAULT_DOMAIN_PREFIX,
        help="must match crypto.sign_domain_prefix on the robot",
    )
    parser.add_argument("--plaintext-bytes", type=int, default=1024 * 1024)
    parser.add_argument(
        "--plaintext-file", help="use this file instead of a synthetic image",
    )
    parser.add_argument(
        "--test-ca", default=str(DEFAULT_TEST_CA),
        help="PEM bundle containing the test plat_ca",
    )
    parser.add_argument(
        "--device-key", default="device_key.pem",
        help="device private key PEM, relative to --out (created if missing)",
    )
    parser.add_argument(
        "--device-pubkey",
        help="wrap the DEK for this public key instead of generating a key pair",
    )
    parser.add_argument(
        "--server-port", type=int, default=18080,
        help="port written into server.json and used by --upload",
    )
    parser.add_argument("--chunk-bytes", type=int, default=100_000)
    parser.add_argument("--verify-timeout", type=float, default=60.0)
    parser.add_argument(
        "--upload", action="store_true",
        help="upload the bundle to a running robot-ota-server and verify decryption",
    )
    parser.add_argument(
        "--upload-only", action="store_true",
        help="skip signing and upload the existing bundle in --out",
    )
    return parser.parse_args()


def upload_existing(args):
    out_dir = Path(args.out).resolve()
    info_path = out_dir / "package-info.json"
    bundle_path = out_dir / "bundle.json"
    ciphertext_path = out_dir / "firmware.enc"
    for path in (info_path, bundle_path, ciphertext_path):
        if not path.exists():
            raise SystemExit(f"missing {path}; build the bundle first")
    info = json.loads(info_path.read_text(encoding="utf-8"))
    ciphertext = ciphertext_path.read_bytes()
    if len(ciphertext) != info["ciphertext_size"]:
        raise SystemExit("firmware.enc size does not match package-info.json")
    print(f"package id   : {info['package_id']}")
    print(f"device SPKI  : {info['recipient_spki_sha256']}")
    print("--- upload and robot-side decryption check ---")
    upload_and_verify(out_dir, args, ciphertext, info["plaintext_sha256"])


def main():
    args = parse_args()
    if args.upload_only:
        upload_existing(args)
        return
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.plaintext_file:
        plaintext = Path(args.plaintext_file).read_bytes()
    else:
        plaintext = synthetic_plaintext(args.plaintext_bytes)
    if not plaintext:
        raise SystemExit("plaintext must not be empty")

    if args.device_pubkey:
        public_key = load_public_key(args.device_pubkey)
        print(f"device key   : public-only {args.device_pubkey}")
    else:
        key = load_or_create_device_key(
            out_dir / args.device_key, out_dir / "device_pub.pem"
        )
        public_key = key.public_key()

    manifest, ciphertext, dek, spki_hash = build_manifest(
        args, public_key, plaintext
    )
    signed = sign_with_kms(args, manifest)

    (out_dir / "manifest.json").write_bytes(canonical_json(manifest))
    (out_dir / "manifest.sig").write_bytes(signed["signature"])
    (out_dir / "signer_cert.der").write_bytes(signed["cert_der"])
    (out_dir / "signer_cert.pem").write_bytes(
        signed["leaf"].public_bytes(serialization.Encoding.PEM)
    )
    (out_dir / "firmware.enc").write_bytes(ciphertext)
    (out_dir / "firmware.plain").write_bytes(plaintext)

    ca = pick_test_ca(args.test_ca)
    ca_pem_path = out_dir / "plat_ca.pem"
    ca_pem_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    bundle = {
        "manifest": manifest,
        "signature_b64": b64(signed["signature"]),
        "signer_cert_b64": b64(signed["cert_der"]),
        "firmware_url": "file://" + str(out_dir / "firmware.enc"),
    }
    (out_dir / "bundle.json").write_bytes(
        json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    server_config = write_server_config(out_dir, args, ca_pem_path)

    info = {
        "package_id": manifest["package_id"],
        "robot_sn": manifest["target"]["robot_sn"],
        "recipient_spki_sha256": spki_hash,
        "manifest_sha256": sha256_hex(canonical_json(manifest)),
        "sign_input_sha256": sha256_hex(signed["sign_input"]),
        "plaintext_sha256": manifest["firmware"]["plaintext_sha256"],
        "ciphertext_sha256": manifest["payload"]["ciphertext_sha256"],
        "ciphertext_size": len(ciphertext),
        "kms_key_id": signed["key_id"],
        "kms_sig_alg": signed["sig_alg"],
        "kms_signer_cert_hash": signed["signer_cert_hash"],
        "kms_signer_subject": signed["leaf"].subject.rfc4514_string(),
        "kms_signer_issuer": signed["leaf"].issuer.rfc4514_string(),
        "kms_signer_not_after": signed["leaf"].not_valid_after_utc.isoformat(),
        "test_ca_subject": ca.subject.rfc4514_string(),
        "domain_prefix": args.domain_prefix,
        "server_config": str(server_config),
    }
    (out_dir / "package-info.json").write_text(
        json.dumps(info, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(f"package id   : {manifest['package_id']}")
    print(f"device SPKI  : {spki_hash}")
    print(f"KMS keyId    : {signed['key_id']} ({signed['sig_alg']})")
    print(f"signer cert  : {info['kms_signer_subject']} <- {info['kms_signer_issuer']}")
    print(f"plaintext    : {len(plaintext)} bytes {info['plaintext_sha256']}")
    print(f"ciphertext   : {len(ciphertext)} bytes {info['ciphertext_sha256']}")
    print(f"output       : {out_dir}")
    print(f"server cfg   : {server_config}")

    if args.upload:
        print("--- upload and robot-side decryption check ---")
        upload_and_verify(
            out_dir, args, ciphertext, info["plaintext_sha256"]
        )
    else:
        print(
            "next         : build/robot-ota-server --config "
            f"{server_config} --verbose"
        )
        print(
            f"               python3 tools/real_kms_bundle.py --out {args.out} "
            "--upload-only   # upload this exact bundle"
        )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate a self-signed TLS certificate for local HTTPS.

Equivalent OpenSSL command:

    openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
        -keyout secrets/tls/key.pem -out secrets/tls/cert.pem \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

The private key is written with mode 600 to secrets/tls/ (git-ignored).
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "secrets" / "tls")
    parser.add_argument("--days", type=int, default=365)
    parser.add_argument("--force", action="store_true", help="overwrite an existing certificate")
    args = parser.parse_args()

    out: Path = args.out
    cert_path, key_path = out / "cert.pem", out / "key.pem"
    if cert_path.exists() and not args.force:
        print(f"Certificate already exists at {cert_path} (use --force to replace).")
        return 0
    out.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(out, 0o700)

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVault (local dev)")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote {cert_path}\nWrote {key_path} (mode 600)")
    print("Your browser will warn that the certificate is self-signed; this is expected locally.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

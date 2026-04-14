#!/usr/bin/env python3
"""
get_fingerprint.py — Extract SPKI SHA-256 fingerprint from a live TLS server.

Usage:
    python3 scripts/get_fingerprint.py your-backend.com
    python3 scripts/get_fingerprint.py your-backend.com 8443

Output: fingerprint in uppercase colon-separated hex (AA:BB:CC:...)
        ready to paste into config.json as "api_fingerprint"
"""

import sys
import ssl
import socket
import hashlib
import subprocess
import tempfile
import os

def get_cert_der(hostname: str, port: int = 443) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
    return cert_der

def extract_spki_openssl(cert_der: bytes) -> bytes:
    """Use OpenSSL CLI to extract SPKI from DER certificate."""
    with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
        f.write(cert_der)
        cert_path = f.name

    try:
        # Extract public key (SPKI) in DER format
        result = subprocess.run(
            ['openssl', 'x509', '-inform', 'der', '-in', cert_path,
             '-pubkey', '-noout'],
            capture_output=True, text=True
        )
        pem_key = result.stdout

        # Convert PEM public key to DER
        result2 = subprocess.run(
            ['openssl', 'pkey', '-pubin', '-outform', 'der'],
            input=pem_key, capture_output=True
        )
        return result2.stdout
    finally:
        os.unlink(cert_path)

def spki_sha256(spki_der: bytes) -> str:
    digest = hashlib.sha256(spki_der).digest()
    return ':'.join(f'{b:02X}' for b in digest)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_fingerprint.py <hostname> [port]")
        sys.exit(1)

    hostname = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"Connecting to {hostname}:{port}...")

    cert_der = get_cert_der(hostname, port)
    print(f"Certificate DER: {len(cert_der)} bytes")

    try:
        spki_der = extract_spki_openssl(cert_der)
        fingerprint = spki_sha256(spki_der)
    except Exception as e:
        print(f"OpenSSL method failed ({e}), falling back to full cert hash...")
        fingerprint = spki_sha256(cert_der)

    print()
    print("═══════════════════════════════════════════════════════")
    print(f"  SPKI SHA-256 Fingerprint for {hostname}")
    print("═══════════════════════════════════════════════════════")
    print()
    print(f"  {fingerprint}")
    print()
    print("  Paste into config.json:")
    print(f'  "api_fingerprint": "{fingerprint}"')
    print()
    print("  Remember to re-sign config.json after updating:")
    print("  cargo run --example sign_config -- <private_key> config.json")
    print("═══════════════════════════════════════════════════════")

if __name__ == '__main__':
    main()

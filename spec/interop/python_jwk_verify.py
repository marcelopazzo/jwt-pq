#!/usr/bin/env python3
"""Parse a jwt-pq JWK (kty=AKP) and verify an ML-DSA-65 signature with dilithium-py.

This exercises the JWK wire format end-to-end: base64url decoding of the
`pub` field, kty/alg field names, and that the bytes actually round-trip
to a Dilithium public key that the reference implementation can use.
"""

import base64
import json
import sys
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

in_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "interop_out")

jwk = json.loads((in_dir / "jwk.json").read_text())
msg = (in_dir / "jwk_msg.bin").read_bytes()
sig = (in_dir / "jwk_sig.bin").read_bytes()

if jwk.get("kty") != "AKP":
    print(f"FAIL: expected kty=AKP, got kty={jwk.get('kty')!r}")
    sys.exit(1)

if jwk.get("alg") != "ML-DSA-65":
    print(f"FAIL: expected alg=ML-DSA-65, got alg={jwk.get('alg')!r}")
    sys.exit(1)

if "pub" not in jwk:
    print("FAIL: JWK is missing 'pub' field")
    sys.exit(1)


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


pk = b64url_decode(jwk["pub"])

print(f"Python verifying Ruby-produced ML-DSA-65 signature via JWK")
print(f"  kty={jwk['kty']} alg={jwk['alg']} kid={jwk.get('kid', '<none>')}")
print(f"  pk:  {len(pk)} bytes (decoded from JWK pub field)")
print(f"  msg: {len(msg)} bytes")
print(f"  sig: {len(sig)} bytes")

if len(pk) != 1952:
    print(f"FAIL: ML-DSA-65 public key must be 1952 bytes, got {len(pk)}")
    sys.exit(1)

ok = ML_DSA_65.verify(pk, msg, sig)
if not ok:
    print("FAIL: dilithium-py rejected the signature")
    sys.exit(1)

print("PASS: Python verified Ruby JWK-exported key + signature")

#!/usr/bin/env python3
"""Verify an ML-DSA-65 signature produced by jwt-pq (Ruby) using dilithium-py."""

import sys
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

in_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "interop_out")

pk = (in_dir / "pk.bin").read_bytes()
msg = (in_dir / "msg.bin").read_bytes()
sig = (in_dir / "sig.bin").read_bytes()

print(f"Python verifying Ruby-produced ML-DSA-65 signature")
print(f"  pk:  {len(pk)} bytes")
print(f"  msg: {len(msg)} bytes")
print(f"  sig: {len(sig)} bytes")

ok = ML_DSA_65.verify(pk, msg, sig)
if not ok:
    print("FAIL: dilithium-py rejected the signature")
    sys.exit(1)

print("PASS: Python verified Ruby signature")

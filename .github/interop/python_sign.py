#!/usr/bin/env python3
"""Generate an ML-DSA-65 keypair with dilithium-py, sign a fixed message,
and write raw pk/msg/sig bytes to disk for Ruby to verify."""

import sys
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "interop_out")
out_dir.mkdir(parents=True, exist_ok=True)

message = b"jwt-pq cross-interop test message"

pk, sk = ML_DSA_65.keygen()
sig = ML_DSA_65.sign(sk, message)

(out_dir / "pk.bin").write_bytes(pk)
(out_dir / "msg.bin").write_bytes(message)
(out_dir / "sig.bin").write_bytes(sig)

print(f"Python signed {len(message)}-byte message with ML-DSA-65")
print(f"  pk:  {len(pk)} bytes")
print(f"  sig: {len(sig)} bytes")
print(f"  out: {out_dir}/")

if not ML_DSA_65.verify(pk, message, sig):
    print("Python self-verify: FAIL")
    sys.exit(1)
print("Python self-verify: OK")

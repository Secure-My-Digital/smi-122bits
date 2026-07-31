#!/usr/bin/env python3
"""
SMI Password Entropy Audit Tool  (WIRED)

F1: gates the verdict on architectural checks (verify_architecture), not only on
    per-string Shannon. The audit now ABORTS if the seed/capacity/seed-dependence
    checks fail (e.g. a zero or public-fallback seed).
F2: load_ikm() fails closed (in crypto.py) — a missing AXIOM_IKM aborts here.
F6: pipeline parameters come from lib.spec via crypto.
"""

import hashlib
import base91
from hkdf import hkdf_extract, hkdf_expand

from crypto import (load_ikm, derive_prk, generate_password,
                    len_bytes, alpha_radix)
from lib.spec import info
from lib.salts import hkdf_salt
from lib.entropy import Welford, shannon_entropy
from lib.report import banner, summary, MAX_ITERATIONS
from lib.audit_checks import verify_architecture


def _pipeline(ikm, n, raw=False):
    """Seed-parameterised generator matching crypto.derive_prk/generate_password."""
    prk = hkdf_extract(hkdf_salt(), ikm, hash=hashlib.sha256)   # F4 salt
    if raw:
        return hkdf_expand(prk, info(n), length=len_bytes, hash=hashlib.sha256)
    return generate_password(prk, n)


def main():
    banner()
    ikm = load_ikm()                                   # F2: aborts if unset/weak

    # F1: real entropy gate — fail the audit if the architecture is broken.
    ok, results = verify_architecture(_pipeline, ikm, len_bytes, alpha_radix)
    print("Architecture checks:")
    for name, passed, msg in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {msg}")
    print()
    if not ok:
        raise SystemExit("[FATAL] architecture checks failed — the 122-bit claim "
                         "is NOT established for this key material. Audit aborts.")

    prk = derive_prk(ikm)
    stats = Welford()
    for i in range(MAX_ITERATIONS):
        stats.update(shannon_entropy(generate_password(prk, i)))
    summary(stats)


if __name__ == '__main__':
    main()

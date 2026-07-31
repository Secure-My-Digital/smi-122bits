# $Intent: F1 remediation — verify the properties that actually guarantee entropy,
#          instead of per-string Shannon (which cannot detect broken key material). $
#
# Per-string Shannon entropy (H = -Σp·log2 p · len) measures how varied the
# characters of ONE output string are. It is ~130-160 for any 32-char base91
# string, so it "PASSES" even a zero/constant/public seed. This module gates the
# audit on the facts that really bound guessing entropy:
#
#   1. capacity  — the pipeline can carry >= TARGET bits (no encoding bottleneck)
#   2. seed      — IKM is present, long enough, not all-zero, not the public
#                  hard-coded fallback, and not low-complexity
#   3. depends   — output is a real function of the seed (avalanche ~50%),
#                  so a generator that ignores/short-circuits the seed fails
#   4. distinct  — successive passwords do not collide
#
# NOTE (scope): the entropy of the user's MASTER PASSWORD cannot be measured from
# the (Argon2id) IKM — it is indistinguishable from random. Master-password
# strength is therefore enforced by policy at entry time (see F3/A3), not here.

import math

TARGET_BITS = 122.0
# The public fallback seed shipped in the repo (must never be accepted as real).
HARDCODED_FALLBACK_IKM = bytes.fromhex('4c6fd3a8379e467b957425e620eba357')


def _byte_entropy_bits(data: bytes) -> float:
    """Shannon entropy of the BYTE histogram (a weak-seed smell test)."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values()) * n


def _hamming_bits(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def check_capacity(len_bytes: int, radix: int, target: float = TARGET_BITS):
    chars = math.ceil(len_bytes * 8 / math.log2(radix))
    cap = min(len_bytes * 8, chars * math.log2(radix))
    return cap >= target, f"pipeline capacity {cap:.1f} bits (need >= {target})"


def check_seed(ikm: bytes, min_len: int = 16):
    if len(ikm) < min_len:
        return False, f"IKM too short: {len(ikm)}B < {min_len}B"
    if ikm == HARDCODED_FALLBACK_IKM:
        return False, "IKM is the public hard-coded fallback (zero real entropy)"
    if set(ikm) == {0}:
        return False, "IKM is all-zero (no entropy)"
    hb = _byte_entropy_bits(ikm)
    if hb < 0.5 * len(ikm) * 8 * 0.25:   # grossly low-complexity guard
        return False, f"IKM byte-entropy suspiciously low ({hb:.0f} bits)"
    return True, f"IKM ok ({len(ikm)}B, byte-entropy {hb:.0f} bits, not fallback)"


def check_depends_on_seed(pipeline, ikm: bytes, n_samples: int = 4):
    """Flip one seed bit; require the raw output to change by ~50% of bits."""
    base = b"".join(pipeline(ikm, i, raw=True) for i in range(n_samples))
    flipped = bytearray(ikm); flipped[0] ^= 0x01
    other = b"".join(pipeline(bytes(flipped), i, raw=True) for i in range(n_samples))
    frac = _hamming_bits(base, other) / (len(base) * 8)
    return 0.35 <= frac <= 0.65, f"avalanche {frac*100:.1f}% bit change (want ~50%)"


def check_distinct(pipeline, ikm: bytes, n: int = 5000):
    seen = {pipeline(ikm, i) for i in range(n)}
    return len(seen) == n, f"{len(seen)}/{n} distinct (collisions {n-len(seen)})"


def verify_architecture(pipeline, ikm, len_bytes, radix):
    """Run all F1 checks. Returns (passed: bool, results: list[(name,ok,msg)])."""
    results = [
        ("capacity", *check_capacity(len_bytes, radix)),
        ("seed",     *check_seed(ikm)),
        ("depends",  *check_depends_on_seed(pipeline, ikm)),
        ("distinct", *check_distinct(pipeline, ikm)),
    ]
    return all(ok for _, ok, _ in results), results

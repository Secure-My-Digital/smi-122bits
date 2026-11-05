# $Intent: F6 remediation — the ONE authoritative parameter set. Import from here;
#          never redefine these constants in crypto.py / report.py / minimal.py /
#          smi-password.py. This eliminates the 26/31/27-byte and Base91/Base95
#          divergence. $

import math

# --- Canonical algorithm (supersedes all prior per-file values) -------------
HASH_NAME          = 'SHA-256'          # HKDF + Argon2id hash family
IKM_BYTES          = 32                 # 256-bit IKM (Argon2id output)
ARGON2ID           = {'t_cost': 3, 'm_cost_kib': 65536, 'parallelism': 4, 'hash_len': 32}
ENCODING           = 'Base91'
RADIX              = 91
OKM_BYTES          = 27                 # HKDF-Expand output length
INFO_TEMPLATE      = 'okm:v1:{okm_bytes}:proof of entropy{n}'
TARGET_ENTROPY_BITS = 122.0

# --- Derived (do not hand-edit; computed from the above) --------------------
BITS_PER_CHAR          = math.log2(RADIX)
MIN_PASSWORD_CHARS     = math.ceil(OKM_BYTES * 8 / BITS_PER_CHAR)
PIPELINE_CAPACITY_BITS = min(OKM_BYTES * 8, MIN_PASSWORD_CHARS * BITS_PER_CHAR)


def info(n: int) -> bytes:
    """Canonical HKDF-Expand info string for counter n."""
    return INFO_TEMPLATE.format(okm_bytes=OKM_BYTES, n=n).encode('utf-8')


# The pipeline must be able to carry the target entropy; fail import otherwise.
assert PIPELINE_CAPACITY_BITS >= TARGET_ENTROPY_BITS, (
    f"capacity {PIPELINE_CAPACITY_BITS:.1f} < target {TARGET_ENTROPY_BITS}"
)

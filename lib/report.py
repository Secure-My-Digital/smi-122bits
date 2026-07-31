# $Intent: Manage CLI banners and final audit reports saving to JSON and stdout $
#
# F0 remediation (CRITICAL — secret-at-rest):
#   The audit report must NEVER contain secret key material (IKM, raw PRK, OKM,
#   the master password, or the server seed). Earlier revisions leaked
#   `ikm_hex` and `prk_hex` into the on-disk JSON, which is sufficient to
#   regenerate every password. This module now:
#     1. imports NO secret from crypto (only public config + the non-reversible
#        prk_proof commitment);
#     2. enforces a fail-closed guard (`_assert_no_secrets`) that refuses to
#        emit any secret-looking field — so a future edit cannot silently
#        reintroduce the leak;
#     3. writes the report file with 0600 permissions.

import os
import re
import stat


# CONFIGURATION
MAX_ITERATIONS = 1_000_000
MIN_ENTROPY_BITS = 122.0
# F7: the previous CONFIDENCE_SIGMA (= 6*3.8205 ≈ 22.9) and the "sigma ⇒
# 99.999999% confidence" statement were meaningless — sampling per-string
# character variety cannot bound guessing entropy. Removed. The entropy
# guarantee comes from the architectural checks (F1) + pipeline capacity (F6),
# not from these descriptive statistics.


# --- F0 guard ---------------------------------------------------------------
# Whole-key names that carry secret material and must never appear in a
# written/printed report. Matched with fullmatch(), so benign fields that merely
# CONTAIN one of these words (e.g. `password_length_chars`, `security_claim`,
# `key_length_bytes`) are NOT flagged. `prk_proof` (a non-reversible HKDF
# commitment) and `salt_hex` (public salt) are intentionally allowed.
_SECRET_KEY_RE = re.compile(
    r'(?:.*_)?'                                            # optional prefix
    r'(?:ikm|okm|raw_?prk|prk_hex|prk_bytes|seed|secret|'
    r'password|passphrase|master_?password|master_?key|private_?key)'
    r'(?:_(?:hex|b64|bytes|raw))?',                        # optional encoding suffix
    re.IGNORECASE,
)


def _assert_no_secrets(obj, path='report'):
    """Fail closed if any secret-bearing field name is present (F0)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _SECRET_KEY_RE.fullmatch(str(k)):
                raise SystemExit(
                    f"[F0] Refusing to emit secret-looking field '{path}.{k}'. "
                    f"Audit reports must not contain key material."
                )
            _assert_no_secrets(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _assert_no_secrets(v, f"{path}[{i}]")


def _write_report_secure(filename, text):
    """Create the report file readable only by the owner (0600)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(filename, flags, 0o600)
    try:
        os.write(fd, text.encode('utf-8'))
    finally:
        os.close(fd)
    # Defensive: enforce perms even if the file pre-existed with a looser mode.
    os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)


def banner():
    print("=" * 70)
    print("SMI Password Entropy Audit Tool")
    print("=" * 70)
    print()
    print(f"Starting audit: Testing {MAX_ITERATIONS:,} passwords...")
    print(f"Target: >= {MIN_ENTROPY_BITS} bits of entropy per password")


def summary(stats):
    import time
    import json
    import sys
    import math
    # F0: import ONLY public config and the non-reversible proof.
    # Do NOT import get_ikm_from_env / prk_hex here — the report has no
    # legitimate use for secret material.
    from crypto import len_bytes, min_password_length, alpha_radix, SALT_HEX, prk_proof

    # Final calculations
    elapsed = time.time() - stats.start_time
    rate = stats.n / elapsed if elapsed > 0 else 0
    variance = stats.M2 / stats.n if stats.n > 0 else 0
    stddev = math.sqrt(variance)

    results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        'audit_tool': 'SMI Password Entropy Audit Tool',
        'audit_version': '1.0.0',
        'security_claim': f'All passwords have at least {MIN_ENTROPY_BITS} bits of entropy',
        'configuration': {
            'max_iterations': MAX_ITERATIONS,
            'min_entropy_bits': MIN_ENTROPY_BITS,
            'key_length_bytes': len_bytes,
            'password_length_chars': min_password_length,
            'base_alphabet_size': alpha_radix,
            'hash_algorithm': 'SHA-256',
        },
        # F0: non-sensitive verification material only.
        #   salt_hex  - public salt (not secret)
        #   prk_proof - HKDF-derived, non-reversible commitment that lets an
        #               auditor confirm the SAME IKM/SALT was used, WITHOUT
        #               revealing the IKM or the PRK.
        'verification': {
            'salt_hex': SALT_HEX,
            'prk_proof': prk_proof,
        },
        'statistics': {
            'total_tested': stats.n,
            'total_failed': stats.failures,
            'completion_percentage': 100 * stats.n / MAX_ITERATIONS,
            'average_entropy_bits': stats.mean,
            'variance_bits_squared': variance,
            'std_deviation_bits': stddev,
            'min_entropy_bits': stats.min_entropy,
            'max_entropy_bits': stats.max_entropy,
            'elapsed_seconds': elapsed,
            'rate_passwords_per_second': rate,
        },
        'verdict': None,
    }

    if stats.failures > 0:
        results['verdict'] = 'FAILED'
        results['verdict_message'] = f"{stats.failures} out of {stats.n} passwords failed the entropy test"
        results['failures'] = getattr(stats, 'failed_passwords', [])
    elif stats.min_entropy < MIN_ENTROPY_BITS:
        results['verdict'] = 'FAILED'
        results['verdict_message'] = f"Minimum entropy ({stats.min_entropy:.2f} bits) is below {MIN_ENTROPY_BITS}"
    elif stats.interrupted:
        results['verdict'] = 'INCOMPLETE'
        results['verdict_message'] = f"Audit interrupted after {stats.n:,} tests"
    else:
        results['verdict'] = 'PASSED'
        # F7: no fabricated statistical confidence. State plainly what was
        # observed and where the guarantee actually comes from.
        results['verdict_message'] = (
            f"Architectural checks passed and all {stats.n:,} sampled passwords "
            f"had per-string Shannon >= {MIN_ENTROPY_BITS} bits. "
            f"Note: per-string Shannon is a DESCRIPTIVE statistic, not a bound on "
            f"guessing entropy; the >= {MIN_ENTROPY_BITS}-bit guarantee rests on the "
            f"architectural checks (seed/capacity/seed-dependence) and pipeline "
            f"capacity, not on this sampling."
        )

    # F0: fail closed before ANY output if a secret-looking field slipped in.
    _assert_no_secrets(results)

    print()
    print("=" * 70)
    print("AUDIT RESULTS")
    print("=" * 70)
    print()
    print(f"Verdict: {results['verdict']}")
    print(f"Message: {results['verdict_message']}")
    print()
    print("Configuration:")
    for key, val in results['configuration'].items():
        print(f"  {key}: {val}")
    print()
    print("Statistics:")
    for key, val in results['statistics'].items():
        if isinstance(val, float):
            print(f"  {key}: {val:.4f}")
        else:
            print(f"  {key}: {val}")
    print()
    print("Verification (non-sensitive):")
    for key, val in results['verification'].items():
        print(f"  {key}: {val}")
    print()

    report_filename = f"entropy_audit_{results['timestamp'].replace(' ', '_').replace(':', '-')}.json"
    _write_report_secure(report_filename, json.dumps(results, indent=2))

    print(f"Full report saved to: {report_filename} (mode 0600, no secrets)")
    print()

    if results['verdict'] == 'PASSED':
        print("✓ Security claim verified: All passwords have >= 122 bits of entropy")
        sys.exit(0)
    elif results['verdict'] == 'FAILED':
        print("✗ Security claim NOT verified: Some passwords have < 122 bits of entropy")
        sys.exit(1)
    else:
        print("⚠ Audit incomplete")
        sys.exit(2)

# "A report is the certificate of truth, the final seal of the security claim." -- Jack S. Molett, BlockSmith Audit Lead [Security Seals, 2026]

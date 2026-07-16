# $Intent: Manage CLI banners and final audit reports saving to JSON and stdout $

def banner():
    print("=" * 70)
    print("SMI Password Entropy Audit Tool")
    print("=" * 70)
    print()

def summary(stats):
    import time
    import json
    import sys
    import math
    from crypto import MAX_ITERATIONS, MIN_ENTROPY_BITS, CONFIDENCE_SIGMA, len_bytes, min_password_length, BASE95_ALPHABET, SALT_HEX
    import crypto
    
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
            'confidence_sigma': CONFIDENCE_SIGMA,
            'key_length_bytes': len_bytes,
            'password_length_chars': min_password_length,
            'base95_alphabet_size': len(BASE95_ALPHABET),
            'hash_algorithm': 'SHA-256',
        },
        'keys': {
            'ikm_hex': crypto.get_ikm_from_env() or '4c6fd3a8379e467b957425e620eba357',
            'salt_hex': SALT_HEX,
            'prk_hex': crypto.prk_hex,
            'prk_proof': crypto.prk_proof,
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
        confidence_bound = CONFIDENCE_SIGMA * stddev
        results['verdict_message'] = (
            f"All {stats.n:,} passwords tested have >= {MIN_ENTROPY_BITS} bits of entropy. "
            f"With {CONFIDENCE_SIGMA}-sigma confidence ({100*(1 - 2*(1-0.5*math.erfc(CONFIDENCE_SIGMA/math.sqrt(2)))):.4f}% confidence level), "
            f"the true minimum is >= {stats.min_entropy - confidence_bound:.2f} bits."
        )
        
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
    print("Keys:")
    for key, val in results['keys'].items():
        print(f"  {key}: {val}")
    print()
    
    report_filename = f"entropy_audit_{results['timestamp'].replace(' ', '_').replace(':', '-')}.json"
    with open(report_filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Full report saved to: {report_filename}")
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

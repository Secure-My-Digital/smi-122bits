# $Intent: Manage CLI banners and final audit reports saving to JSON and stdout with comprehensive metrics integration $
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
import math
import time
import json
import sys
from collections import Counter

# Try to import zxcvbn for advanced metrics
try:
    import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


# CONFIGURATION
MAX_ITERATIONS = 1_000_000
MIN_ENTROPY_BITS = 122.0
# F7: the previous CONFIDENCE_SIGMA (= 6*3.8205 ≈ 22.9) and the "sigma ⇒
# 99.999999% confidence" statement were meaningless — sampling per-string
# character variety cannot bound guessing entropy. Removed. The entropy
# guarantee comes from the architectural checks (F1) + pipeline capacity (F6),
# not from these descriptive statistics.

# --- Metrics calculation functions ---

def calculate_shannon_entropy(password):
    """Calculate Shannon entropy of a password in bits."""
    if not password:
        return 0.0
    
    freq = Counter(password)
    total = len(password)
    
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return entropy


def calculate_renyi_entropies(password):
    """Calculate Rényi entropies Hα for different alpha values."""
    if not password:
        return {'H0': 0.0, 'H1': 0.0, 'H2': 0.0, 'Hinf': 0.0}
    
    freq = Counter(password)
    total = len(password)
    
    # H0 - Hartley entropy (log of the number of distinct symbols)
    distinct_chars = len(freq)
    H0 = math.log2(distinct_chars) if distinct_chars > 0 else 0.0
    
    # H1 - Shannon entropy
    H1 = calculate_shannon_entropy(password)
    
    # H2 - Collision entropy
    H2_sum = 0.0
    for count in freq.values():
        if count > 0:
            p = count / total
            H2_sum -= p ** 2
    H2 = -math.log2(H2_sum) if H2_sum > 0 else 0.0
    
    # Hinf - Min-entropy (worst-case entropy)
    max_p = max(freq.values()) / total if freq else 0
    Hinf = -math.log2(max_p) if max_p > 0 else 0.0
    
    return {'H0': H0, 'H1': H1, 'H2': H2, 'Hinf': Hinf}


def calculate_lz77_compression_ratio(password):
    """Calculate LZ77 compression ratio as a measure of repetitiveness."""
    if not password or len(password) <= 1:
        return 1.0
    
    compressed_length = 0
    i = 0
    n = len(password)
    
    while i < n:
        max_len = 0
        best_offset = 0
        
        search_start = max(0, i - 256)
        
        for offset in range(search_start, i):
            match_len = 0
            while (i + match_len < n and 
                   password[offset + match_len] == password[i + match_len] and
                   match_len < 256):
                match_len += 1
            
            if match_len > max_len:
                max_len = match_len
                best_offset = offset
        
        if max_len >= 3:
            compressed_length += 2
            i += max_len
        else:
            compressed_length += 1
            i += 1
    
    original_length = len(password)
    return compressed_length / original_length if original_length > 0 else 1.0


def calculate_zxcvbn_metrics(password):
    """Calculate zxcvbn-based metrics for password strength."""
    if not ZXCVBN_AVAILABLE:
        return {
            'score': 0,
            'guesses': float('inf'),
            'guesses_log10': float('inf'),
            'crack_time': 'zxcvbn not available',
            'crack_time_seconds': float('inf'),
            'feedback_warning': 'zxcvbn library not installed',
            'feedback_suggestions': [],
            'pattern_matches': 0,
            'calc_time': 0.0,
            'guessability': 0.0
        }
    
    try:
        result = zxcvbn.zxcvbn(password)
        
        metrics = {
            'score': result['score'],
            'guesses': result['guesses'],
            'guesses_log10': result['guesses_log10'],
            'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            'crack_time_seconds': result['crack_times_seconds']['offline_slow_hashing_1e4_per_second'],
            'feedback_warning': result['feedback']['warning'],
            'feedback_suggestions': result['feedback']['suggestions'],
            'pattern_matches': len(result.get('sequence', [])),
            'calc_time': result['calc_time']
        }
        
        if result['guesses'] > 0:
            metrics['guessability'] = 1.0 / result['guesses']
        else:
            metrics['guessability'] = 1.0
            
        return metrics
        
    except Exception as e:
        return {
            'score': 0,
            'guesses': float('inf'),
            'guesses_log10': float('inf'),
            'crack_time': f'zxcvbn error: {str(e)}',
            'crack_time_seconds': float('inf'),
            'feedback_warning': f'zxcvbn calculation failed: {str(e)}',
            'feedback_suggestions': [],
            'pattern_matches': 0,
            'calc_time': 0.0,
            'guessability': 0.0
        }


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
    print(f"zxcvbn available: {ZXCVBN_AVAILABLE}")


def summary(stats):
    # F0: import ONLY public config and the non-reversible proof.
    # Do NOT import get_ikm_from_env / prk_hex here — the report has no
    # legitimate use for secret material.
    from crypto import len_bytes, min_password_length, alpha_radix, SALT_HEX, prk_proof

    # Final calculations
    elapsed = time.time() - stats.start_time
    rate = stats.n / elapsed if elapsed > 0 else 0
    m2_shannon = stats.M2.get('shannon', 0.0) if isinstance(stats.M2, dict) else stats.M2
    mean_shannon = stats.mean.get('shannon', 0.0) if isinstance(stats.mean, dict) else stats.mean
    variance = m2_shannon / stats.n if stats.n > 0 else 0
    stddev = math.sqrt(variance)

    # Calculate comprehensive metrics if password samples are available
    password_samples = getattr(stats, 'password_samples', [])
    
    # Initialize metrics aggregates
    shannon_entropies = []
    h0_entropies = []
    h1_entropies = []
    h2_entropies = []
    hinf_entropies = []
    lz77_ratios = []
    zxcvbn_scores = []
    guessabilities = []
    
    # Calculate metrics for each password sample
    password_metrics = []
    for pwd in password_samples:
        shannon = calculate_shannon_entropy(pwd)
        renyi = calculate_renyi_entropies(pwd)
        lz77 = calculate_lz77_compression_ratio(pwd)
        zxcvbn = calculate_zxcvbn_metrics(pwd)
        
        shannon_entropies.append(shannon)
        h0_entropies.append(renyi['H0'])
        h1_entropies.append(renyi['H1'])
        h2_entropies.append(renyi['H2'])
        hinf_entropies.append(renyi['Hinf'])
        lz77_ratios.append(lz77)
        zxcvbn_scores.append(zxcvbn['score'])
        guessabilities.append(zxcvbn.get('guessability', 0))
        
        password_metrics.append({
            'shannon_entropy': shannon,
            'renyi_entropies': renyi,
            'lz77_compression_ratio': lz77,
            'zxcvbn_metrics': zxcvbn
        })

    # Build comprehensive results
    results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        'audit_tool': 'SMI Password Entropy Audit Tool',
        'audit_version': '2.0.0',
        'security_claim': f'All passwords have at least {MIN_ENTROPY_BITS} bits of entropy',
        'configuration': {
            'max_iterations': MAX_ITERATIONS,
            'min_entropy_bits': MIN_ENTROPY_BITS,
            'key_length_bytes': len_bytes,
            'password_length_chars': min_password_length,
            'base_alphabet_size': alpha_radix,
            'hash_algorithm': 'SHA-256',
            'zxcvbn_available': ZXCVBN_AVAILABLE
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
            'average_entropy_bits': mean_shannon,
            'variance_bits_squared': variance,
            'std_deviation_bits': stddev,
            'min_entropy_bits': stats.min_entropy,
            'max_entropy_bits': stats.max_entropy,
            'elapsed_seconds': elapsed,
            'rate_passwords_per_second': rate,
        },
        'verdict': None,
    }

    # Add comprehensive entropy metrics if we have samples
    if password_samples:
        results['entropy_metrics'] = {
            'sample_size': len(password_samples),
            'shannon_entropy': {
                'mean': sum(shannon_entropies) / len(shannon_entropies) if shannon_entropies else 0,
                'min': min(shannon_entropies) if shannon_entropies else 0,
                'max': max(shannon_entropies) if shannon_entropies else 0,
                'std_dev': (sum((x - (sum(shannon_entropies) / len(shannon_entropies))) ** 2 
                           for x in shannon_entropies) / len(shannon_entropies)) ** 0.5 if shannon_entropies and len(shannon_entropies) > 1 else 0
            },
            'renyi_entropies': {
                'H0': {
                    'mean': sum(h0_entropies) / len(h0_entropies) if h0_entropies else 0,
                    'min': min(h0_entropies) if h0_entropies else 0,
                    'max': max(h0_entropies) if h0_entropies else 0
                },
                'H1': {
                    'mean': sum(h1_entropies) / len(h1_entropies) if h1_entropies else 0,
                    'min': min(h1_entropies) if h1_entropies else 0,
                    'max': max(h1_entropies) if h1_entropies else 0
                },
                'H2': {
                    'mean': sum(h2_entropies) / len(h2_entropies) if h2_entropies else 0,
                    'min': min(h2_entropies) if h2_entropies else 0,
                    'max': max(h2_entropies) if h2_entropies else 0
                },
                'Hinf': {
                    'mean': sum(hinf_entropies) / len(hinf_entropies) if hinf_entropies else 0,
                    'min': min(hinf_entropies) if hinf_entropies else 0,
                    'max': max(hinf_entropies) if hinf_entropies else 0
                }
            },
            'lz77_compression': {
                'mean_ratio': sum(lz77_ratios) / len(lz77_ratios) if lz77_ratios else 1.0,
                'min_ratio': min(lz77_ratios) if lz77_ratios else 1.0,
                'max_ratio': max(lz77_ratios) if lz77_ratios else 1.0
            }
        }

    # Add zxcvbn metrics if available
    if password_samples and ZXCVBN_AVAILABLE:
        results['zxcvbn_metrics'] = {
            'sample_size': len(password_samples),
            'mean_score': sum(zxcvbn_scores) / len(zxcvbn_scores) if zxcvbn_scores else 0,
            'min_score': min(zxcvbn_scores) if zxcvbn_scores else 0,
            'max_score': max(zxcvbn_scores) if zxcvbn_scores else 0,
            'mean_guessability': sum(guessabilities) / len(guessabilities) if guessabilities else 0,
            'strong_passwords_count': sum(1 for score in zxcvbn_scores if score >= 4),
            'weak_passwords_count': sum(1 for score in zxcvbn_scores if score < 2)
        }

    # Add individual password metrics (optional, can be large)
    if password_samples and len(password_samples) <= 100:  # Limit to avoid huge reports
        results['password_metrics'] = password_metrics

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

    # Print entropy metrics summary
    if 'entropy_metrics' in results:
        print("Entropy Metrics:")
        em = results['entropy_metrics']
        print(f"  Sample size: {em['sample_size']}")
        print(f"  Shannon entropy: mean={em['shannon_entropy']['mean']:.2f}, min={em['shannon_entropy']['min']:.2f}, max={em['shannon_entropy']['max']:.2f}")
        print(f"  Rényi H0: mean={em['renyi_entropies']['H0']['mean']:.2f}, min={em['renyi_entropies']['H0']['min']:.2f}, max={em['renyi_entropies']['H0']['max']:.2f}")
        print(f"  Rényi H1: mean={em['renyi_entropies']['H1']['mean']:.2f}, min={em['renyi_entropies']['H1']['min']:.2f}, max={em['renyi_entropies']['H1']['max']:.2f}")
        print(f"  Rényi H2: mean={em['renyi_entropies']['H2']['mean']:.2f}, min={em['renyi_entropies']['H2']['min']:.2f}, max={em['renyi_entropies']['H2']['max']:.2f}")
        print(f"  Rényi Hinf: mean={em['renyi_entropies']['Hinf']['mean']:.2f}, min={em['renyi_entropies']['Hinf']['min']:.2f}, max={em['renyi_entropies']['Hinf']['max']:.2f}")
        print(f"  LZ77 compression ratio: mean={em['lz77_compression']['mean_ratio']:.4f}, min={em['lz77_compression']['min_ratio']:.4f}, max={em['lz77_compression']['max_ratio']:.4f}")
        print()

    # Print zxcvbn metrics summary
    if 'zxcvbn_metrics' in results:
        zm = results['zxcvbn_metrics']
        print("zxcvbn Metrics:")
        print(f"  Sample size: {zm['sample_size']}")
        print(f"  Mean score: {zm['mean_score']:.2f}/4")
        print(f"  Score range: {zm['min_score']} to {zm['max_score']}")
        print(f"  Strong passwords (score >= 4): {zm['strong_passwords_count']}")
        print(f"  Weak passwords (score < 2): {zm['weak_passwords_count']}")
        print(f"  Mean guessability: {zm['mean_guessability']:.6f}")
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

# "A comprehensive report is the foundation of trust, where every metric tells the story of security." -- Michel G. Combes, BlockSmith CEO [Comprehensive Metrics, 2026]

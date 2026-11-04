# $Intent: Implement multi-metric entropy calculations (Hartley, Shannon, Collision, Min-Entropy, LZ77) and Welford tracking $

import math
import sys
import time
import signal

class MultiMetricWelford:
    """Online Welford accumulator tracking multiple entropy metrics simultaneously."""
    instance = None

    def __init__(self, metrics=('hartley', 'shannon', 'collision', 'min_entropy', 'lz77')):
        self.metrics = metrics
        self.n = 0
        self.mean = {m: 0.0 for m in metrics}
        self.M2 = {m: 0.0 for m in metrics}
        self.min_val = {m: float('inf') for m in metrics}
        self.max_val = {m: float('-inf') for m in metrics}
        
        self.failures = 0
        self.start_time = time.time()
        self.interrupted = False
        MultiMetricWelford.instance = self

    @property
    def min_entropy(self):
        """Backward compatibility accessor for legacy Shannon min_entropy."""
        return self.min_val.get('shannon', float('inf'))

    @property
    def max_entropy(self):
        """Backward compatibility accessor for legacy Shannon max_entropy."""
        return self.max_val.get('shannon', float('-inf'))

    def update(self, metrics_data):
        """Update streaming statistics with a single float or dictionary of metrics."""
        if isinstance(metrics_data, (int, float)):
            metrics_data = {'shannon': float(metrics_data)}

        self.n += 1
        from lib.report import MIN_ENTROPY_BITS, MAX_ITERATIONS

        shannon_val = metrics_data.get('shannon', 0.0)
        if shannon_val < MIN_ENTROPY_BITS:
            self.failures += 1
            print(f"  [FAIL] Iteration {self.n}: Shannon entropy {shannon_val:.2f} bits < {MIN_ENTROPY_BITS}")
            if not hasattr(self, 'failed_passwords'):
                self.failed_passwords = []
            self.failed_passwords.append({
                'iteration': self.n,
                'entropy_bits': shannon_val
            })

        for m, val in metrics_data.items():
            if m not in self.mean:
                self.mean[m] = 0.0
                self.M2[m] = 0.0
                self.min_val[m] = float('inf')
                self.max_val[m] = float('-inf')

            if val < self.min_val[m]:
                self.min_val[m] = val
            if val > self.max_val[m]:
                self.max_val[m] = val

            delta = val - self.mean[m]
            self.mean[m] += delta / self.n
            delta2 = val - self.mean[m]
            self.M2[m] += delta * delta2

        if self.n % 100_000 == 0:
            shannon_stddev = math.sqrt(self.M2['shannon'] / self.n) if self.n > 0 else 0
            min_e_avg = self.mean.get('min_entropy', 0.0)
            elapsed = time.time() - self.start_time
            rate = self.n / elapsed if elapsed > 0 else 0
            print(f"  Progress: {self.n:,}/{MAX_ITERATIONS:,} "
                  f"({100*self.n/MAX_ITERATIONS:.1f}%) "
                  f"| Shannon: {self.mean['shannon']:.2f}±{shannon_stddev:.2f}b "
                  f"| Min-Entropy: {min_e_avg:.2f}b "
                  f"| Rate: {rate:,.0f} pwd/sec")

# Alias for backward compatibility
Welford = MultiMetricWelford


def compute_all_entropies(data: str) -> dict:
    """Compute Hartley (H0), Shannon (H1), Collision (H2), Min-Entropy (H_inf), 

    LZ77 compression predictor, and single-guess bounds for a given string.
    """
    if not data:
        return {
            'hartley': 0.0,
            'shannon': 0.0,
            'collision': 0.0,
            'min_entropy': 0.0,
            'lz77': 0.0,
            'max_guess_prob': 1.0,
            'min_guess_work_bits': 0.0
        }

    length = len(data)
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    probs = [count / length for count in freq.values()]
    distinct_chars = len(freq)

    # 1. Hartley Entropy (H0): L * log2(|Support|)
    hartley = length * math.log2(distinct_chars) if distinct_chars > 0 else 0.0

    # 2. Shannon Entropy (H1): -L * sum(p * log2(p))
    shannon = length * sum(-p * math.log2(p) for p in probs if p > 0)

    # 3. Collision Entropy (H2): -L * log2(sum(p^2))  -- Birthday attack resistance
    sum_p2 = sum(p**2 for p in probs)
    collision = length * (-math.log2(sum_p2)) if sum_p2 > 0 else 0.0

    # 4. Min-Entropy (H_infinity): -L * log2(max(p))  -- Worst-case guessability lower bound
    max_p = max(probs)
    min_entropy = length * (-math.log2(max_p)) if max_p > 0 else 0.0

    # 5. LZ77 Predictor / Compression Entropy (Lempel-Ziv phrase factorisation)
    seen_phrases = set()
    curr_phrase = ""
    n_phrases = 0
    for char in data:
        curr_phrase += char
        if curr_phrase not in seen_phrases:
            seen_phrases.add(curr_phrase)
            curr_phrase = ""
            n_phrases += 1
    if curr_phrase:
        n_phrases += 1

    lz77_bits = n_phrases * math.log2(n_phrases) if n_phrases > 1 else 0.0

    # 6. Guessability Metrics
    max_guess_prob = max_p ** length
    min_guess_work_bits = min_entropy

    return {
        'hartley': hartley,
        'shannon': shannon,
        'collision': collision,
        'min_entropy': min_entropy,
        'lz77': lz77_bits,
        'max_guess_prob': max_guess_prob,
        'min_guess_work_bits': min_guess_work_bits
    }


def shannon_entropy(data: str) -> float:
    """Legacy helper function returning Shannon entropy in bits."""
    return compute_all_entropies(data)['shannon']


def signal_handler(sig, frame):
    if MultiMetricWelford.instance:
        MultiMetricWelford.instance.interrupted = True
        print("\n[!] Ctrl+C caught, completing current test...", file=sys.stderr)
        from lib.report import summary
        summary(MultiMetricWelford.instance)
    else:
        sys.exit(2)

signal.signal(signal.SIGINT, signal_handler)

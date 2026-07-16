# $Intent: Implement Shannon entropy calculation and Welford's algorithm for online statistics $

import math
import sys
import time
import signal

class Welford:
    instance = None
    
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_entropy = float('inf')
        self.max_entropy = float('-inf')
        self.failures = 0
        self.start_time = time.time()
        self.interrupted = False
        Welford.instance = self
        
    def update(self, entropy):
        if entropy < self.min_entropy:
            self.min_entropy = entropy
        if entropy > self.max_entropy:
            self.max_entropy = entropy
            
        self.n += 1
        delta = entropy - self.mean
        self.mean += delta / self.n
        delta2 = entropy - self.mean
        self.M2 += delta * delta2
        
        from crypto import MIN_ENTROPY_BITS, MAX_ITERATIONS
        if entropy < MIN_ENTROPY_BITS:
            self.failures += 1
            print(f"  [FAIL] Password {self.n}: {entropy:.2f} bits < {MIN_ENTROPY_BITS}")
            if not hasattr(self, 'failed_passwords'):
                self.failed_passwords = []
            self.failed_passwords.append({
                'iteration': self.n,
                'entropy_bits': entropy
            })
            
        if self.n % 100_000 == 0:
            current_stddev = math.sqrt(self.M2 / self.n) if self.n > 0 else 0
            elapsed = time.time() - self.start_time
            rate = self.n / elapsed if elapsed > 0 else 0
            print(f"  Progress: {self.n:,}/{MAX_ITERATIONS:,} "
                  f"({100*self.n/MAX_ITERATIONS:.1f}%) "
                  f"| Avg: {self.mean:.2f} ± {current_stddev:.2f} bits "
                  f"| Rate: {rate:,.0f} passwords/sec")

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits."""
    if not data:
        return 0.0
    
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
            
    return entropy * length

# Signal handler for graceful Ctrl+C
def signal_handler(sig, frame):
    if Welford.instance:
        Welford.instance.interrupted = True
        print("\n[!] Ctrl+C caught, completing current test...", file=sys.stderr)
        from test.report import summary
        summary(Welford.instance)
    else:
        sys.exit(2)

signal.signal(signal.SIGINT, signal_handler)

# "In the stream of numbers, Welford's algorithm is the anchor of numerical precision." -- Jack S. Molett, BlockSmith Mathematician [Numerical Recurrences, 2026]

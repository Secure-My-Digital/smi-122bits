To "prove entropy beyond Shannon" in the context of the Zero Material Projection (ZMP) and vaultless security architecture means moving from measuring simple **character variety** to proving **cryptographic unpredictability** and **architectural resilience**. The sources highlight that Shannon entropy, when measured on a single static string, is an invalid metric for security because it reflects encoding variety rather than the difficulty of guessing a secret.

### 1. The Limitation of Shannon Entropy
The sources identify a **critical methodological flaw** in using Shannon entropy for security audits: it measures character frequency distribution but fails to detect zero-entropy secrets.
*   **The Shannon Fallacy:** A fixed, hardcoded 32-character string like `abcdefghijklmnopqrstuvwxyz123456` would be evaluated as having high Shannon entropy (~160 bits) despite having **0 bits of actual secret entropy**.
*   **Audit Failure:** In testing, the Shannon entropy metric allowed all-zero seeds and public fallback keys to "pass" as high-entropy (over 130 bits), proving it cannot distinguish between random noise and deterministic constants.

### 2. Alternative Metrics: Guessing and Min-Entropy
To go beyond Shannon, the architecture focuses on metrics that quantify the **adversary's effort**:
*   **Guessing Entropy ($E_C$):** This metric quantifies the expected number of feature descriptors an attacker would need to examine to reproduce a hardened password. It represents the actual work factor for an offline attacker.
*   **Min-Entropy:** Measures the probability of the single most likely outcome, providing a conservative lower bound for security.
*   **Guessability:** Unlike combinatorics (bits), guessability measures the work an attacker actually performs. This can be estimated using **Monte Carlo techniques** to sample realistic attacker distributions (e.g., dictionary words, keyboard walks, or Markov chains) rather than just counting character classes.

### 3. Architectural Verification: The Weak Primitive Test
A core BlockSmith innovation is proving entropy through **structural absence** rather than mathematical hardness alone.
*   **The Weak Primitive Test:** To prove that security is **architectural** rather than cryptographic, the system's primitives (like SHA-256) are replaced with intentionally weak ones (like 32-bit `cyrb53` hashes).
*   **The Logic:** If the system remains secure with a 32-bit hash because the **Input Key Material (IKM) entropy dominates** (e.g., 256 bits) and the architecture prevents secret reconstruction, then the security is independent of primitive strength.

### 4. Holistic Lower Bound Estimation
A robust proof of entropy requires calculating a conservative lower bound based on the entire "chain" of trust:
$$\text{Lower Bound} = \min(\text{Seed Entropy, Argon2id Work Factor, Encoding Capacity, Master Password Entropy})$$.

This multi-layered approach includes:
*   **Seed Quality:** Proving the seed is derived from a truly random source that meets **FIPS 140-3** recommendations (e.g., 256 bits).
*   **Computational Debt:** Factorizing the work of memory-hard functions like **Argon2id** (e.g., 64MB memory, 3 passes) as part of the entropy "floor".
*   **Master Password Strength:** Integrating tools like **`zxcvbn`** to estimate and enforce a minimum threshold of human-provided entropy (the weakest link).
*   **Negative Testing:** Validating the entropy-proving tools by ensuring they **must fail** when given zero-entropy or weak seeds.

### 5. Information-Theoretic Security (ITS)
Ultimately, the goal is to achieve **Perfect Secrecy**, where the data available to an attacker provides exactly zero information about the secret. By storing only a **Shift Vector ($\Delta$)**—the modular difference between a secret and an ephemeral pad—the architecture ensures that even with infinite computing power, every candidate password remains equally probable.

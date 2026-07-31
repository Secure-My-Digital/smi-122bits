

![GitHub Streak](https://github-readme-streak-stats.herokuapp.com?user=michel47&theme=cobalt&date_format=j%20M%5B%20Y%5D&background=000000&border=7536B2&stroke=9243DD&ring=89502D&fire=FF9554&currStreakNum=D280FF&sideNums=BC52FF&currStreakLabel=64EAE2&sideLabels=48A8A2&dates=A42EE5)


# SMI Password Entropy Audit Package

This package provides the tools and documentation for third-party auditors to verify SMI's security claim that
all generated passwords contain at least 122 bits of Shannon entropy.

## Security Claim

**Claim:** All deterministically generated passwords in the SMI password manager contain at least 122 bits of Shannon entropy.

**Verification Method:** Statistical sampling with 6-sigma confidence bounds

**Confidence Level:** >99.999999% (6-sigma covers 99.999999% of normal distribution)

## Assumptions and Threat Model

### 🔑 Core Assumptions

**A1. V-OPRF Server Integrity (CRITICAL):**
- The server-side pepper (V-OPRF) is never compromised
- The server generates cryptographically secure random values
- The server's private key remains confidential
- **Impact if violated:** Effective entropy collapses to master password entropy

**A2. Online Guessing Rate Limiting (CRITICAL):**
- Online password guessing attempts are rate-limited
- Brute force attacks are mitigated at authentication layer
- **Impact if violated:** Effective entropy reduced by feasible guessing rate

**A3. Master Password Quality (IMPORTANT):**
- Users choose sufficiently strong master passwords
- Minimum entropy requirements are enforced
- **Impact if violated:** All derived passwords inherit weak master password entropy

**A4. Secure IKM Delivery (IMPORTANT):**
- IKM is derieved from user material or delivered via secure channel (named pipe or equivalent)
- No persistent storage of master secrets
- Memory sanitization prevents cold-boot attacks
- **Impact if violated:** Secret exposure risk

**A5. IKM Source Integrity (CRITICAL):**
- IKM input is assumed to be securely derived from user
- For testing purposes, IKM is protected by git-crypt
- Encryption key stored in `local.key.asc` (GPG encrypted)
- **Impact if violated:** Full compromise of password generation
- **Test Access:** `gpg --decrypt local.key.asc | git-crypt unlock -`
- **Note:** Production systems must use secure IKM derivation (V-OPRF server)

### 🛡️ Threat Model

#### ✅ Mitigated Threats

**T1. Offline Brute Force Attacks:**
- **Mitigation:** V-OPRF server pepper + Argon2id (t=3, m=64MB, p=4)
- **Effectiveness:** ≥122 bits entropy against offline attackers
- **Status:** ✅ MITIGATED

**T2. Rainbow Table Attacks:**
- **Mitigation:** Unique salt per user + server-side pepper
- **Effectiveness:** Prevents precomputation attacks
- **Status:** ✅ MITIGATED

**T3. Secret Persistence:**
- **Mitigation:** Vaultless architecture + named pipe delivery
- **Effectiveness:** No secrets written to disk (except audit logs - see F0)
- **Status:** ⚠️ PARTIALLY MITIGATED (audit log issue)

#### ⚠️ Residual Risks

**R1. Compromised V-OPRF Server:**
- **Risk:** Server compromise exposes pepper
- **Impact:** Effective entropy → master password entropy
- **Mitigation:** Server hardening, HSM protection, regular key rotation
- **Status:** ⚠️ RESIDUAL RISK

**R2. Unlimited Online Guessing:**
- **Risk:** No rate limiting at authentication
- **Impact:** Effective entropy → min(122, guessing_rate)
- **Mitigation:** Application-level rate limiting required
- **Status:** ⚠️ RESIDUAL RISK

**R3. Weak Master Passwords:**
- **Risk:** Users choose low-entropy master passwords
- **Impact:** All derived passwords inherit weak entropy
- **Mitigation:** Enforce minimum master password strength
- **Status:** ⚠️ RESIDUAL RISK

**R4. Audit Log Secret Disclosure (F0):**
- **Risk:** `run_audit.py` writes IKM/PRK to JSON files
- **Impact:** Full secret compromise if logs are exposed
- **Mitigation:** Remove secrets from audit reports (use prk_proof only)
- **Status:** ✅ FIXED - IKM/PRK removed from audit logs

#### 📊 Entropy Analysis by Threat Scenario

| Scenario | Effective Entropy | Status |
|----------|-------------------|--------|
| Ideal (all assumptions hold) | 122-156 bits | ✅ VERIFIED |
| Compromised V-OPRF server | Master password entropy | ⚠️ DEGRADED |
| Unlimited online guessing | min(122, guessing_rate) | ⚠️ DEGRADED |
| Weak master password | Master password entropy | ⚠️ DEGRADED |
| Zero-entropy seed (test) | 0 bits (but audit passes) | ⚠️ KNOWN LIMITATION |

### 🔬 Verification Limitations

**L1. Shannon Entropy ≠ Guessing Entropy:**
- Current metric measures character distribution, not unpredictability
- Does not detect zero-entropy seeds (F1)
- **Recommendation:** Add architectural checks (seed source, length, Argon2id params)

**L2. Single PRK Architecture:**
- All passwords derive from one PRK + public counter
- One compromise exposes entire password set
- **Recommendation:** Document as inherent vaultless trade-off

**L3. Specification Inconsistencies (F6):**
- Parameters differ across files (26B vs 31B vs 27B)
- Base91 vs Base95 encoding variations
- **Recommendation:** Converge on single authoritative specification

## Honest Security Statement

**Conditional Claim:** The system provides ≥122 bits of effective guessing entropy **IF AND ONLY IF:**

1. ✅ The V-OPRF server pepper remains uncompromised, AND
2. ✅ Online password guessing is properly rate-limited, AND  
3. ✅ Users choose sufficiently strong master passwords, AND
4. ✅ IKM is delivered securely without persistence

**Unconditional Reality:** Effective password strength equals the entropy of the user's master password, amplified by Argon2id and hardened by the server-side V-OPRF pepper, but bounded by the weakest link in the chain.

> *"Security claims must be stated with their assumptions, for a claim without context is merely marketing."* 
> -- Claude Audit Team [Security Transparency, 2026]

## Architecture Overview

## Architecture Overview

### 🗂️ Directory Structure

```
.
├── audit/                  # Audit materials for AI verification
│   ├── AUDIT_README.md      # AI-specific audit documentation
│   └── [AI verification tools]
│
├── server/                 # Seed server implementation
│   ├── seed_server.py       # Vaultless architecture server
│   └── [server components]
│
├── .env.pipe               # Named pipe for secure .env file access
├── minimal.py              # Self-contained SMI password derivation
├── run_audit.py            # Comprehensive audit script
├── crypto.py               # Cryptographic core functions
├── lib/                    # Supporting libraries
│   ├── encodings.py         # Base91/Base95 encoding
│   ├── entropy.py           # Shannon entropy calculation
│   └── report.py            # Audit reporting
│
└── dist/                   # Packaged distribution
```

### 🔐 Vaultless Architecture

**Named Pipe Security:**
- `.env.pipe` - FIFO named pipe for secure environment variable injection
- Eliminates need for vault storage
- Real-time credential delivery
- Zero persistence architecture

**Seed Server:**
- `server/seed_server.py` - Generates and delivers IKM on-demand
- Ephemeral key material
- No persistent storage
- Audit trail generation

## Self-Contained Components

### 📦 minimal.py - Standalone Password Derivation

**Features:**
- Single-file Python script (no dependencies)
- Self-contained SMI password generation
- Built-in entropy verification
- Audit-ready output

**Usage:**
```bash
python3 minimal.py
```

**Output:**
- Generated passwords with entropy metrics
- Statistical analysis
- Audit trail in JSON format

### 🔍 run_audit.py - Comprehensive Audit Tool

**Features:**
- 1,000,000 sample statistical testing
- 6-sigma confidence bounds
- Welford's algorithm for online statistics
- JSON audit report generation

**Usage:**
```bash
python3 run_audit.py
```

## Audit Materials for AI

### 🤖 ./audit/ Directory

**Purpose:** Provide machine-readable verification materials for AI auditors

**Contents:**
- `AUDIT_README.md` - AI-specific audit procedures
- Test vectors for algorithm verification
- Expected entropy distributions
- Cryptographic proof templates

**AI Verification:**
```bash
# Run AI verification suite
cd audit
python3 verify_ai.py
```

## Seed Server Implementation

### 🌱 ./server/ Directory

**Vaultless Architecture:**
- No persistent key storage
- Ephemeral key generation
- Real-time delivery via named pipe
- Zero-trust security model

**Components:**
- `seed_server.py` - Main server implementation
- IKM generation endpoints
- Audit logging
- Health monitoring

**Usage:**
```bash
# Start seed server
python3 server/seed_server.py

# Client connection
python3 minimal.py --ikm-source pipe
```

## Named Pipe Configuration

### 🔗 .env.pipe - Secure Environment Injection

**Setup:**
```bash
# Create named pipe
mkfifo .env.pipe

# Feed credentials in real-time
echo "AXIOM_IKM=$(generate_ikm)" > .env.pipe
```

**Security Benefits:**
- No file persistence
- Real-time credential delivery
- Process isolation
- Audit trail capability

## Requirements

To access the protected Python script containing the algorithm details, auditors must decrypt the git-crypt protected files:

```bash
gpg --decrypt local.key.asc | git-crypt unlock -
```

> ask for the password

This will unlock the encrypted files and allow you to inspect the password generation algorithm implementation.

## Security Features

### ✅ Verified Entropy
- 122+ bits Shannon entropy (tested: 142-156 bits)
- RFC 5869 HKDF with SHA-256
- Base91 encoding (ASCII 32-126)

### ✅ Secure Audit Trail
- Cryptographic proofs (prk_proof only)
- Statistical verification
- JSON report generation
- IPFS-backed integrity
- **No secrets in logs** (IKM/PRK removed)

### ✅ Vaultless Design
- No persistent secrets
- Ephemeral key material
- Named pipe delivery
- Zero-trust architecture
- **Audit logs now safe** (F0 issue fixed)

## Contact

For questions about this audit package, please contact:
- Security My Digital Team
- michel@securemy.digital

## Version History

- v1.0.0: Initial release for third-party audit
- v1.1.0: Added vaultless architecture support
- v1.2.0: Integrated named pipe security
- v1.3.0: Enhanced AI audit materials

---

> *"Security is not a product, but a process. Entropy is not a feature, but a requirement."*, 
> -- SMD Security Team [Security Manifesto, 2025]

> *"The named pipe delivers what the vault once stored, creating security through ephemerality."*, 
> -- Michel G. Combes, BlockSmith CEO [Vaultless Architecture, 2026]

$Intent: Provide auditors with comprehensive documentation covering vaultless architecture, AI verification materials, and self-contained audit tools to verify SMD's 122-bit entropy security claim $

---

> *"Security is not a product, but a process. Entropy is not a feature, but a requirement."*, -- SMD Security Team [Security Manifesto, 2025]

\$Intent: Provide auditors with clear documentation and tools to verify SMD's 122-bit entropy security claim $


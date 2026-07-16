# SMI Password Entropy Audit Package

## Overview

This package provides the tools and documentation for third-party auditors to verify SMI's security claim that all generated passwords contain at least 122 bits of Shannon entropy.

## Installation and Requirements

### Prerequisites
- **Python 3.6 or later** (Python 3.7+ recommended)
- **pip** (Python package manager)
- **Standard library modules**: math, time, signal, sys, json, hashlib

### Installation
```bash
# Clone or download this audit package
cd /path/to/audit-package

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install hkdf

# Verify installation
python3 -c "import hkdf; print('hkdf version:', hkdf.__version__)"
```

### Requirements File
A requirements.txt file is provided for easy installation:
```bash
pip install -r requirements.txt
```

## Files in This Package

| File                   | Purpose                                            |
|------------------------|----------------------------------------------------|
| `run_audit.py` | Main audit script - runs the entropy verification  |
| `entropy_audit_*.json` | Generated audit reports (created when script runs) |

## Quick Start

### Prerequisites

```bash
# Python 3.6 or later required
python3 --version

# Install dependencies
pip install hkdf
```

### Running the Audit

```bash
# Run the full audit (1 million iterations)
python3 run_audit.py

# Run a quick test (100 iterations) for verification
python3 -c "import run_audit; run_audit.MAX_ITERATIONS = 100; run_audit.main()"
```

### Expected Output

The script will:
1. Display progress during testing
2. Print a summary of results
3. Save a detailed JSON report to `entropy_audit_YYYY-MM-DD_HH-MM-SS.json`
4. Exit with code 0 (PASSED), 1 (FAILED), or 2 (INCOMPLETE)

## For Auditors

Please read the comprehensive Auditor Guide at the top of `run_audit.py` which explains:
- All assumptions made in this audit
- What you need to verify
- Limitations of the methodology
- How to interpret results

## Security Claim

**Claim:** All deterministically generated passwords in the SMI password manager contain at least 122 bits of Shannon entropy.

**Verification Method:** Statistical sampling with 6-sigma confidence bounds

**Confidence Level:** >99.999999% (6-sigma covers 99.999999% of normal distribution)

## Algorithm Details

### Password Generation
```
1. HKDF-Extract(SHA-256, SALT, IKM) -> PRK
2. HKDF-Expand(SHA-256, PRK, info, len_bytes) -> OKM
3. Base95-Encode(OKM) -> Password String
```

### Entropy Calculation
```
Shannon Entropy = -Σ p(x) * log2(p(x)) * length
where:
  - x iterates over each unique character in the password
  - p(x) is the probability of character x
  - length is the total number of characters
```

### Parameters
- IKM: 128-bit UUID (16 bytes)
- SALT: 128-bit UUID (16 bytes)
- PRK: 32 bytes (SHA-256 output)
- OKM: 27 bytes (calculated to ensure >= 122 bits after Base95 encoding)
- Password: ~33 Base95 characters

## Reproducibility

The audit is fully reproducible:
- Same inputs (IKM, SALT, algorithm) always produce same outputs
- Results are deterministic (no randomness beyond HKDF, which is deterministic with fixed inputs)
- Can be run on any system with Python 3.6+ and the hkdf package

## Contact

For questions about this audit package, please contact:
- Security My Digital Team
- michel@securemy.digital

## Version History

- v1.0.0: Initial release for third-party audit

---

> *"Security is not a product, but a process. Entropy is not a feature, but a requirement."*, -- SMD Security Team [Security Manifesto, 2025]

$Intent: Provide auditors with clear documentation and tools to verify SMD's 122-bit entropy security claim $


# SMI Password Derivation — Authoritative Specification (v1)

Single source of truth: `lib/spec.py`. All code imports these values; no file
redefines them.

| Parameter        | Canonical value                         |
|------------------|-----------------------------------------|
| IKM              | 256-bit (Argon2id output)               |
| Argon2id         | t=3, m=64 MiB, p=4, hash_len=32         |
| Per-user salt    | `argon2_salt(user_id)` (F4)             |
| KDF              | HKDF-SHA256 (RFC 5869)                   |
| HKDF salt        | `hkdf_salt()` — distinct domain (F4)     |
| OKM length       | 26 bytes                                 |
| Encoding         | Base91                                   |
| Password length  | 32 chars (min; base91 stream)            |
| info(n)          | `okm:v1:26:proof of entropy{n}`          |
| Pipeline capacity| 208 bits  (>= 122 target)                |

## Pipeline
```
master password --Argon2id(argon2_salt(user_id))--> IKM (32B)
  --HKDF-Extract(hkdf_salt())--> PRK
  --HKDF-Expand(info(n), 26B)--> OKM  --Base91--> 32-char password
```

## Superseded (must be updated to match)
- README/AUDIT_README "27 bytes / Base95"  -> 26 bytes / Base91
- smi-password.py "31 bytes / Base95 / 38 chars" -> 26 / Base91 / 32
- "IKM is a 128-bit UUID" -> 256-bit Argon2id output (entropy bounded by the
  master password; see F3)

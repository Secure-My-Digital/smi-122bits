# $Intent: F5 remediation — a CORRECT verifiable OPRF (deterministic + DLEQ). $
#
# The seeder's "V-OPRF" was broken: it used a fresh random blinding key each run
# with no unblinding (so the pepper differed every run -> non-deterministic) and
# never verified the server used the committed key (so not "verifiable").
#
# This is a correct DH-OPRF / VOPRF (RFC 9497 shape) with:
#   * proper blind -> evaluate -> UNBLIND (blind factor cancels) => the output
#     N = H1(x)^k is DETERMINISTIC in the password x and server key k;
#   * a Chaum-Pedersen DLEQ proof that the server used the key committed in its
#     public key Y => the response is VERIFIABLE, tampering is detected.
#
# It runs in a prime-order subgroup (RFC 3526 2048-bit safe prime, order q) using
# stdlib big-ints, so the protocol is demonstrably correct without hand-rolled
# curve code. PRODUCTION: instantiate the same flow over ristretto255 / P-256 via
# a vetted library (RFC 9497), and have server/peppered-env.pl adopt it.

import hashlib
import secrets

# RFC 3526 2048-bit MODP safe prime p = 2q+1
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(_P_HEX, 16)
Q = (P - 1) // 2          # prime order of the QR subgroup
G = 4                     # 2^2 : a generator of the order-q subgroup


def _int(*chunks) -> int:
    h = hashlib.sha256()
    for c in chunks:
        h.update(len(c).to_bytes(4, 'big')); h.update(c)
    return int.from_bytes(h.digest(), 'big')


def hash_to_group(x: bytes) -> int:
    """Map input into the order-q subgroup (square => quadratic residue)."""
    return pow(_int(b'H1', x) % P, 2, P)


# ---- Server (holds key k; Y = g^k is its public commitment) ----------------
class OPRFServer:
    def __init__(self, k: int = None):
        self.k = k or (secrets.randbelow(Q - 1) + 1)
        self.Y = pow(G, self.k, P)

    def evaluate(self, blinded: int):
        Z = pow(blinded, self.k, P)
        # Chaum-Pedersen DLEQ: prove log_G(Y) == log_blinded(Z) (same k)
        t = secrets.randbelow(Q - 1) + 1
        A, B = pow(G, t, P), pow(blinded, t, P)
        c = _int(b'DLEQ', str(G).encode(), str(self.Y).encode(),
                 str(blinded).encode(), str(Z).encode(),
                 str(A).encode(), str(B).encode()) % Q
        s = (t + c * self.k) % Q
        return Z, (c, s)


# ---- Client ----------------------------------------------------------------
def blind(x: bytes):
    r = secrets.randbelow(Q - 1) + 1
    P1 = hash_to_group(x)
    return r, pow(P1, r, P)                      # (blind factor, blinded element)


def _verify_dleq(Y, blinded, Z, proof) -> bool:
    c, s = proof
    A = (pow(G, s, P) * pow(Y, (Q - c) % Q, P)) % P          # g^s * Y^-c
    B = (pow(blinded, s, P) * pow(Z, (Q - c) % Q, P)) % P    # blinded^s * Z^-c
    c2 = _int(b'DLEQ', str(G).encode(), str(Y).encode(),
              str(blinded).encode(), str(Z).encode(),
              str(A).encode(), str(B).encode()) % Q
    return c2 == c


def unblind_and_finalize(x: bytes, r: int, Z: int, proof, Y: int) -> bytes:
    """Verify the DLEQ proof, unblind, and derive the deterministic pepper."""
    blinded = pow(hash_to_group(x), r, P)
    if not _verify_dleq(Y, blinded, Z, proof):
        raise ValueError("OPRF DLEQ verification failed: server response rejected")
    r_inv = pow(r, -1, Q)
    N = pow(Z, r_inv, P)                          # = H1(x)^k, r cancels
    return hashlib.sha256(b'OPRF-finalize' + x + N.to_bytes(256, 'big')).digest()


def oprf_pepper(x: bytes, server: OPRFServer) -> bytes:
    r, blinded = blind(x)
    Z, proof = server.evaluate(blinded)
    return unblind_and_finalize(x, r, Z, proof, server.Y)

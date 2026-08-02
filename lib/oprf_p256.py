# $Intent: F5 (complete) — verifiable OPRF over secp256r1 (P-256). $
#
# Correct DH-OPRF / VOPRF (RFC 9497 shape) on the curve the seeder uses:
#   blind:  r <- random scalar;  blinded = r * H2C(password)
#   server: Z = k * blinded  + DLEQ proof that k matches the public key Y = k*G
#   client: VERIFY the DLEQ proof; unblind  N = r^-1 * Z = k * H2C(password)
#           pepper = SHA256("SMI-OPRF-v1" | password | N)
# => pepper is DETERMINISTIC in the password (r cancels) and VERIFIABLE
#    (a wrong-key or tampered response is rejected).
#
# Pure-Python P-256 (stdlib only) so the protocol is testable end-to-end.
# PRODUCTION NOTE: use a vetted RFC 9497 implementation and RFC 9380 SSWU
# hash-to-curve; the try-increment map here is correct (P-256 cofactor = 1) but
# not constant-time.

import hashlib
import secrets

# --- secp256r1 (NIST P-256) parameters --------------------------------------
P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A  = P - 3
B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G  = (GX, GY)


def _inv(x, m): return pow(x % m, -1, m)


def add(Pt, Qt):
    if Pt is None: return Qt
    if Qt is None: return Pt
    x1, y1 = Pt; x2, y2 = Qt
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if Pt == Qt:
        m = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        m = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    return (x3, (m * (x1 - x3) - y1) % P)


def mul(k, Pt):
    k %= N; R = None
    while k:
        if k & 1: R = add(R, Pt)
        Pt = add(Pt, Pt); k >>= 1
    return R


def _hash_int(*parts):
    h = hashlib.sha256()
    for p in parts:
        b = p if isinstance(p, bytes) else str(p).encode()
        h.update(len(b).to_bytes(4, 'big')); h.update(b)
    return int.from_bytes(h.digest(), 'big')


def hash_to_curve(data: bytes):
    """Deterministic map password -> curve point (try-increment; cofactor 1)."""
    for ctr in range(256):
        x = _hash_int(b'SMI-H2C-v1', data, bytes([ctr])) % P
        rhs = (x * x * x + A * x + B) % P
        if pow(rhs, (P - 1) // 2, P) == 1:              # quadratic residue?
            y = pow(rhs, (P + 1) // 4, P)               # P % 4 == 3
            return (x, y if y % 2 == 0 else P - y)
    raise RuntimeError("hash_to_curve failed")


def _pt(b): return b                                    # points are (x,y) tuples
def _enc(Pt): return Pt[0].to_bytes(32, 'big') + Pt[1].to_bytes(32, 'big')


# --- Server (holds key k; publishes Y = k*G) --------------------------------
class OPRFServer:
    def __init__(self, k=None):
        self.k = k or (secrets.randbelow(N - 1) + 1)
        self.Y = mul(self.k, G)

    def evaluate(self, blinded):
        Z = mul(self.k, blinded)
        t = secrets.randbelow(N - 1) + 1
        Ap, Bp = mul(t, G), mul(t, blinded)
        c = _hash_int(b'DLEQ', _enc(G), _enc(self.Y), _enc(blinded), _enc(Z), _enc(Ap), _enc(Bp)) % N
        s = (t + c * self.k) % N
        return Z, (c, s)


# --- Client -----------------------------------------------------------------
def blind(password: bytes):
    r = secrets.randbelow(N - 1) + 1
    return r, mul(r, hash_to_curve(password))


def verify_dleq(Y, blinded, Z, proof) -> bool:
    c, s = proof
    Ap = add(mul(s, G), mul((N - c) % N, Y))            # s*G - c*Y
    Bp = add(mul(s, blinded), mul((N - c) % N, Z))      # s*blinded - c*Z
    c2 = _hash_int(b'DLEQ', _enc(G), _enc(Y), _enc(blinded), _enc(Z), _enc(Ap), _enc(Bp)) % N
    return c2 == c


def unblind_finalize(password: bytes, r: int, Z, proof, Y) -> bytes:
    blinded = mul(r, hash_to_curve(password))
    if not verify_dleq(Y, blinded, Z, proof):
        raise ValueError("OPRF DLEQ verification failed — response rejected")
    N_pt = mul(_inv(r, N), Z)                           # = k * H2C(password)
    return hashlib.sha256(b'SMI-OPRF-v1' + password + _enc(N_pt)).digest()


def run_client(password: bytes, transport, server_pubkey):
    """transport(blinded_bytes) -> (Z_point, proof). Returns the pepper bytes."""
    r, blinded = blind(password)
    Z, proof = transport(_enc(blinded))
    return unblind_finalize(password, r, Z, proof, server_pubkey)


def oprf_pepper(password: bytes, server: OPRFServer) -> bytes:
    return run_client(password, lambda bb: server.evaluate((int.from_bytes(bb[:32],'big'),
                                                             int.from_bytes(bb[32:],'big'))),
                      server.Y)


# --- Production CLI: blind -> query seeder -> verify -> unblind -> pepper -----
def _point_from_hex(h):
    b = bytes.fromhex(h)
    return (int.from_bytes(b[:32], 'big'), int.from_bytes(b[32:64], 'big'))


def main():
    """Read password from stdin; print JSON {oprf_pepper, mask, key_version}.

    Env:
      SEEDER_URL          V-OPRF eval endpoint
      SMI_OPRF_PUBKEY     PINNED server public key Y (128 hex chars, x||y).
                          Pinned (not taken from the response) so a malicious
                          server cannot verify its own forged key.
      KEY_VERSION         optional
    Seeder response JSON must include:
      evaluated_element (hex x||y), dleq_proof {c, s} (decimal), mask (hex),
      key_version.  Missing dleq_proof => client FAILS CLOSED.
    """
    import json, os, sys, urllib.request
    pw = sys.stdin.buffer.read().rstrip(b"\n")
    pub_hex = os.environ["SMI_OPRF_PUBKEY"]
    Y = _point_from_hex(pub_hex)
    url = os.environ["SEEDER_URL"]
    key_ver = os.environ.get("KEY_VERSION", "v1")

    def transport(blinded_bytes):
        body = json.dumps({"blinded_element": blinded_bytes.hex(),
                           "key_version": key_ver}).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        transport.mask = resp.get("mask")
        transport.key_version = resp.get("key_version", key_ver)
        proof = resp.get("dleq_proof")
        if not proof:
            raise ValueError("seeder returned no dleq_proof — unverifiable")
        Z = _point_from_hex(resp["evaluated_element"])
        return Z, (int(proof["c"]), int(proof["s"]))

    pepper = run_client(pw, transport, Y)
    print(json.dumps({"oprf_pepper": pepper.hex(),
                      "mask": transport.mask,
                      "key_version": transport.key_version}))


if __name__ == "__main__":
    main()

"""Thin wrapper around py_arkworks_bls12381 (BLS12-381).

All scalars are handled as Python ints modulo R and converted at the boundary,
so the scheme code reads like the paper.
"""
import hashlib
import secrets
from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar

# order of G1, G2, GT
R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

G1 = G1Point()          # generator g1
G2 = G2Point()          # generator g2
ID1 = G1Point.identity()
ID2 = G2Point.identity()


def rand_scalar():
    """Uniform element of Z_R."""
    return secrets.randbelow(R)


# py_arkworks_bls12381 changed its API between versions (0.3.x on Python 3.9
# has no from_be_bytes_mod_order and no hash_to_curve), so we support both.
_HAS_BE = hasattr(Scalar, "from_be_bytes_mod_order")
_HAS_H2C = hasattr(G1Point, "hash_to_curve")


def sc(x):
    """Python int -> library Scalar (reduced mod R)."""
    x %= R
    if _HAS_BE:
        return Scalar.from_be_bytes_mod_order(x.to_bytes(32, "big"))
    return Scalar.from_le_bytes(x.to_bytes(32, "little"))


def g1(x):
    return G1 * sc(x)


def g2(x):
    return G2 * sc(x)


def mul(P, x):
    """P^x for a G1 or G2 point P (written multiplicatively in the paper)."""
    return P * sc(x)


def msm1(points, scalars):
    return G1Point.multiexp_unchecked(list(points), [sc(s) for s in scalars])


def msm2(points, scalars):
    return G2Point.multiexp_unchecked(list(points), [sc(s) for s in scalars])


def prod(points, identity):
    acc = identity
    for P in points:
        acc = acc + P
    return acc


def pair(P, Q):
    return GT.pairing(P, Q)


def multi_pair(Ps, Qs):
    return GT.multi_pairing(list(Ps), list(Qs))


def enc(*items):
    """Unambiguous byte encoding of points, ints, bytes, strings and tuples."""
    out = bytearray()
    for it in items:
        if isinstance(it, (G1Point, G2Point)):
            b = bytes(it.to_compressed_bytes())
        elif isinstance(it, int):
            b = it.to_bytes(48, "big", signed=False)
        elif isinstance(it, str):
            b = it.encode()
        elif isinstance(it, (bytes, bytearray)):
            b = bytes(it)
        elif isinstance(it, (list, tuple)):
            b = enc(*it)
        else:
            raise TypeError(type(it))
        out += len(b).to_bytes(4, "big") + b
    return bytes(out)


# base field prime and G1 cofactor (used only by the fallback below)
_P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
_H1 = 0x396C8C005555E1568C00AAAB0000AAAB


def _hash_to_g1_fallback(dst: bytes, msg: bytes):
    """Try-and-increment hash into G1 for old library versions.

    Hash to an x-coordinate, keep the first one that lies on the curve, then
    clear the cofactor. The discrete log of the output is unknown, so it is a
    valid random oracle for this PoC, but it is not constant time and it is
    not the RFC 9380 encoding (outputs differ from the newer library).
    """
    ctr = 0
    while True:
        h = b""
        for k in range(2):
            h += hashlib.sha256(dst + b"|try|" + ctr.to_bytes(4, "big") + bytes([k]) + msg).digest()
        x = int.from_bytes(h, "big") % _P
        b = bytearray(x.to_bytes(48, "big"))
        b[0] |= 0x80                      # compressed-encoding flag
        if h[-1] & 1:
            b[0] |= 0x20                  # choose y sign from the hash
        try:
            P = G1Point.from_compressed_bytes_unchecked(bytes(b))
        except Exception:
            ctr += 1
            continue
        P = P * Scalar.from_le_bytes(_H1.to_bytes(32, "little"))
        if P != ID1:
            return P
        ctr += 1


def hash_to_g1(dst: bytes, *items):
    """Random oracle into G1 (RFC 9380 hash-to-curve when available)."""
    if _HAS_H2C:
        return G1Point.hash_to_curve(enc(*items), dst)     # library order: (msg, dst)
    return _hash_to_g1_fallback(dst, enc(*items))


def hash_to_zr(dst: bytes, *items):
    """Random oracle into Z_R (64 bytes of SHA-256 output reduced mod R)."""
    data = enc(*items)
    h = hashlib.sha256(dst + b"|0|" + data).digest() + hashlib.sha256(dst + b"|1|" + data).digest()
    return int.from_bytes(h, "big") % R


def lagrange_at(points, i, x):
    """lambda_i^{points}(x) in Z_R."""
    num, den = 1, 1
    for j in points:
        if j != i:
            num = num * (x - j) % R
            den = den * (i - j) % R
    return num * pow(den, -1, R) % R


def poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % R
    return acc

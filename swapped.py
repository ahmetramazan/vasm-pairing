"""Verification of all schemes with the groups swapped: public keys (MPK, pk_j, apk,
pk_j^{a_j}) in G1, the hashes H0, H2 and the signatures in G2.

The schemes and their security arguments do not change under this swap; only the cost
of each operation does. This module is used for the second verification table of the
paper (bench.py --verify). The signatures are computed directly from the secret scalars
(the verifier only sees public data); the setups are the ones of vasm.py / msp_based.py.
"""
from py_arkworks_bls12381 import G1Point, G2Point, GT
from groups import R, G1, ID1, ID2, sc, g1, prod, multi_pair, enc, hash_to_zr
from vasm import DST_VASM
from msp_based import DST_H0, DST_H1, DST_H2

NEG_G1 = -G1


def hash_to_g2(dst, *items):
    """Random oracle into G2 (RFC 9380 hash-to-curve)."""
    return G2Point.hash_to_curve(enc(*items), dst)


# ---------------------------------------------------------------- vASM
def vasm_group(gid, mks):
    """The group data of vASM with keys in G1: gid and MPK = (g1^{mk_1}, ..., g1^{mk_n})."""
    return gid, [g1(k) for k in mks]


def vasm_sign(gid, mks, S, m):
    x = sum(mks[i - 1] for i in S) % R
    return hash_to_g2(DST_VASM, gid, m) * sc(x)


def vasm_verify(group, S, m, sigma):
    """e(prod_{i in S} mpk_i, H0(gid, m)) == e(g1, sigma)."""
    gid, MPK = group
    apk_S = prod((MPK[i - 1] for i in S), ID1)
    return multi_pair([apk_S, NEG_G1], [hash_to_g2(DST_VASM, gid, m), sigma]) == GT.one()


# ---------------------------------------------------------------- BDN, ASMwSA / ASMwCA
class MSPGroup1:
    """What a verifier computes once per group, keys in G1: apk, pk_j^{a_j} and,
    optionally, H2(apk, j) in G2."""

    def __init__(self, PK, with_h2=False):
        a = [hash_to_zr(DST_H1, pk, PK) for pk in PK]
        self.a = a
        self.apk = G1Point.multiexp_unchecked(list(PK), [sc(x) for x in a])
        self.wpk = [pk * sc(x) for pk, x in zip(PK, a)]
        self.h2 = [hash_to_g2(DST_H2, self.apk, j) for j in range(1, len(PK) + 1)] if with_h2 else None

    def H2(self, j):
        return self.h2[j - 1] if self.h2 is not None else hash_to_g2(DST_H2, self.apk, j)


def msp_example(sks, S, m):
    """Keys in G1; returns (group without H2, group with H2, BDN signature, ASMwSA signature)."""
    PK = [g1(s) for s in sks]
    grp, grp_h2 = MSPGroup1(PK), MSPGroup1(PK, with_h2=True)
    h0 = hash_to_g2(DST_H0, grp.apk, m)
    h2S = prod((grp_h2.H2(j) for j in S), ID2)
    ask = sum(x * s for x, s in zip(grp.a, sks)) % R
    bdn_s = h0 * sc(sum(sks[i - 1] for i in S)) + h2S * sc(ask)
    bdn = (bdn_s, prod((PK[i - 1] for i in S), ID1))          # sigma = (s, pk), as in BDN
    sa = (h0 + h2S) * sc(sum(grp.a[i - 1] * sks[i - 1] for i in S))
    return grp, grp_h2, bdn, sa


def bdn_verify(grp, S, m, sigma):
    """e(pk, H0(apk, m)) e(apk, prod_{i in S} H2(apk, i)) == e(g1, s)."""
    s, pk = sigma
    h2S = prod((grp.H2(j) for j in S), ID2)
    return multi_pair([pk, grp.apk, NEG_G1], [hash_to_g2(DST_H0, grp.apk, m), h2S, s]) == GT.one()


def sa_verify(grp, S, m, sigma):
    """e(spk_S, H0(apk, m) prod_{j in S} H2(apk, j)) == e(g1, sigma), spk_S from pk_j^{a_j}."""
    spk = prod((grp.wpk[j - 1] for j in S), ID1)
    h = hash_to_g2(DST_H0, grp.apk, m) + prod((grp.H2(j) for j in S), ID2)
    return multi_pair([spk, NEG_G1], [h, sigma]) == GT.one()

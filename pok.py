"""Proofs of knowledge of all discrete logs C_k = g2^{a_k} (paper, Section 3.3).

d+1 Schnorr proofs that share one challenge, made non-interactive with the
Fiat-Shamir transformation:

    R_k = g2^{rho_k},   c = H_pok(ctx, C, R),   z_k = rho_k + c * a_k,
    proof = (c, [z_0, ..., z_d]).

The verifier recomputes R_k = g2^{z_k} C_k^{-c} and checks that c is the hash.
The paper proves the schemes secure with these proofs in the algebraic group
model with random oracles, where the witness is extracted without rewinding
(Lemma "Straight-line extraction").
"""
from groups import G2, R, rand_scalar, g2, msm2, hash_to_zr

DST_POK = b"vASM-v2-POK"


def _scalar(x):
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < R


def prove(ctx, coeffs, C):
    rho = [rand_scalar() for _ in coeffs]
    Rk = [g2(r) for r in rho]
    c = hash_to_zr(DST_POK, ctx, C, Rk)
    z = [(r + c * a) % R for r, a in zip(rho, coeffs)]
    return (c, z)


def verify(ctx, C, proof):
    try:
        c, z = proof
        z = list(z)
    except (TypeError, ValueError):
        return False
    if len(z) != len(C) or not _scalar(c) or not all(_scalar(zk) for zk in z):
        return False
    Rk = [msm2([G2, Ck], [zk, -c % R]) for Ck, zk in zip(C, z)]
    return c == hash_to_zr(DST_POK, ctx, C, Rk)


def size_bytes(proof):
    """Size of the proof with 32-byte scalars: (d + 2) * 32."""
    c, z = proof
    return 32 * (1 + len(z))

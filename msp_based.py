"""BDN's ASM (baseline) and our ASMwSA / ASMwCA (paper, Section 6).

All three share the MSP key aggregation a_i = H1(pk_i, PK), apk = prod pk_i^{a_i}.
A verifier derives everything it needs from PK itself, once per group (MSPGroup):
apk for all schemes, the weighted keys pk_j^{a_j} from which it computes the
subgroup key spk of ASMwSA / ASMwCA, and optionally BDN's H2(apk, j) values.
spk is never taken from the signer or the combiner: with a chosen spk = g2^x,
sigma = (H0(apk,m) prod_{j in S} H2(apk,j))^x would verify for every S and m.
"""
from dataclasses import dataclass
from py_arkworks_bls12381 import GT
from groups import (R, G2, ID1, ID2, rand_scalar, g2, mul, msm2, prod, multi_pair,
                    hash_to_g1, hash_to_zr, enc, valid_subgroup)
import pok

DST_H0 = b"MSP-ASM-v2-H0"
DST_H1 = b"MSP-ASM-v2-H1"
DST_H2 = b"MSP-ASM-v2-H2"


def keygen():
    sk = rand_scalar()
    return sk, g2(sk)


# ------------------------------------------------- key proofs (ASMwSA / ASMwCA)
# Each key carries a Fiat-Shamir proof of knowledge of sk (paper: Prop. subsetsum and
# the fix chosen for the journal version).  ctx = ("ASM-key", pk).
def keygen_with_proof():
    sk, pk = keygen()
    return sk, pk, pok.prove(enc("ASM-key", pk), [sk], [pk])


def check_keys(PK, proofs):
    """Group-setup check: distinct keys and a valid proof for every key."""
    if len(set(bytes(pk.to_compressed_bytes()) for pk in PK)) != len(PK):
        return False
    return all(pok.verify(enc("ASM-key", pk), [pk], pr) for pk, pr in zip(PK, proofs))


def coefficients(PK):
    return [hash_to_zr(DST_H1, pk, PK) for pk in PK]


def aggregate_key(PK, a):
    return msm2(PK, a)


def H0(apk, m):
    return hash_to_g1(DST_H0, apk, m)


def H2(apk, j):
    return hash_to_g1(DST_H2, apk, j)


def mu_values(i, sk, PK):
    """mu_{ij} = H2(apk, j)^{a_i sk_i} for j = 1..n."""
    a = coefficients(PK)
    apk = aggregate_key(PK, a)
    e = a[i - 1] * sk % R
    return apk, {j: mul(H2(apk, j), e) for j in range(1, len(PK) + 1)}


def subgroup_key(PK, a, S):
    return msm2([PK[i - 1] for i in S], [a[i - 1] for i in S])


@dataclass
class MSPGroup:
    """Per-group values a verifier computes once from PK."""
    PK: list
    a: list
    apk: object
    wpk: list            # wpk[j-1] = pk_j^{a_j}
    h2: list = None      # h2[j-1] = H2(apk, j), only for the cached BDN verifier


def msp_group(PK, proofs=None, with_h2=False):
    """A verifier's per-group step. Pass the key proofs when PK comes from an
    untrusted source: the group is then accepted only if the keys are distinct and
    every proof verifies (paper, ASMwSA verification step). Without proofs, the caller
    must already trust PK, e.g. because it ran check_keys itself."""
    if proofs is not None and not check_keys(PK, proofs):
        raise ValueError("keys are not distinct or a key proof does not verify")
    a = coefficients(PK)
    apk = aggregate_key(PK, a)
    wpk = [mul(pk, aj) for pk, aj in zip(PK, a)]
    h2 = [H2(apk, j) for j in range(1, len(PK) + 1)] if with_h2 else None
    return MSPGroup(list(PK), a, apk, wpk, h2)


# ---------------------------------------------------------------- BDN ASM (baseline)
def bdn_setup(sks):
    """One interactive round: member i sends mu_{ij} to member j; mk_j = prod_i mu_{ij}."""
    PK = [g2(s) for s in sks]
    mus = [mu_values(i + 1, s, PK)[1] for i, s in enumerate(sks)]
    a = coefficients(PK)
    apk = aggregate_key(PK, a)
    mks = [prod((mus[i][j] for i in range(len(sks))), ID1) for j in range(1, len(sks) + 1)]
    return PK, apk, mks


def bdn_sign_share(apk, sk, mk, m):
    return mul(H0(apk, m), sk) + mk


def bdn_combine(PK, S, shares):
    return prod(shares, ID1), prod((PK[i - 1] for i in S), ID2)


def bdn_verify(apk, S, m, sigma, n=None):
    if not valid_subgroup(S, n):
        return False
    s, pk = sigma
    h2 = prod((H2(apk, j) for j in S), ID1)
    return multi_pair([H0(apk, m), h2, -s], [pk, apk, G2]) == GT.one()


def bdn_verify_cached(grp, S, m, sigma):
    """BDN verification with the message-independent H2(apk, j) stored per group."""
    if not valid_subgroup(S, len(grp.PK)):
        return False
    s, pk = sigma
    h2 = prod((grp.h2[j - 1] for j in S), ID1)
    return multi_pair([H0(grp.apk, m), h2, -s], [pk, grp.apk, G2]) == GT.one()


# ---------------------------------------------------------------- ASMwSA
def asmwsa_sign_share(PK, i, sk, mus, apk, S, m):
    a_i = coefficients(PK)[i - 1]
    smk = prod((mus[j] for j in S), ID1)
    return mul(H0(apk, m), a_i * sk % R) + smk


def sa_verify(grp, S, m, sigma):
    """e(H0(apk,m) * prod_{j in S} H2(apk,j), spk_S) == e(sigma, g2), where the
    verifier computes spk_S = prod_{j in S} pk_j^{a_j} from its MSPGroup (ASMwSA and ASMwCA).
    If the group values include the H2(apk, j), they are used instead of hashing."""
    if not valid_subgroup(S, len(grp.PK)):
        return False
    spk = prod((grp.wpk[j - 1] for j in S), ID2)
    if grp.h2 is not None:
        h2 = prod((grp.h2[j - 1] for j in S), ID1)
    else:
        h2 = prod((H2(grp.apk, j) for j in S), ID1)
    return multi_pair([H0(grp.apk, m) + h2, -sigma], [spk, G2]) == GT.one()


# ---------------------------------------------------------------- ASMwCA
def asmwca_sign_share(PK, i, sk, mu_ii, apk, m):
    a_i = coefficients(PK)[i - 1]
    return mul(H0(apk, m), a_i * sk % R) + mu_ii


def asmwca_combine(S, shares, mus_to_combiner):
    """shares[i] = s_i; mus_to_combiner[i][j] = mu_{ij} for j != i."""
    acc = ID1
    for i in S:
        acc = acc + shares[i]
        for j in S:
            if j != i:
                acc = acc + mus_to_combiner[i][j]
    return acc

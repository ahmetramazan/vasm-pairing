"""Full aggregation (paper, Section 7): Sigma = prod sigma_k, N+1 pairings."""
from py_arkworks_bls12381 import GT
from groups import G2, ID1, ID2, prod, multi_pair
import vasm
import msp_based as mb


def aggregate(sigmas):
    return prod(sigmas, ID1)


def avasm_verify(items, Sigma):
    """items: list of (gpk, S, m)."""
    Ps = [vasm.H0(gpk, m) for gpk, S, m in items]
    Qs = [prod((gpk.MPK[i - 1] for i in S), ID2) for gpk, S, m in items]
    return multi_pair(Ps + [-Sigma], Qs + [G2]) == GT.one()


def aasm_sa_verify(items, Sigma):
    """items: list of (grp, S, m) for ASMwSA / ASMwCA signatures, grp = mb.msp_group(PK)
    computed by the verifier; spk_S is computed from grp, never taken from the signature."""
    Ps, Qs = [], []
    for grp, S, m in items:
        Ps.append(mb.H0(grp.apk, m) + prod((mb.H2(grp.apk, j) for j in S), ID1))
        Qs.append(prod((grp.wpk[j - 1] for j in S), ID2))
    return multi_pair(Ps + [-Sigma], Qs + [G2]) == GT.one()

import vasm
import msp_based as mb
import aggregate as ag
from groups import rand_scalar


def test_avasm_two_groups():
    items, sigs = [], []
    for n, S, m in [(3, [1, 2], b"a"), (4, [2, 3, 4], b"b")]:
        mks, gpk = vasm.run_setup([rand_scalar() for _ in range(n)])
        sigs.append(vasm.combine([vasm.sign_share(gpk, mks[i - 1], m) for i in S]))
        items.append((gpk, S, m))
    Sigma = ag.aggregate(sigs)
    assert ag.avasm_verify(items, Sigma)
    assert not ag.avasm_verify(items[:1], Sigma)


def test_aasmwsa():
    items, sigs = [], []
    for n, S, m in [(3, [1, 3], b"x"), (3, [2], b"y")]:
        sks = [rand_scalar() for _ in range(n)]
        PK = [mb.g2(s) for s in sks]
        shares = []
        for i in S:
            apk, mus = mb.mu_values(i, sks[i - 1], PK)
            shares.append(mb.asmwsa_sign_share(PK, i, sks[i - 1], mus, apk, S, m))
        sigs.append(sum(shares[1:], shares[0]))
        items.append((mb.msp_group(PK), S, m))
    assert ag.aasm_sa_verify(items, ag.aggregate(sigs))

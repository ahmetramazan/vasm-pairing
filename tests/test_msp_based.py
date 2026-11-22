import pytest
import random
import msp_based as mb
from groups import rand_scalar


def _group(n):
    sks = [rand_scalar() for _ in range(n)]
    PK = [mb.g2(s) for s in sks]
    return sks, PK


def test_bdn_asm():
    sks = [rand_scalar() for _ in range(5)]
    PK, apk, mks = mb.bdn_setup(sks)
    S, m = [1, 3, 4], b"m"
    shares = [mb.bdn_sign_share(apk, sks[i - 1], mks[i - 1], m) for i in S]
    sigma = mb.bdn_combine(PK, S, shares)
    assert mb.bdn_verify(apk, S, m, sigma)
    assert not mb.bdn_verify(apk, [1, 3], m, sigma)
    grp = mb.msp_group(PK, with_h2=True)
    assert grp.apk == apk
    assert mb.bdn_verify_cached(grp, S, m, sigma)
    assert not mb.bdn_verify_cached(grp, [1, 3], m, sigma)


def test_asmwsa():
    sks, PK = _group(5)
    S, m = [2, 5], b"m"
    shares = []
    for i in S:
        apk, mus = mb.mu_values(i, sks[i - 1], PK)
        shares.append(mb.asmwsa_sign_share(PK, i, sks[i - 1], mus, apk, S, m))
    sigma = sum(shares[1:], shares[0])
    grp = mb.msp_group(PK)
    assert grp.apk == apk
    assert mb.sa_verify(grp, S, m, sigma)
    assert not mb.sa_verify(grp, [2], m, sigma)
    grp_h2 = mb.msp_group(PK, with_h2=True)
    assert mb.sa_verify(grp_h2, S, m, sigma)
    assert not mb.sa_verify(grp_h2, [2], m, sigma)


def test_asmwsa_spk_is_computed_by_the_verifier():
    """A signature made for a chosen spk = g2^x must not verify (K2 of the review):
    the verifier computes spk_S from PK and never takes it from the signer."""
    from groups import mul
    sks, PK = _group(4)
    grp = mb.msp_group(PK)
    S, m, x = [1, 2], b"forged", rand_scalar()
    P = mb.H0(grp.apk, m) + mb.H2(grp.apk, 1) + mb.H2(grp.apk, 2)
    assert not mb.sa_verify(grp, S, m, mul(P, x))


def test_asmwca():
    sks, PK = _group(4)
    mus = {}
    for i in range(1, 5):
        apk, mus[i] = mb.mu_values(i, sks[i - 1], PK)
    S, m = [1, 2, 4], b"m"
    shares = {i: mb.asmwca_sign_share(PK, i, sks[i - 1], mus[i][i], apk, m) for i in S}
    to_combiner = {i: {j: mus[i][j] for j in mus[i] if j != i} for i in mus}
    sigma = mb.asmwca_combine(S, shares, to_combiner)
    assert mb.sa_verify(mb.msp_group(PK), S, m, sigma)


# ------------------------------------------------ key proofs and the subset-sum attack
def test_key_proofs():
    keys = [mb.keygen_with_proof() for _ in range(3)]
    PK = [k[1] for k in keys]
    proofs = [k[2] for k in keys]
    assert mb.check_keys(PK, proofs)
    assert not mb.check_keys(PK + [PK[0]], proofs + [proofs[0]])      # duplicate key
    # a proof for one key does not verify for another key
    assert not mb.check_keys([PK[1]], [proofs[0]])


def test_verifier_group_step_checks_key_proofs():
    keys = [mb.keygen_with_proof() for _ in range(3)]
    PK = [k[1] for k in keys]
    proofs = [k[2] for k in keys]
    assert mb.msp_group(PK, proofs).apk == mb.msp_group(PK).apk
    with pytest.raises(ValueError):
        mb.msp_group(PK, [proofs[1], proofs[0], proofs[2]])           # proofs swapped
    with pytest.raises(ValueError):
        mb.msp_group(PK + [PK[0]], proofs + [proofs[0]])              # repeated key


def test_subset_sum_attack_without_key_proofs(monkeypatch):
    """Prop. subsetsum: if a_iota + sum_{S\\iota} a_j = 0 mod q, then spk_S = g2^y.

    Finding such S needs a modular subset-sum solver (Wagner); here we simulate a
    solved instance by fixing the coefficients, to check the algebra on the curve.
    """
    from groups import R, rand_scalar, mul, g2
    sk_star = rand_scalar()
    pk_star = g2(sk_star)
    y = [rand_scalar(), rand_scalar()]
    PK = [pk_star, pk_star + g2(y[0]), pk_star + g2(y[1])]          # pk_j = pk* . g2^{y_j}
    a1, a2 = rand_scalar(), rand_scalar()
    a = [a1, a2, (-a1 - a2) % R]                                    # "solved" subset sum
    monkeypatch.setattr(mb, "coefficients", lambda PK_: a)
    apk = mb.aggregate_key(PK, a)
    S, m = [1, 2, 3], b"forged without the honest key"
    yS = (a[1] * y[0] + a[2] * y[1]) % R
    assert mb.subgroup_key(PK, a, S) == g2(yS)
    P = mb.H0(apk, m) + mb.H2(apk, 1) + mb.H2(apk, 2) + mb.H2(apk, 3)
    sigma = mul(P, yS)
    assert mb.sa_verify(mb.msp_group(PK), S, m, sigma)              # forgery verifies
    # With key proofs the rogue keys are rejected: the adversary cannot prove
    # knowledge of sk_j = sk* + y_j; a proof made with y_j alone fails.
    import pok
    from groups import enc
    bad = [pok.prove(enc("ASM-key", PK[j]), [y[j - 1]], [PK[j]]) for j in (1, 2)]
    assert not mb.check_keys(PK[1:], bad)


def test_subgroup_must_be_valid():
    sks = [rand_scalar() for _ in range(4)]
    PK, apk, mks = mb.bdn_setup(sks)
    S, m = [1, 4], b"m"
    shares = []
    for i in S:
        _, mus = mb.mu_values(i, sks[i - 1], PK)
        shares.append(mb.asmwsa_sign_share(PK, i, sks[i - 1], mus, apk, S, m))
    sigma = shares[0] + shares[1]
    grp_h2 = mb.msp_group(PK, with_h2=True)
    assert mb.sa_verify(grp_h2, S, m, sigma)
    assert not mb.sa_verify(grp_h2, [1, 0], m, sigma)
    bsig = mb.bdn_combine(PK, S, [mb.bdn_sign_share(apk, sks[i - 1], mks[i - 1], m) for i in S])
    assert mb.bdn_verify_cached(grp_h2, S, m, bsig)
    assert not mb.bdn_verify_cached(grp_h2, [1, 0], m, bsig)

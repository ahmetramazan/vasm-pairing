"""The attacks of Section 5.2, run on the real curve.

Honest member iota = 1 is a real vasm.Member; members 2..n are the adversary.
"""
import random
import pytest
import vasm
from groups import (R, G2, rand_scalar, g2, mul, msm2, lagrange_at, poly_eval, enc)
from vasm import Member, GroupPublic, H0, SetupError

IOTA = 1


def _cancel_poly(n, S, need_zero_at_0):
    """g with g(iota)=0, sum_{i in S} g(i) = -1 (and g(0)=0 if requested)."""
    shift = 1 if need_zero_at_0 else 0
    for e in range(n - 1 - shift):
        sg = sum((i - IOTA) * pow(i, e + shift, R) for i in S) % R
        if sg:
            c = (-pow(sg, -1, R)) % R
            g = [0] * n
            g[e + shift + 1] = (g[e + shift + 1] + c) % R
            g[e + shift] = (g[e + shift] - c * IOTA) % R
            return g
    pytest.skip("no cancelling polynomial for this S")


def rogue_setup(n, S, honest_use_pok, corrupt_keys_have_pop):
    """Rushing adversary of Prop. 1. Returns (honest_result_or_exception, forge_fn)."""
    idx = list(range(1, n + 1))
    corrupt = [j for j in idx if j != IOTA]
    j0 = corrupt[0]
    sk_star, pk_star = vasm.keygen()
    g = _cancel_poly(n, S, need_zero_at_0=corrupt_keys_have_pop)
    lam = lagrange_at(idx, IOTA, 0)
    d = g[0] * pow(lam, -1, R) % R            # pk_j0 = pk*^d g2^u, fixed BEFORE setup
    u = {j: rand_scalar() for j in corrupt}
    PK = [None] * n
    PK[IOTA - 1] = pk_star
    for j in corrupt:
        PK[j - 1] = (mul(pk_star, d) + g2(u[j])) if j == j0 else g2(u[j])
    honest = Member(IOTA, sk_star, PK, use_pok=honest_use_pok)
    (C_h, proof_h), shares_h = honest.round1()
    # adversary learns f*(j) for j != iota and computes g2^t
    K = sum(lagrange_at(idx, j, 0) * shares_h[j] for j in corrupt) % R
    gt = msm2(C_h, [pow(IOTA, k, R) for k in range(n)])
    polys, broadcasts = {}, {IOTA: (C_h, proof_h)}
    for j in corrupt:
        if j == j0:
            b = [rand_scalar() for _ in range(n)]
            b[0] = (u[j] + d * K) % R
            C = [g2(b[k]) + mul(gt, g[k]) for k in range(n)]
            polys[j] = b                       # the t-free part the adversary knows
        else:
            b = [u[j]] + [rand_scalar() for _ in range(n - 1)]
            C = [g2(x) for x in b]
            polys[j] = b
        broadcasts[j] = (C, None)              # cannot prove knowledge of t-dependent coeffs
    my_shares = {IOTA: shares_h[IOTA]}
    for j in corrupt:
        my_shares[j] = poly_eval(polys[j], IOTA)   # t-free since g(iota) = 0
    try:
        res = honest.finish(broadcasts, my_shares)
    except SetupError as e:
        res = e

    def forge(gpk, m):
        T = (sum(shares_h[i] for i in S if i != IOTA)
             + sum(poly_eval(polys[j], i) for j in corrupt for i in S)) % R
        return mul(H0(gpk, m), T)
    return res, forge


@pytest.mark.parametrize("n,S", [(2, [1, 2]), (3, [1, 3]), (4, [1, 2, 4]), (5, [1, 2, 3, 4, 5])])
def test_prop1_attack_breaks_setup_without_pok(n, S):
    res, forge = rogue_setup(n, S, honest_use_pok=False, corrupt_keys_have_pop=False)
    assert not isinstance(res, Exception), "honest member should accept"
    mk, gpk = res
    for m in [b"drain the bridge", b"any other message"]:
        assert vasm.verify(gpk, S, m, forge(gpk, m))


@pytest.mark.parametrize("n,S", [(3, [1, 3]), (4, [1, 2, 4]), (5, [1, 2])])
def test_prop1_attack_survives_pop_on_keys(n, S):
    res, forge = rogue_setup(n, S, honest_use_pok=False, corrupt_keys_have_pop=True)
    mk, gpk = res
    assert vasm.verify(gpk, S, b"m", forge(gpk, b"m"))


@pytest.mark.parametrize("n,S", [(2, [1, 2]), (4, [1, 2, 4])])
def test_prop1_attack_stopped_by_pok(n, S):
    res, _ = rogue_setup(n, S, honest_use_pok=True, corrupt_keys_have_pop=False)
    assert isinstance(res, SetupError) and res.reason == "invalid proof of knowledge"


def _prop2(legacy_hash):
    n, idx = 4, [1, 2, 3, 4]
    corrupt = [2, 3, 4]
    sk_star, pk_star = vasm.keygen()
    sk_c = {j: rand_scalar() for j in corrupt}
    PK = [pk_star] + [g2(sk_c[j]) for j in corrupt]
    honest = Member(IOTA, sk_star, PK, use_pok=True, legacy_hash=legacy_hash)
    (C_h, pf_h), sh_h = honest.round1()
    corrupt_members = {j: Member(j, sk_c[j], PK, use_pok=True, legacy_hash=legacy_hash) for j in corrupt}
    outs = {j: corrupt_members[j].round1() for j in corrupt}
    broadcasts = {IOTA: (C_h, pf_h), **{j: outs[j][0] for j in corrupt}}
    my_shares = {IOTA: sh_h[IOTA], **{j: outs[j][1][IOTA] for j in corrupt}}
    mk, gpk = honest.finish(broadcasts, my_shares)
    m = b"pay 1M to Mallory"
    sigma_bls = vasm.bls_sign(sk_star, m)          # honest user's personal BLS signature
    lam = lagrange_at(idx, IOTA, 0)
    K = sum(lagrange_at(idx, j, 0) * sh_h[j] for j in corrupt) % R
    Hm = vasm.hash_to_g1(vasm.DST_BLS, m)
    Ht = mul(sigma_bls + mul(Hm, (-K) % R), pow(lam, -1, R))       # H^t
    S = [1, 2, 3]
    rest = (sum(sh_h[i] for i in S if i != IOTA)
            + sum(poly_eval(corrupt_members[j].coeffs, i) for j in corrupt for i in S)) % R
    forged = Ht + mul(Hm, rest)
    return vasm.verify(gpk, S, m, forged)


def test_prop2_shared_hash_attack_works_with_legacy_hash():
    assert _prop2(legacy_hash=True)


def test_prop2_stopped_by_domain_separation():
    assert not _prop2(legacy_hash=False)


# ------------------------------------------------ duplicate keys (review K1)
def _unchecked_member(i, sk, PK):
    """A Member built without the step-(0) input checks, to show why they are needed."""
    m = Member.__new__(Member)
    m.i, m.sk, m.PK, m.n = i, sk, list(PK), len(PK)
    m.use_pok, m.legacy_hash = True, False
    m.coeffs = [sk] + [rand_scalar() for _ in range(m.n - 1)]
    return m


def _replay_with_duplicate_key(make_member):
    """PK = (pk*, pk*, pk3). The adversary records the honest dealing of a setup in
    which the honest member sits at position 2 (that setup then aborts) and replays
    it at position 2 of a second setup with the same PK, where the honest member sits
    at position 1. Checks (a), (b), (c) pass, and for S = {1, 2} the honest
    contributions cancel because 1/lambda_1(0) + 1/lambda_2(0) = 0 for n = 3."""
    idx = [1, 2, 3]
    sk_star, pk_star = vasm.keygen()
    u3 = rand_scalar()
    PK = [pk_star, pk_star, g2(u3)]
    (C_A, pi_A), sh_A = make_member(2, sk_star, PK).round1()      # setup A
    honB = make_member(1, sk_star, PK)                            # setup B
    (C_B, pi_B), sh_B = honB.round1()
    adv3 = make_member(3, u3, PK)
    (C_3, pi_3), sh_3 = adv3.round1()
    broadcasts = {1: (C_B, pi_B), 2: (C_A, pi_A), 3: (C_3, pi_3)}  # slot 2 = replay of A
    my_shares = {1: sh_B[1], 2: sh_A[1], 3: sh_3[1]}
    mk1, gpk = honB.finish(broadcasts, my_shares)
    lam = {j: lagrange_at(idx, j, 0) for j in idx}
    inv = lambda x: pow(x, -1, R)
    # f_B(1) and f_A(2) are the only unknown terms; their sk* parts are sk*/lam_1 and sk*/lam_2
    tB = (-(lam[2] * sh_B[2] + lam[3] * sh_B[3])) * inv(lam[1]) % R
    tA = (-(lam[1] * sh_A[1] + lam[3] * sh_A[3])) * inv(lam[2]) % R
    T = (tB + sh_B[2] + sh_A[1] + tA + sh_3[1] + sh_3[2]) % R
    m = b"signed without the honest member"
    return vasm.verify(gpk, [1, 2], m, mul(H0(gpk, m), T))


def test_duplicate_key_replay_forges_without_the_check():
    assert _replay_with_duplicate_key(_unchecked_member)


def test_duplicate_keys_are_refused_before_sending():
    with pytest.raises(SetupError) as e:
        _replay_with_duplicate_key(Member)
    assert e.value.blame is None and "not distinct" in e.value.reason


def test_member_refuses_a_foreign_key_at_its_position():
    sk_star, pk_star = vasm.keygen()
    PK = [g2(rand_scalar()), pk_star]
    with pytest.raises(SetupError):
        Member(1, sk_star, PK)

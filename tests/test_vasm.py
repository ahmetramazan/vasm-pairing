import random
import pytest
import vasm
from groups import rand_scalar, R


@pytest.mark.parametrize("n", [2, 3, 5])
def test_correctness_all_subgroups(n):
    sks = [rand_scalar() for _ in range(n)]
    mks, gpk = vasm.run_setup(sks)
    m = b"transfer 10 ETH"
    for size in range(1, n + 1):
        S = sorted(random.sample(range(1, n + 1), size))
        sig = vasm.combine([vasm.sign_share(gpk, mks[i - 1], m) for i in S])
        assert vasm.verify(gpk, S, m, sig)
        assert not vasm.verify(gpk, S, b"other message", sig)


def test_wrong_subgroup_rejected():
    sks = [rand_scalar() for _ in range(4)]
    mks, gpk = vasm.run_setup(sks)
    sig = vasm.combine([vasm.sign_share(gpk, mks[i - 1], b"m") for i in [1, 2]])
    assert not vasm.verify(gpk, [1, 2, 3], b"m", sig)
    assert not vasm.verify(gpk, [1], b"m", sig)


def test_bad_share_is_blamed():
    sks = [rand_scalar() for _ in range(3)]
    PK = [vasm.g2(s) for s in sks]
    members = [vasm.Member(i + 1, s, PK) for i, s in enumerate(sks)]
    out = [m.round1() for m in members]
    out[2][1][1] = (out[2][1][1] + 1) % R          # member 3 cheats member 1
    broadcasts = {i + 1: out[i][0] for i in range(3)}
    my_shares = {j: out[j - 1][1][1] for j in broadcasts}
    with pytest.raises(vasm.SetupError) as e:
        members[0].finish(broadcasts, my_shares)
    assert e.value.blame == 3


def test_pok_rejects_tampering():
    import pok
    from groups import rand_scalar, g2, R
    a = [rand_scalar() for _ in range(3)]
    C = [g2(x) for x in a]
    p = pok.prove(b"ctx", a, C)
    assert pok.verify(b"ctx", C, p)
    assert pok.size_bytes(p) == 32 * 4
    c, z = p
    z2 = list(z); z2[1] = (z2[1] + 1) % R
    assert not pok.verify(b"ctx", C, (c, z2))                   # changed response
    assert not pok.verify(b"ctx", C, ((c + 1) % R, z))          # changed challenge
    z3 = list(z); z3[0] += R
    assert not pok.verify(b"ctx", C, (c, z3))                   # non-canonical response
    assert not pok.verify(b"ctx", C, (c, z[:2]))                # wrong length
    assert not pok.verify(b"ctx", C, None)
    assert not pok.verify(b"other", C, p)                       # other context
    C2 = list(C); C2[2] = g2(rand_scalar())
    assert not pok.verify(b"ctx", C2, p)                        # other commitments
    # a proof made with a wrong witness does not verify
    bad = pok.prove(b"ctx", [a[0], a[1], (a[2] + 1) % R], C)
    assert not pok.verify(b"ctx", C, bad)


def test_eval_commitments_matches_multiexp():
    from groups import msm2
    C = [vasm.g2(rand_scalar()) for _ in range(6)]
    for x in (1, 2, 5, 6, 255):
        assert vasm.eval_commitments(C, x) == msm2(C, [pow(x, k, R) for k in range(6)])


def test_subgroup_must_be_valid():
    """Index 0 must not select member n, and a repeated index must not count twice."""
    sks = [rand_scalar() for _ in range(4)]
    mks, gpk = vasm.run_setup(sks)
    sig = vasm.combine([vasm.sign_share(gpk, mks[i - 1], b"m") for i in [1, 4]])
    assert vasm.verify(gpk, [1, 4], b"m", sig)
    assert not vasm.verify(gpk, [1, 0], b"m", sig)
    assert not vasm.verify(gpk, [1, 5], b"m", sig)
    twice = vasm.combine([vasm.sign_share(gpk, mks[0], b"m")] * 2)
    assert not vasm.verify(gpk, [1, 1], b"m", twice)


def test_verifier_group_from_com():
    sks = [rand_scalar() for _ in range(3)]
    mks, gpk = vasm.run_setup(sks)
    v = vasm.group_public(gpk.PK, gpk.COM)
    assert v.gid == gpk.gid and v.MPK == gpk.MPK


def test_verifier_checks_dealings():
    """Verifier side of the setup (Section 5.1): it recomputes gid and MPK from the
    published dealings and gets the members' values."""
    sks = [rand_scalar() for _ in range(4)]
    mks, gpk = vasm.run_setup(sks)
    v = vasm.verifier_group(gpk.PK, gpk.dealings)
    assert v.gid == gpk.gid and v.MPK == gpk.MPK
    sig = vasm.combine([vasm.sign_share(gpk, mks[i - 1], b"m") for i in [1, 3]])
    assert vasm.verify(v, [1, 3], b"m", sig)


def test_unchecked_com_is_forgeable_checked_is_not():
    """Remark 3.7: from public keys alone, C_0 = prod pk_j and a chosen C_1 give
    prod_{i in S} mpk_i = g2^x, so H0(gid, m)^x verifies if only COM is used.
    The verifier's check of the dealings rejects such a group."""
    n, S = 4, [1, 2]
    sks = [rand_scalar() for _ in range(n)]
    mks, gpk = vasm.run_setup(sks)
    PK = gpk.PK
    x = rand_scalar()
    C0 = vasm.prod(PK, vasm.ID2)
    t = sum(S) % R
    C1 = (vasm.g2(x) + (-C0) * vasm.sc(len(S))) * vasm.sc(pow(t, -1, R))
    COM = [C0, C1] + [vasm.ID2] * (n - 2)
    fake = vasm.group_public(PK, COM)
    m = b"forged"
    assert vasm.verify(fake, S, m, vasm.mul(vasm.H0(fake, m), x))   # the attack works on COM alone
    # any dealing list that is not the members' own fails the check
    bad = list(gpk.dealings)
    C, proof = bad[1]
    bad[1] = ([C[0], C[1] + vasm.g2(1)] + list(C[2:]), proof)
    with pytest.raises(vasm.SetupError) as e:
        vasm.verifier_group(PK, bad)
    assert e.value.blame == 2

"""Benchmarks for Section 9 of the paper.  Usage:
    python bench.py            # full run, n in 4,16,64 (paper table)
    python bench.py --big      # also n=256 (slow, optional)
    python bench.py --vasm256  # only vASM sign/verify at n=256 (about a minute)
    python bench.py --msp      # only the ASM and ASMwSA/ASMwCA setups, separately
    python bench.py --setup    # setup per member of ASM, ASMwSA/ASMwCA and vASM, n = 4..256
                               # (the 'Setup, per member' rows of the paper; a few minutes)
    python bench.py --sign     # only ASMwSA and ASMwCA signing
    python bench.py --verify   # verification of all schemes, n = 4..256, in both group
                               # orientations, and the cost of single operations
    python bench.py --quick    # n in 4,16 only, to check that everything works
    python bench.py --paper    # every number of Section 9 of the paper, in one run
                               # (results_paper.csv; about 5 minutes)
Writes results.csv (milliseconds: median, min and max of the runs; the number of runs
is in the last column). --verify writes results_verify.csv (keys in G2, as in the
paper), results_verify_swap.csv (keys in G1) and results_ops.csv; --setup writes
results_setup.csv. All proofs of knowledge are Fiat-Shamir proofs (pok.py).
"""
import csv, platform, statistics, sys, time
import vasm
import msp_based as mb
import aggregate as ag
import swapped as sw
from groups import rand_scalar, g2

REPS = 5
REPS_FAST = 21          # sub-millisecond operations (signing, verification, single operations)


def stats(fn, reps=REPS):
    """(median, min, max, runs) of the running time of fn in milliseconds."""
    ts = []
    fn()                                   # warm-up run, not timed
    for _ in range(reps):
        t = time.perf_counter(); fn(); ts.append((time.perf_counter() - t) * 1000)
    return statistics.median(ts), min(ts), max(ts), reps


def timeit(fn, reps=REPS):
    return stats(fn, reps)[0]


def write_csv(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["# " + platform.platform() + " | " + platform.processor() + " | python " + platform.python_version()])
        w.writerow(["operation", "scheme", "n_or_N", "median_ms", "min_ms", "max_ms", "runs"])
        for op, scheme, n, (med, mn, mx, runs) in rows:
            w.writerow([op, scheme, n, f"{med:.3f}", f"{mn:.3f}", f"{mx:.3f}", runs])
    for op, scheme, n, (med, mn, mx, runs) in rows:
        print(f"{op:<18} {scheme:<40} {n:>4}  {med:10.3f} ms  [{mn:.3f}, {mx:.3f}] ({runs} runs)")
    print(f"\nSaved to {path}")


def msp_signed_example(sks, S, m):
    """BDN and ASMwSA signatures of the first l members on m, and the verifier's
    per-group values (MSPGroup) computed once from PK."""
    PK, apk, bmks = mb.bdn_setup(sks)
    bsig = mb.bdn_combine(PK, S, [mb.bdn_sign_share(apk, sks[i - 1], bmks[i - 1], m) for i in S])
    shares = []
    for i in S:
        _, mus = mb.mu_values(i, sks[i - 1], PK)
        shares.append(mb.asmwsa_sign_share(PK, i, sks[i - 1], mus, apk, S, m))
    ssig = sum(shares[1:], shares[0])
    grp = mb.msp_group(PK)                    # apk and pk_j^{a_j}
    grp_h2 = mb.msp_group(PK, with_h2=True)   # ... and H2(apk, j), j = 1..n
    assert mb.bdn_verify(apk, S, m, bsig) and mb.bdn_verify_cached(grp_h2, S, m, bsig)
    assert mb.sa_verify(grp, S, m, ssig) and mb.sa_verify(grp_h2, S, m, ssig)
    return PK, apk, bmks, bsig, ssig, grp, grp_h2


def verify_rows(n, sks, S, m, mks, gpk, reps=REPS):
    """Verification rows of Table 2: vASM; BDN's ASM and ASMwSA/ASMwCA, each with the
    message-independent H2(apk, j) hashed in every verification or stored per group.
    For ASMwSA/ASMwCA the verifier always computes spk from the stored pk_j^{a_j}."""
    rows = []
    sig = vasm.combine([vasm.sign_share(gpk, mks[i - 1], m) for i in S])
    assert vasm.verify(gpk, S, m, sig)
    PK, apk, bmks, bsig, ssig, grp, grp_h2 = msp_signed_example(sks, S, m)
    rows.append(("verify (l=n/2)", "vASM", n, stats(lambda: vasm.verify(gpk, S, m, sig), reps)))
    rows.append(("verify (l=n/2)", "BDN ASM (H2 hashed each time)", n, stats(lambda: mb.bdn_verify(apk, S, m, bsig), reps)))
    rows.append(("verify (l=n/2)", "BDN ASM (H2 stored per group)", n, stats(lambda: mb.bdn_verify_cached(grp_h2, S, m, bsig), reps)))
    rows.append(("verify (l=n/2)", "ASMwSA / ASMwCA (H2 hashed each time)", n, stats(lambda: mb.sa_verify(grp, S, m, ssig), reps)))
    rows.append(("verify (l=n/2)", "ASMwSA / ASMwCA (H2 stored per group)", n, stats(lambda: mb.sa_verify(grp_h2, S, m, ssig), reps)))
    return rows


def verify_rows_swapped(n, sks, S, m, mks, gpk, reps=REPS):
    """The same verifiers with keys in G1 and hashes and signatures in G2 (swapped.py)."""
    rows = []
    vgrp = sw.vasm_group(gpk.gid, mks)
    sig = sw.vasm_sign(gpk.gid, mks, S, m)
    grp, grp_h2, bsig, ssig = sw.msp_example(sks, S, m)
    assert sw.vasm_verify(vgrp, S, m, sig)
    assert sw.bdn_verify(grp, S, m, bsig) and sw.bdn_verify(grp_h2, S, m, bsig)
    assert sw.sa_verify(grp, S, m, ssig) and sw.sa_verify(grp_h2, S, m, ssig)
    rows.append(("verify swapped", "vASM", n, stats(lambda: sw.vasm_verify(vgrp, S, m, sig), reps)))
    rows.append(("verify swapped", "BDN ASM (H2 hashed each time)", n, stats(lambda: sw.bdn_verify(grp, S, m, bsig), reps)))
    rows.append(("verify swapped", "BDN ASM (H2 stored per group)", n, stats(lambda: sw.bdn_verify(grp_h2, S, m, bsig), reps)))
    rows.append(("verify swapped", "ASMwSA / ASMwCA (H2 hashed each time)", n, stats(lambda: sw.sa_verify(grp, S, m, ssig), reps)))
    rows.append(("verify swapped", "ASMwSA / ASMwCA (H2 stored per group)", n, stats(lambda: sw.sa_verify(grp_h2, S, m, ssig), reps)))
    return rows


def op_rows():
    """Cost of single operations: a product of 128 elements, hashes, multi-pairings."""
    from py_arkworks_bls12381 import G1Point, G2Point
    from groups import g1, prod, multi_pair, ID1, ID2
    P1 = [g1(rand_scalar()) for _ in range(128)]
    P2 = [g2(rand_scalar()) for _ in range(128)]
    msg = b"x" * 64
    a = [g1(rand_scalar()) for _ in range(3)]
    b = [g2(rand_scalar()) for _ in range(3)]
    reps = 21
    return [
        ("operation", "product of 128 elements of G1", 1, stats(lambda: prod(P1, ID1), reps)),
        ("operation", "product of 128 elements of G2", 1, stats(lambda: prod(P2, ID2), reps)),
        ("operation", "hash to G1", 1, stats(lambda: G1Point.hash_to_curve(msg, b"bench"), reps)),
        ("operation", "hash to G2", 1, stats(lambda: G2Point.hash_to_curve(msg, b"bench"), reps)),
        ("operation", "multi-pairing, 2 pairs", 1, stats(lambda: multi_pair(a[:2], b[:2]), reps)),
        ("operation", "multi-pairing, 3 pairs", 1, stats(lambda: multi_pair(a, b), reps)),
    ]


def verify_only(ns):
    """Only the verification rows, for all n (vASM keys from fast_setup)."""
    rows = []
    swap = []
    for n in ns:
        print(f"n = {n} ...", flush=True)
        sks = [rand_scalar() for _ in range(n)]
        mks, gpk = fast_setup(sks)
        S, m = list(range(1, max(1, n // 2) + 1)), b"benchmark message"
        rows += verify_rows(n, sks, S, m, mks, gpk)
        swap += verify_rows_swapped(n, sks, S, m, mks, gpk)
    write_csv(rows, "results_verify.csv")
    write_csv(swap, "results_verify_swap.csv")
    write_csv(op_rows(), "results_ops.csv")


def vasm_setup_member(n, use_pok):
    """Work of one member: its own dealing (commitments, proof, shares) and the checks
    of the n-1 other dealings (C_0 = pk_j, shares against commitments, proofs), then COM,
    gid and MPK. The share check of member i evaluates the commitments at i (Horner's rule,
    exponentiations by i), so its cost grows with the bit length and the number of ones
    of i. We measure member n-1 (= 2^m - 1 for the n used here), the most expensive one;
    member 1 would be the cheapest."""
    sks = [rand_scalar() for _ in range(n)]
    PK = [g2(s) for s in sks]
    members = [vasm.Member(i + 1, s, PK, use_pok=use_pok) for i, s in enumerate(sks)]
    out = [m.round1() for m in members]
    broadcasts = {i + 1: out[i][0] for i in range(n)}
    me = max(1, n - 1)
    my = {j: out[j - 1][1][me] for j in broadcasts}
    fresh = vasm.Member(me, sks[me - 1], PK, use_pok=use_pok)
    return lambda: (fresh.round1(), members[me - 1].finish(broadcasts, my))


def fast_setup(sks):
    """Same keys and group data as an honest vasm.run_setup, computed directly
    (no proofs, no per-member checks). Only for timing sign/verify at large n,
    where running every member's full setup would take hours."""
    from groups import poly_eval, R
    n = len(sks)
    PK = [g2(s) for s in sks]
    polys = [[s] + [rand_scalar() for _ in range(n - 1)] for s in sks]
    F = [sum(p[k] for p in polys) % R for k in range(n)]
    COM = [g2(c) for c in F]
    mks = [poly_eval(F, i) for i in range(1, n + 1)]
    return mks, vasm.group_public(PK, COM)          # gid and MPK as a verifier computes them


def sign_verify_only(n):
    """Signing and verification of vASM for one n, using fast_setup."""
    mks, gpk = fast_setup([rand_scalar() for _ in range(n)])
    S, m = list(range(1, n // 2 + 1)), b"benchmark message"
    sig = vasm.combine([vasm.sign_share(gpk, mks[i - 1], m) for i in S])
    assert vasm.verify(gpk, S, m, sig)
    for i in range(1, n + 1):
        assert g2(mks[i - 1]) == gpk.MPK[i - 1]
    print(f"sign share         vASM                       {n:>4}  {timeit(lambda: vasm.sign_share(gpk, mks[0], m)):10.3f} ms")
    print(f"verify (l=n/2)     vASM                       {n:>4}  {timeit(lambda: vasm.verify(gpk, S, m, sig)):10.3f} ms")


def msp_sign_only(ns):
    """One signature share of ASMwSA and of ASMwCA (a_i precomputed at setup, l = n/2)."""
    from groups import ID1
    from groups import prod as gprod
    m = b"benchmark message"
    for n in ns:
        sks = [rand_scalar() for _ in range(n)]
        PK = [g2(x) for x in sks]
        a = mb.coefficients(PK)
        apk = mb.aggregate_key(PK, a)
        S = list(range(1, n // 2 + 1))
        e1 = a[0] * sks[0] % mb.R
        _, mus = mb.mu_values(1, sks[0], PK)          # member 1's own mu_{1j} = H2(apk, j)^{a_1 sk_1}
        smk = gprod((mus[j] for j in S), ID1)
        assert mb.mul(mb.H0(apk, m), e1) + smk == mb.asmwsa_sign_share(PK, 1, sks[0], mus, apk, S, m)
        sa = lambda: mb.mul(mb.H0(apk, m), e1) + gprod((mus[j] for j in S), ID1)
        ca = lambda: mb.mul(mb.H0(apk, m), e1) + mus[1]
        print(f"sign share         ASMwSA                     {n:>4}  {timeit(sa):10.3f} ms", flush=True)
        print(f"sign share         ASMwCA                     {n:>4}  {timeit(ca):10.3f} ms", flush=True)


def bdn_setup_member1(n):
    sks = [rand_scalar() for _ in range(n)]
    PK = [g2(s) for s in sks]
    return lambda: mb.mu_values(1, sks[0], PK)


def msp_setups_only(ns):
    """Per-member setup of BDN's ASM and of ASMwSA/ASMwCA, measured separately.
    ASM:          compute mu_{1j} for all j, then mk_1 = product of the n received mu_{i1}.
    ASMwSA/wCA:   check every key proof (distinct keys + Fiat-Shamir proofs), then compute mu_{1j}.
                  (ASMwSA stores the received mu_{i1}; ASMwCA sends them to the combiner.)"""
    from groups import ID1
    from groups import prod as gprod
    for n in ns:
        r = REPS
        keys = [mb.keygen_with_proof() for _ in range(n)]
        sks, PK, prf = [k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]
        a = mb.coefficients(PK)
        h = mb.H2(mb.aggregate_key(PK, a), 1)
        recv = [mb.mul(h, a[i] * sks[i] % mb.R) for i in range(n)]       # mu_{i1}, received by member 1

        def asm():
            mb.mu_values(1, sks[0], PK)
            return gprod(recv, ID1)

        def asmwsa():
            assert mb.check_keys(PK, prf)
            return mb.mu_values(1, sks[0], PK)

        print(f"setup per member   ASM (BDN)                  {n:>4}  {timeit(asm, r):10.3f} ms", flush=True)
        print(f"setup per member   ASMwSA / ASMwCA            {n:>4}  {timeit(asmwsa, r):10.3f} ms", flush=True)


def setup_rows(n):
    """Setup per member of ASM, ASMwSA/ASMwCA (with the key-proof check) and vASM."""
    from groups import ID1
    from groups import prod as gprod
    keys = [mb.keygen_with_proof() for _ in range(n)]
    sks, PK, prf = [k[0] for k in keys], [k[1] for k in keys], [k[2] for k in keys]
    a = mb.coefficients(PK)
    h = mb.H2(mb.aggregate_key(PK, a), 1)
    recv = [mb.mul(h, a[i] * sks[i] % mb.R) for i in range(n)]       # mu_{i1}, received by member 1

    def asm():
        mb.mu_values(1, sks[0], PK)
        return gprod(recv, ID1)

    def asmwsa():
        # member 1 checks that the keys are distinct and the proofs of the n-1 other keys
        assert len(set(bytes(pk.to_compressed_bytes()) for pk in PK)) == n
        assert all(mb.pok.verify(mb.enc("ASM-key", pk), [pk], pr) for pk, pr in zip(PK[1:], prf[1:]))
        return mb.mu_values(1, sks[0], PK)

    r = REPS if n <= 64 else 3
    rows = [("setup per member", "ASM (BDN) incl. mk", n, stats(asm, r)),
            ("setup per member", "ASMwSA/ASMwCA incl. key-proof check", n, stats(asmwsa, r))]
    for row in rows:
        print(f"  {row[1]:<40} {row[3][0]:10.3f} ms", flush=True)
    rows.append(("setup per member", "vASM", n, stats(vasm_setup_member(n, True), REPS if n <= 64 else 1)))
    print(f"  {'vASM':<40} {rows[-1][3][0]:10.3f} ms", flush=True)
    return rows


def sign_rows(n, reps=REPS_FAST):
    """One signature share (l = n/2) of ASM, ASMwSA, ASMwCA and vASM; everything that does
    not depend on the message (a_i sk_i, mk_i, the mu_{ij}) is computed at setup."""
    from groups import ID1, prod as gprod
    m = b"benchmark message"
    sks = [rand_scalar() for _ in range(n)]
    PK = [g2(x) for x in sks]
    a = mb.coefficients(PK)
    apk = mb.aggregate_key(PK, a)
    S = list(range(1, max(1, n // 2) + 1))
    e1 = a[0] * sks[0] % mb.R
    _, mus = mb.mu_values(1, sks[0], PK)               # mu_{1j} = H2(apk, j)^{a_1 sk_1}
    ask = sum(x * s for x, s in zip(a, sks)) % mb.R
    mk1 = mb.mul(mb.H2(apk, 1), ask)                    # BDN: mk_1 = prod_i mu_{i1} = H2(apk,1)^{sum a_i sk_i}
    mks, gpk = fast_setup(sks)
    assert mb.asmwsa_sign_share(PK, 1, sks[0], mus, apk, S, m) == mb.mul(mb.H0(apk, m), e1) + gprod((mus[j] for j in S), ID1)
    return [
        ("sign share", "ASM (BDN)", n, stats(lambda: mb.bdn_sign_share(apk, sks[0], mk1, m), reps)),
        ("sign share", "ASMwSA", n, stats(lambda: mb.mul(mb.H0(apk, m), e1) + gprod((mus[j] for j in S), ID1), reps)),
        ("sign share", "ASMwCA", n, stats(lambda: mb.mul(mb.H0(apk, m), e1) + mus[1], reps)),
        ("sign share", "vASM", n, stats(lambda: vasm.sign_share(gpk, mks[0], m), reps)),
    ]


def aggregate_rows(Ns=(1, 10, 100), size=4):
    """AvASM aggregate verification of N signatures from N different groups of `size`
    members, each signed by a subgroup of size 2; the verifier stores MPK per group."""
    rows = []
    for N in Ns:
        items, sigs = [], []
        for k in range(N):
            mks, gpk = fast_setup([rand_scalar() for _ in range(size)])
            msg = b"msg %d" % k
            sigs.append(vasm.combine([vasm.sign_share(gpk, mks[i], msg) for i in range(2)]))
            items.append((gpk, [1, 2], msg))
        Sigma = ag.aggregate(sigs)
        assert ag.avasm_verify(items, Sigma)
        rows.append(("aggregate verify", "AvASM", N, stats(lambda: ag.avasm_verify(items, Sigma))))
    return rows


def paper(ns=(4, 16, 64, 256)):
    """All measurements of Section 9 in one file."""
    rows = []
    for n in ns:
        print(f"n = {n}: setup ...", flush=True)
        rows += setup_rows(n)
        print(f"n = {n}: signing and verification ...", flush=True)
        rows += sign_rows(n)
        sks = [rand_scalar() for _ in range(n)]
        mks, gpk = fast_setup(sks)
        S, m = list(range(1, max(1, n // 2) + 1)), b"benchmark message"
        rows += verify_rows(n, sks, S, m, mks, gpk, REPS_FAST)
        rows += verify_rows_swapped(n, sks, S, m, mks, gpk, REPS_FAST)
    print("single operations and aggregate verification ...", flush=True)
    rows += op_rows()
    rows += aggregate_rows()
    write_csv(rows, "results_paper.csv")


def setup_only(ns):
    rows = []
    for n in ns:
        print(f"n = {n} ...", flush=True)
        rows += setup_rows(n)
    write_csv(rows, "results_setup.csv")


def main(ns):
    rows = []
    for n in ns:
        print(f"n = {n} ...", flush=True)
        r = REPS if n <= 64 else 1
        rows.append(("setup per member", "vASM", n, stats(vasm_setup_member(n, True), r)))
        rows.append(("setup per member", "vASM (no PoK, insecure)", n, stats(vasm_setup_member(n, False), r)))
        rows.append(("setup per member", "BDN ASM / ASMwSA", n, stats(bdn_setup_member1(n), r)))
        keys = [mb.keygen_with_proof() for _ in range(n)]
        rows.append(("check key proofs", "ASMwSA/ASMwCA", n,
                     stats(lambda: mb.check_keys([k[1] for k in keys], [k[2] for k in keys]), r)))
        # signing and verification with l = n/2
        sks = [rand_scalar() for _ in range(n)]
        mks, gpk = vasm.run_setup(sks) if n <= 64 else fast_setup(sks)
        S, m = list(range(1, max(1, n // 2) + 1)), b"benchmark message"
        PK, apk, bmks = mb.bdn_setup(sks)
        rows.append(("sign share", "vASM", n, stats(lambda: vasm.sign_share(gpk, mks[0], m))))
        rows.append(("sign share", "BDN ASM", n, stats(lambda: mb.bdn_sign_share(apk, sks[0], bmks[0], m))))
        rows += verify_rows(n, sks, S, m, mks, gpk)
    # aggregate verification, N signatures by N groups of size 4
    for N in [1, 10, 100]:
        items, sigs = [], []
        for k in range(N):
            mks, gpk = vasm.run_setup([rand_scalar() for _ in range(4)])
            mk_m = b"msg %d" % k
            sigs.append(vasm.combine([vasm.sign_share(gpk, mks[i], mk_m) for i in range(2)]))
            items.append((gpk, [1, 2], mk_m))
        Sigma = ag.aggregate(sigs)
        rows.append(("aggregate verify", "AvASM", N, stats(lambda: ag.avasm_verify(items, Sigma))))
    write_csv(rows, "results.csv")


if __name__ == "__main__":
    if "--paper" in sys.argv:
        paper()
    elif "--verify" in sys.argv:
        verify_only([4, 16, 64, 256])
    elif "--sign" in sys.argv:
        msp_sign_only([4, 16, 64, 256])
    elif "--msp" in sys.argv:
        msp_setups_only([4, 16, 64, 256])
    elif "--setup" in sys.argv:
        setup_only([4, 16, 64, 256])
    elif "--vasm256" in sys.argv:
        sign_verify_only(256)
    elif "--quick" in sys.argv:
        main([4, 16])
    elif "--big" in sys.argv:
        main([4, 16, 64, 256])
    else:
        main([4, 16, 64])

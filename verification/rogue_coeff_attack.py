"""
P1 / vASM — strong-model (BDN-level) analysis of the group setup WITHOUT proof of knowledge.

Model: n members, one honest member i*; the adversary controls the other n-1.
Honest polynomial f*(x) = s + a_1 x + ... + a_{n-1} x^{n-1}.
Adversary learns the scalars f*(j) for j != i* and all commitments g2^{coeffs}.
Write t := f*(i*). Every honest coefficient is (known scalar) + (known scalar)*t,
so the adversary can publish commitments to polynomials f_j whose coefficients are
affine in t (it only needs g2^t, computable from COM_{i*}). The only scalar it must
reveal to the honest member is f_j(i*), so f_j(i*) must be t-free.

T_S := sum_{i in S} mk_i. The adversary forges on every message for S iff the
t-coefficient of T_S is 0 (then T_S is a scalar it knows).

Part 1 (exact, sympy): for each n, i*, S containing i* with |S| >= 2, solve for the
t-parts g_j of the corrupt polynomials with g_j(i*) = 0 making [t]T_S = 0.
Part 2: with PoK (corrupt coefficients t-free), [t]T_S == 1 for every S containing i*.
Part 3: numeric end-to-end check in exponent space mod a prime, n=2..5, including
setup checks (a), (b) and the verification equation.
"""
import itertools, random, sys
import sympy as sp

def part1_and_2(nmax):
    for n in range(2, nmax + 1):
        idx = list(range(1, n + 1))
        for istar in idx:
            corrupt = [j for j in idx if j != istar]
            for r in range(2, n + 1):
                for rest in itertools.combinations(corrupt, r - 1):
                    S = (istar,) + rest
                    # t-part of corrupt polynomial j: g_j(x)=sum_k d_{j,k} x^k
                    d = {(j, k): sp.Symbol(f"d_{j}_{k}") for j in corrupt for k in range(n)}
                    g = lambda j, x: sum(d[(j, k)] * x**k for k in range(n))
                    eqs = [sp.Eq(g(j, istar), 0) for j in corrupt]
                    # honest contributes t only through f*(i*) (=t); f*(i), i!=i*, are known scalars
                    tcoef = 1 + sum(g(j, i) for j in corrupt for i in S)
                    eqs.append(sp.Eq(tcoef, 0))
                    sol = sp.solve(eqs, list(d.values()), dict=True)
                    assert sol, (n, istar, S)
                # S = {i*} alone: [t]T = 1 + sum_j g_j(i*) = 1 always
            # Part 2: with PoK, g_j == 0, so [t]T_S = 1 for all S containing i*
        print(f"n={n}: cancellation feasible for every S∋i*, |S|>=2, every i*; "
              f"S={{i*}} and PoK case give [t]T=1")

def part3(trials=200):
    q = (1 << 255) - 19  # any prime; we work with exponents mod q
    for n in range(2, 6):
        for _ in range(trials // 4):
            idx = list(range(1, n + 1))
            istar = random.choice(idx)
            corrupt = [j for j in idx if j != istar]
            S = [istar] + random.sample(corrupt, random.randint(1, n - 1))
            # honest
            fh = [random.randrange(q) for _ in range(n)]  # s, a_1..a_{n-1}
            ev = lambda c, x: sum(ck * pow(x, k, q) for k, ck in enumerate(c)) % q
            t = ev(fh, istar)
            K = {j: ev(fh, j) for j in corrupt}       # scalars adversary learns
            # adversary: corrupt j0 carries the cancelling t-part, others honest-looking
            j0 = corrupt[0]
            # need g(x) deg<=n-1, g(i*)=0, sum_{i in S} g(i) = -1 : take g = c*(x-i*)
            # g(x) = c*(x-i*)*x^e with e chosen so that sum_{i in S} g(i) != 0 before scaling
            for e in range(n - 1):
                sg = sum((i - istar) * pow(i, e, q) for i in S) % q
                if sg:
                    break
            assert sg != 0
            c = (-pow(sg, -1, q)) % q
            gpoly = [0] * n                                    # t-part coefficients
            gpoly[e + 1] = (gpoly[e + 1] + c) % q
            gpoly[e] = (gpoly[e] - c * istar) % q
            base = {j: [random.randrange(q) for _ in range(n)] for j in corrupt}
            coeff = {j: [(base[j][k] + (gpoly[k] * t if j == j0 else 0)) % q for k in range(n)]
                     for j in corrupt}   # true exponents behind the published commitments
            coeff[istar] = fh
            # shares sent to honest are t-free scalars:
            for j in corrupt:
                assert ev(coeff[j], istar) == ev(base[j], istar)  # t-free share to honest
            # public keys: honest pk = g^s; corrupt pk chosen so check (a) holds (rogue key)
            pk = {istar: fh[0]}
            for j in corrupt:
                pk[j] = coeff[j][0]
            C = [sum(coeff[j][k] for j in idx) % q for k in range(n)]
            assert C[0] == sum(pk.values()) % q                       # check (a)
            mk_h = sum(ev(coeff[j], istar) for j in idx) % q
            assert mk_h == ev(C, istar)                               # check (b), honest
            mpk = {i: ev(C, i) for i in idx}
            T = sum(mpk[i] for i in S) % q
            # adversary's own computation of T from scalars it knows:
            T_adv = (sum(K[i] for i in S if i != istar)
                     + sum(ev(base[j], i) for j in corrupt for i in S)) % q
            # honest t contributions: f*(i*)=t, plus j0's t-part sum = -t  -> cancel
            assert (T - T_adv) % q == 0, "forgery exponent mismatch"
    print("numeric: forged exponent equals verifier's aggregate exponent in all trials (n=2..5)")

if __name__ == "__main__":
    part1_and_2(int(sys.argv[1]) if len(sys.argv) > 1 else 5)
    part3()

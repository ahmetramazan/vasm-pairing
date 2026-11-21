"""
Variant of rogue_coeff_attack.py in which every corrupt member's public key is FIXED
before the group setup and the setup checks C_0^{(j)} == pk_j for each dealer j
(a per-dealer version of check (a)). The adversary is rushing: it receives the honest
member's commitments and shares before it publishes its own.

Also (POP=True): a PoP on pk_j alone does NOT stop it for n >= 3; knowledge of ALL
coefficients is required. For n = 2 a PoP suffices against this particular strategy.

Shows the attack survives: the corrupt key is pk_j = pk*^{d} * g2^{e} (a rogue key),
chosen before setup, and the remaining coefficients absorb everything learned later.
Exponent arithmetic mod a prime; s = sk*, t = f*(i*).
"""
import random
q = 2**255 - 19
def ev(c, x): return sum(ck * pow(x, k, q) for k, ck in enumerate(c)) % q
def lag_at(points, i, x):
    num, den = 1, 1
    for j in points:
        if j != i:
            num = num * (x - j) % q; den = den * (i - j) % q
    return num * pow(den, -1, q) % q

def trial(n, istar):
    idx = list(range(1, n + 1)); corrupt = [j for j in idx if j != istar]
    S = [istar] + random.sample(corrupt, random.randint(1, n - 1))
    # --- adversary, BEFORE setup: choose t-part polynomial g (deg<=n-1) for corrupt j0
    #     with g(i*) = 0 and sum_{i in S} g(i) = -1. Need g(0) only through pk_j0.
    if POP:   # honest-key PoP on pk_j forces d = 0, i.e. g(0) = 0: g = c*x^(e+1)*(x - i*)
        for e in range(n - 2):
            sg = sum((i - istar) * pow(i, e + 1, q) for i in S) % q
            if sg: break
        else:
            return None
        c = (-pow(sg, -1, q)) % q
        g = [0] * n; g[e + 2] = (g[e + 2] + c) % q; g[e + 1] = (g[e + 1] - c * istar) % q
    else:
        for e in range(n - 1):
            sg = sum((i - istar) * pow(i, e, q) for i in S) % q
            if sg: break
        c = (-pow(sg, -1, q)) % q
        g = [0] * n; g[e + 1] = (g[e + 1] + c) % q; g[e] = (g[e] - c * istar) % q
    # t = (s - K)/L with L = lag_{i*}^{[n]}(0)... use points P = [n]: s = f*(0) = sum_i lag_i(0) f*(i)
    L = lag_at(idx, istar, 0)
    # constant term of f_j0 = g[0]*t + base0 = (g[0]/L)*s - (g[0]/L)*K + base0
    d = g[0] * pow(L, -1, q) % q                         # s-coefficient, fixed in advance
    e_pk = {j: random.randrange(q) for j in corrupt}     # pk_j = pk*^{d_j} g2^{e_j}
    dco = {j: (d if j == corrupt[0] else 0) for j in corrupt}
    # --- honest key and setup
    s = random.randrange(q)
    pk = {istar: s}
    for j in corrupt: pk[j] = (dco[j] * s + e_pk[j]) % q
    fh = [s] + [random.randrange(q) for _ in range(n - 1)]
    t = ev(fh, istar)
    K = sum(lag_at(idx, j, 0) * ev(fh, j) for j in corrupt) % q   # adversary knows (shares)
    assert (L * t + K) % q == s
    coeff = {istar: fh}
    for j in corrupt:
        if j == corrupt[0]:
            base = [random.randrange(q) for _ in range(n)]
            base[0] = (e_pk[j] + d * K) % q          # forced so that C_0^{(j)} == pk_j
            coeff[j] = [(base[k] + g[k] * t) % q for k in range(n)]
        else:
            coeff[j] = [e_pk[j]] + [random.randrange(q) for _ in range(n - 1)]
    for j in corrupt: assert coeff[j][0] == pk[j]               # per-dealer check (a')
    C = [sum(coeff[j][k] for j in idx) % q for k in range(n)]
    assert C[0] == sum(pk.values()) % q                           # aggregate check (a)
    assert sum(ev(coeff[j], istar) for j in idx) % q == ev(C, istar)   # check (b) honest
    for j in corrupt: assert ev(coeff[j], istar) == ev([b if k else b for k, b in enumerate(coeff[j])], istar)
    T = sum(ev(C, i) for i in S) % q
    # adversary's scalar knowledge: shares f*(i), i != i*, and t-free parts of its polys
    tfree = {j: ([(coeff[j][k] - g[k] * t) % q for k in range(n)] if j == corrupt[0] else coeff[j]) for j in corrupt}
    for j in corrupt: assert ev(coeff[j], istar) == ev(tfree[j], istar)   # share to honest is t-free
    T_adv = (sum(ev(fh, i) for i in S if i != istar) + sum(ev(tfree[j], i) for j in corrupt for i in S)) % q
    return T == T_adv

POP = False
print("fixed-key rushing attack works in all trials:",
      all(trial(n, random.randint(1, n)) for n in range(2, 8) for _ in range(100)))
POP = True   # corrupt keys carry a valid PoP (know sk_j), but higher coefficients are free
res = [trial(n, random.randint(1, n)) for n in range(3, 8) for _ in range(100)]
print("with PoP on pk_j only (n>=3): attack works whenever applicable:", all(r for r in res if r is not None),
      "| applicable trials:", sum(r is not None for r in res), "/", len(res))
res2 = [trial(2, random.randint(1, 2)) for _ in range(50)]
print("n=2 with PoP: attack applicable in", sum(r is not None for r in res2), "of", len(res2), "trials")

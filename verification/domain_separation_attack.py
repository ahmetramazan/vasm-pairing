"""
P1 / vASM — why H_0 must be domain-separated by the group (gid) and from plain BLS.

Setting: honest member i* with secret key s = sk (constant term of f*), the other n-1
members corrupt but otherwise behaving honestly (they even know their coefficients, i.e.
the attack works WITH the coefficient PoK). The adversary learns f*(j) for all j != i*.
By Lagrange interpolation over {1..n}:  t = f*(i*) = (s - sum_{j!=i*} L_j(0) f*(j)) / L_{i*}(0).
So any value H^s lets the adversary compute H^t and hence H^{T_S} for every S.

Sources of H^s with a shared hash H_0(m):
  (1) a plain BLS signature of the honest user under sk on m       (Remark 6 usage)
  (2) the honest user's share signature on m in ANOTHER group G'    (cross-group)
Both give a vASM forgery on m for group G and any S containing i*.
We check this in exponent space mod a prime (H = g1^h, unknown h is irrelevant: we only
track exponents relative to h).
"""
import random
q = 2**255 - 19
def lag0(points, i):
    num, den = 1, 1
    for j in points:
        if j != i:
            num = num * j % q
            den = den * (j - i) % q
    return num * pow(den, -1, q) % q
def ev(c, x): return sum(ck * pow(x, k, q) for k, ck in enumerate(c)) % q

def run(n, istar, source):
    idx = list(range(1, n + 1))
    s = random.randrange(q)
    def setup():
        fh = [s] + [random.randrange(q) for _ in range(n - 1)]
        fc = {j: [random.randrange(q) for _ in range(n)] for j in idx if j != istar}
        coeffs = dict(fc); coeffs[istar] = fh
        C = [sum(coeffs[j][k] for j in idx) % q for k in range(n)]
        return fh, fc, C
    fh, fc, C = setup()                       # target group G
    S = [istar] + random.sample([j for j in idx if j != istar], random.randint(1, n - 1))
    T = sum(ev(C, i) for i in S) % q          # verifier's exponent for (G, S)
    # what the honest party leaks on message m (exponent relative to H_0(m)):
    if source == "bls":
        leak = s
        to_s = lambda e: e
    else:                                     # share signature in another group G'
        fh2, fc2, C2 = setup()
        mk2 = ev(C2, istar)                   # honest share-signature exponent in G'
        leak = mk2
        known2 = sum(ev(fc2[j], istar) for j in fc2) % q
        L = lag0(idx, istar)
        knownsh2 = sum(lag0(idx, j) * ev(fh2, j) for j in idx if j != istar) % q
        # mk2 = t2 + known2, s = L*t2 + knownsh2
        to_s = lambda e: (L * ((e - known2) % q) + knownsh2) % q
    s_rec = to_s(leak)
    L = lag0(idx, istar)
    knownsh = sum(lag0(idx, j) * ev(fh, j) for j in idx if j != istar) % q
    t = (s_rec - knownsh) * pow(L, -1, q) % q
    T_adv = (t + sum(ev(fh, i) for i in S if i != istar)
             + sum(ev(fc[j], i) for j in fc for i in S)) % q
    return T_adv == T

for src in ("bls", "cross-group"):
    ok = all(run(n, random.randint(1, n), src) for n in range(2, 8) for _ in range(50))
    print(f"{src}: forged exponent matches verifier exponent in all trials: {ok}")

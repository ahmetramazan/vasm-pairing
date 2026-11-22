"""
Swap attack on aggregate ASM signatures (BDN18, ASIACRYPT, Section 4.4), checked in
exponent space: every group element is written as its discrete log mod a prime q,
and a pairing e(g1^a, g2^b) is modelled as a*b mod q.

Attack: an aggregate for {(S1,m1),(S2,m2)} under the same group key is offered as an
aggregate for the swapped tuples {(S1,m2),(S2,m1)}.

  * BDN ASM, aggregated by plain multiplication (no exponents b_i): ACCEPTED
    (this is the attack that forces BDN to use b_i).
  * AvASM  (contribution H0(gid,m)^{T_S}):                         REJECTED
  * AASMwSA/AASMwCA (contribution (H0(apk,m) prod_{j in S} H2(apk,j))^{x_S}): REJECTED
"""
import random

q = (1 << 255) - 19          # a large prime; stands in for the group order
rnd = random.Random(2026)
R = lambda: rnd.randrange(1, q)
n = 8
S1, S2 = {1, 2, 3}, {4, 5, 6, 7}
h0 = {}; h2 = {}
H0 = lambda tag, m: h0.setdefault((tag, m), R())   # random oracle H0
H2 = lambda tag, j: h2.setdefault((tag, j), R())   # random oracle H2
m1, m2 = "m1", "m2"

def report(name, ok_orig, ok_swap):
    print(f"{name:34s} original: {'valid' if ok_orig else 'INVALID'}   swapped: {'ACCEPTED (attack works)' if ok_swap else 'rejected'}")
    return ok_swap

# ---------------- BDN ASM, plain partial aggregation ----------------
sk = {i: R() for i in range(1, n + 1)}
a = {i: R() for i in range(1, n + 1)}                    # a_i = H1(pk_i, PK)
x_apk = sum(a[i] * sk[i] for i in sk) % q                # apk = prod pk_i^{a_i}
apk = "apk"
def asm_sign(S, m):                                      # sigma = (PK, s)
    PKS = sum(sk[i] for i in S) % q
    s = (H0(apk, m) * PKS + x_apk * sum(H2(apk, i) for i in S)) % q
    return PKS, s
def bdn_plain_avf(tuples, PKs, s):                       # e(s,g2)=prod e(H0,PK_k) * e(prod H2, apk)
    rhs = sum(H0(apk, m) * PK for (S, m), PK in zip(tuples, PKs))
    rhs += x_apk * sum(H2(apk, i) for S, _ in tuples for i in S)
    return s == rhs % q
(PK1, s1), (PK2, s2) = asm_sign(S1, m1), asm_sign(S2, m2)
s = (s1 + s2) % q
a1 = report("BDN ASM, plain aggregation",
            bdn_plain_avf([(S1, m1), (S2, m2)], [PK1, PK2], s),
            bdn_plain_avf([(S1, m2), (S2, m1)], [PK2, PK1], s))

# ---------------- AvASM ----------------
f = [[R() for _ in range(n)] for _ in range(n)]          # f_j of degree n-1, one per member
Phi = lambda x: sum(sum(c * pow(x, k, q) for k, c in enumerate(fj)) for fj in f) % q
T = lambda S: sum(Phi(i) for i in S) % q                 # verifier gets g2^{T_S} from COM
gid = "gid"
sig = lambda S, m: H0(gid, m) * T(S) % q
avasm_avf = lambda tuples, s: s == sum(H0(gid, m) * T(S) for S, m in tuples) % q
s = (sig(S1, m1) + sig(S2, m2)) % q
a2 = report("AvASM",
            avasm_avf([(S1, m1), (S2, m2)], s),
            avasm_avf([(S1, m2), (S2, m1)], s))

# ---------------- AASMwSA / AASMwCA ----------------
xS = lambda S: sum(a[j] * sk[j] for j in S) % q          # spk = prod_{j in S} pk_j^{a_j}
c = lambda S, m: (H0(apk, m) + sum(H2(apk, j) for j in S)) % q
sig = lambda S, m: c(S, m) * xS(S) % q
aasm_avf = lambda tuples, s: s == sum(c(S, m) * xS(S) for S, m in tuples) % q
s = (sig(S1, m1) + sig(S2, m2)) % q
a3 = report("AASMwSA / AASMwCA",
            aasm_avf([(S1, m1), (S2, m2)], s),
            aasm_avf([(S1, m2), (S2, m1)], s))

# Why: the swapped sum differs from the original by
#   (H0(m1)-H0(m2)) * (T_{S1}-T_{S2})              for AvASM,
#   (H0(m1)-H0(m2)) * (x_{S1}-x_{S2})              for AASMwSA/AASMwCA,
# which is nonzero unless the messages or the subgroup exponents coincide.
d_av = (H0(gid, m1) - H0(gid, m2)) * (T(S1) - T(S2)) % q
d_aa = (H0(apk, m1) - H0(apk, m2)) * (xS(S1) - xS(S2)) % q
print(f"difference nonzero: AvASM {d_av != 0}, AASMwSA/AASMwCA {d_aa != 0}")
assert a1 and not a2 and not a3
print("OK: swap attack works on plain BDN aggregation only.")

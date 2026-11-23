"""vASM: accountable subgroup multi-signature from a verifiable Feldman setup.

Follows Section 5.1 of the paper. Members are indexed 1..n.
Flags (only for the attack tests, never for real use):
  use_pok=False      -> earlier version's setup without proofs of knowledge
  legacy_hash=True   -> H_0(m) shared with plain BLS instead of H_0(gid, m)
"""
import hashlib
from dataclasses import dataclass
from py_arkworks_bls12381 import GT
from groups import (R, G1, G2, ID2, rand_scalar, g2, mul, sc, prod, pair, multi_pair,
                    hash_to_g1, hash_to_zr, enc, poly_eval, valid_subgroup)
import pok

DST_VASM = b"vASM-v2-H0"
DST_BLS = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"   # plain BLS (min-sig) hash
DST_GID = b"vASM-v2-GID"


class SetupError(Exception):
    """blame = index of the member to blame, or None if the input itself is invalid."""

    def __init__(self, blame, reason):
        super().__init__(f"member {blame}: {reason}" if blame is not None else reason)
        self.blame = blame
        self.reason = reason


def keygen():
    sk = rand_scalar()
    return sk, g2(sk)


def bls_sign(sk, m):
    """Plain BLS signature under the same key (used in Prop. 2 test)."""
    return mul(hash_to_g1(DST_BLS, m), sk)


@dataclass
class GroupPublic:
    gid: bytes
    PK: list
    COM: list
    MPK: list          # MPK[i-1] = mpk_i
    legacy_hash: bool = False
    dealings: list = None   # dealings[j-1] = (COM_j, proof_j), published with the group


def group_id(PK, COM):
    """gid: a SHA-256 digest of (PK, COM), computed once per group, so that H_0 hashes
    32 bytes and not 2n group elements for every message (Section 5.1)."""
    return hashlib.sha256(enc(DST_GID, PK, COM)).digest()


def eval_commitments(C, x):
    """prod_k C_k^{x^k} for a member index x, by Horner's rule:
    ((C_{t-1}^x C_{t-2})^x ... C_1)^x C_0, i.e. t-1 exponentiations by the small integer x
    and t-1 multiplications. A multi-exponentiation with the exponents x^k mod q would
    use full-size exponents for most k (and be almost free only for x = 1)."""
    s = sc(x)
    acc = C[-1]
    for Ck in reversed(C[:-1]):
        acc = acc * s + Ck
    return acc


def group_public(PK, COM, legacy_hash=False):
    """The per-group values of a verifier: gid and MPK, computed from PK and COM
    (mpk_i = prod_k C_k^{i^k}). A verifier never takes MPK from an untrusted source:
    with a chosen mpk_i = g2^{x_i}, sigma = H0(gid, m)^{sum x_i} would verify."""
    MPK = [eval_commitments(COM, t) for t in range(1, len(PK) + 1)]
    return GroupPublic(group_id(PK, COM), list(PK), list(COM), MPK, legacy_hash)


def verifier_group(PK, dealings, legacy_hash=False):
    """Once-per-group check of the verifier (Section 5.1): gpk = (PK, (COM_j, proof_j)_j).
    The keys in PK must be distinct and, for every j, COM_j must have n elements,
    C_0^(j) = pk_j and proof_j must verify with context (PK, j). Only then are COM and
    MPK computed. Checking COM alone is not enough: with C_0 = prod pk_j and a chosen
    C_1, anyone can make prod_{i in S} mpk_i = g2^x (paper, Remark 3.7)."""
    n = len(PK)
    keys = [bytes(pk.to_compressed_bytes()) for pk in PK]
    if len(set(keys)) != n:
        raise SetupError(None, "the public keys in PK are not distinct")
    if len(dealings) != n:
        raise SetupError(None, "wrong number of dealings")
    for j in range(1, n + 1):
        C, proof = dealings[j - 1]
        if len(C) != n:
            raise SetupError(j, "wrong number of commitments")
        if C[0] != PK[j - 1]:
            raise SetupError(j, "C_0 != pk_j")
        if proof is None or not pok.verify(enc(PK, j), C, proof):
            raise SetupError(j, "invalid proof of knowledge")
    COM = [prod((dealings[j][0][k] for j in range(n)), ID2) for k in range(n)]
    gpk = group_public(PK, COM, legacy_hash)
    gpk.dealings = list(dealings)
    return gpk


def H0(gpk: GroupPublic, m: bytes):
    if gpk.legacy_hash:
        return hash_to_g1(DST_BLS, m)
    return hash_to_g1(DST_VASM, gpk.gid, m)


class Member:
    """One member's side of GSetup."""

    def __init__(self, i, sk, PK, use_pok=True, legacy_hash=False):
        self.i, self.sk, self.PK = i, sk, list(PK)
        self.n = len(PK)
        # Step (0): abort before sending anything unless the keys in PK are pairwise
        # distinct and pk_i is this member's key.  With a repeated key, the dealing
        # (COM, proof, share) of a member in one setup can be replayed at another
        # position of a later setup with the same PK, and the honest contribution
        # then cancels in the sum of two membership keys (paper, Section 5.1).
        keys = [bytes(pk.to_compressed_bytes()) for pk in self.PK]
        if len(set(keys)) != len(keys):
            raise SetupError(None, "the public keys in PK are not distinct")
        if not 1 <= i <= self.n or self.PK[i - 1] != g2(sk):
            raise SetupError(None, f"pk_{i} is not the key of this member")
        self.use_pok, self.legacy_hash = use_pok, legacy_hash
        # step (1): f_i(x) = sk_i + a_1 x + ... + a_{n-1} x^{n-1}
        self.coeffs = [sk] + [rand_scalar() for _ in range(self.n - 1)]

    def round1(self):
        """Steps (2)-(3): returns (broadcast, private_shares)."""
        C = [g2(a) for a in self.coeffs]
        proof = pok.prove(enc(self.PK, self.i), self.coeffs, C) if self.use_pok else None
        shares = {j: poly_eval(self.coeffs, j) for j in range(1, self.n + 1)}
        return (C, proof), shares

    def finish(self, broadcasts, my_shares):
        """Steps (4)-(6). broadcasts[j] = (COM_j, proof_j); my_shares[j] = f_j(i)."""
        n, i = self.n, self.i
        for j in range(1, n + 1):
            C, proof = broadcasts[j]
            if j == i:                     # own dealing: nothing to check
                continue
            if len(C) != n:
                raise SetupError(j, "wrong number of commitments")
            if C[0] != self.PK[j - 1]:                                   # check (a')
                raise SetupError(j, "C_0 != pk_j")
            if self.use_pok and not pok.verify(enc(self.PK, j), C, proof):
                raise SetupError(j, "invalid proof of knowledge")
            if g2(my_shares[j]) != eval_commitments(C, i):                     # check (b')
                raise SetupError(j, "share inconsistent with commitments")
        mk = sum(my_shares.values()) % R
        COM = [prod((broadcasts[j][0][k] for j in range(1, n + 1)), ID2) for k in range(n)]
        gpk = group_public(self.PK, COM, self.legacy_hash)
        gpk.dealings = [broadcasts[j] for j in range(1, n + 1)]   # published for verifiers
        return mk, gpk


def run_setup(sks, use_pok=True, legacy_hash=False):
    """Honest execution of GSetup among all members (for tests and benchmarks)."""
    PK = [g2(sk) for sk in sks]
    members = [Member(i + 1, sk, PK, use_pok, legacy_hash) for i, sk in enumerate(sks)]
    out = [m.round1() for m in members]
    broadcasts = {i + 1: out[i][0] for i in range(len(sks))}
    results = []
    for m in members:
        my_shares = {j: out[j - 1][1][m.i] for j in broadcasts}
        results.append(m.finish(broadcasts, my_shares))
    mks = [r[0] for r in results]
    return mks, results[0][1]


def sign_share(gpk, mk, m):
    return mul(H0(gpk, m), mk)


def share_ok(gpk, i, m, s):
    """Combiner's optional check e(s_i, g2) = e(H0, mpk_i)."""
    return pair(s, G2) == pair(H0(gpk, m), gpk.MPK[i - 1])


def combine(shares):
    acc = None
    for s in shares:
        acc = s if acc is None else acc + s
    return acc


def verify(gpk, S, m, sigma):
    """e(H0(gid,m), prod_{i in S} mpk_i) == e(sigma, g2)   (eq. vasm-verify)."""
    if not valid_subgroup(S, len(gpk.MPK)):
        return False
    apk_S = prod((gpk.MPK[i - 1] for i in S), ID2)
    return multi_pair([H0(gpk, m), -sigma], [apk_S, G2]) == GT.one()

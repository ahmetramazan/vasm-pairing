"""Test vectors for the on-chain verifier in contracts/ASMVerifier.sol.

On Ethereum the EIP-2537 precompiles make G1 operations cheaper than G2
operations, so the on-chain variant swaps the groups: public keys (MPK, pk_j,
apk) are in G1, hashes and signatures in G2. The schemes and their proofs are
unchanged under this swap. For comparison, vASM is also exported in the
orientation of the paper (keys in G2, signatures in G1).

Hash-to-curve is RFC 9380 (BLS12381G2_XMD:SHA-256_SSWU_RO_ and the G1 suite)
with the scheme's own DST. The verifier only sees the public data of a group,
so the vectors use random secret keys and compute the signatures directly from
them; the group setup itself is the one in vasm.py / msp_based.py.

Run:  python evm/vectors.py   (writes evm/vectors.json)
"""
import hashlib, json, os, random, secrets, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from py_arkworks_bls12381 import G1Point, G2Point, GT                 # noqa: E402
from groups import R, sc, enc, hash_to_zr                              # noqa: E402

DST_VASM = b"vASM-v2-H0"
DST_GID = b"vASM-v2-GID"
DST_H0 = b"MSP-ASM-v2-H0"
DST_H1 = b"MSP-ASM-v2-H1"
DST_H2 = b"MSP-ASM-v2-H2"

G1, G2 = G1Point(), G2Point()


def h_g1(dst, msg):
    return G1Point.hash_to_curve(msg, dst)        # library order: (msg, dst)


def h_g2(dst, msg):
    return G2Point.hash_to_curve(msg, dst)


def e1(P):
    """EIP-2537 encoding of a G1 point (128 bytes)."""
    xy = bytes(P.to_xy_bytes_be())
    return b"\0" * 16 + xy[:48] + b"\0" * 16 + xy[48:]


def e2(Q):
    """EIP-2537 encoding of a G2 point (256 bytes): x.c0, x.c1, y.c0, y.c1."""
    xy = bytes(Q.to_xy_bytes_be())
    return b"".join(b"\0" * 16 + xy[48 * k:48 * k + 48] for k in range(4))


def hx(b):
    return "0x" + b.hex()


def subset(n, rng):
    return sorted(rng.sample(range(1, n + 1), n // 2))


def S_bytes(S):
    return b"".join(i.to_bytes(2, "big") for i in S)


def sum_points(points, identity):
    acc = identity
    for P in points:
        acc = acc + P
    return acc


def vasm_vector(n, rng, keys_in_g2=False):
    mk = [secrets.randbelow(R) for _ in range(n)]
    gid = hashlib.sha256(b"example group " + os.urandom(16)).digest()    # 32-byte group id
    m = b"vASM on-chain test message, n=%d" % n
    S = subset(n, rng)
    msg = enc(gid, m)
    x = sum(mk[i - 1] for i in S) % R
    if keys_in_g2:
        MPK = [G2 * sc(k) for k in mk]
        H = h_g1(DST_VASM, msg)
        sig = H * sc(x)
        apk = sum_points((MPK[i - 1] for i in S), G2Point.identity())
        assert GT.pairing(H, apk) == GT.pairing(sig, G2)
        return dict(n=n, gid=hx(gid), keys=[hx(e2(P)) for P in MPK], S=hx(S_bytes(S)),
                    m=hx(m), sig=hx(e1(sig)))
    MPK = [G1 * sc(k) for k in mk]
    H = h_g2(DST_VASM, msg)
    sig = H * sc(x)
    apk = sum_points((MPK[i - 1] for i in S), G1Point.identity())
    assert GT.pairing(apk, H) == GT.pairing(G1, sig)
    return dict(n=n, gid=hx(gid), keys=[hx(e1(P)) for P in MPK], S=hx(S_bytes(S)),
                m=hx(m), sig=hx(e2(sig)))


def msp_vector(n, rng):
    """One MSP group (keys in G1) with a BDN and an ASMwSA signature on the same S, m.
    BDN's signature is (s, pk) with pk = prod_{i in S} pk_i, as in its paper."""
    sk = [secrets.randbelow(R) for _ in range(n)]
    PK = [G1 * sc(s) for s in sk]
    a = [hash_to_zr(DST_H1, pk, PK) for pk in PK]
    apk = G1Point.multiexp_unchecked(PK, [sc(x) for x in a])
    apkc = bytes(apk.to_compressed_bytes())
    wpk = [pk * sc(x) for pk, x in zip(PK, a)]
    H2 = [h_g2(DST_H2, enc(apk, j)) for j in range(1, n + 1)]
    m = b"MSP on-chain test message, n=%d" % n
    S = subset(n, rng)
    H0 = h_g2(DST_H0, enc(apk, m))
    ask = sum(x * s for x, s in zip(a, sk)) % R
    h2S = sum_points((H2[i - 1] for i in S), G2Point.identity())
    # BDN: sigma = H0^{sum_S sk_i} * prod_{i in S} H2(apk, i)^{ask}
    bdn = H0 * sc(sum(sk[i - 1] for i in S)) + h2S * sc(ask)
    pkS = sum_points((PK[i - 1] for i in S), G1Point.identity())
    assert GT.pairing(pkS, H0) * GT.pairing(apk, h2S) == GT.pairing(G1, bdn)
    # ASMwSA / ASMwCA: sigma = (H0 * prod_{j in S} H2(apk, j))^{sum_S a_j sk_j}
    sa = (H0 + h2S) * sc(sum(a[i - 1] * sk[i - 1] for i in S))
    spk = sum_points((wpk[i - 1] for i in S), G1Point.identity())
    assert GT.pairing(spk, H0 + h2S) == GT.pairing(G1, sa)
    return dict(n=n, apk=hx(e1(apk)), apkc=hx(apkc), pk=[hx(e1(P)) for P in PK],
                wpk=[hx(e1(P)) for P in wpk], h2=[hx(e2(Q)) for Q in H2],
                S=hx(S_bytes(S)), m=hx(m), bdn=hx(e2(bdn) + e1(pkS)), asmwsa=hx(e2(sa)))


def msp_vector_g2keys(n, rng):
    """The same schemes in the orientation of the paper: keys in G2, H0, H2 and signatures in G1."""
    sk = [secrets.randbelow(R) for _ in range(n)]
    PK = [G2 * sc(x) for x in sk]
    a = [hash_to_zr(DST_H1, pk, PK) for pk in PK]
    apk = G2Point.multiexp_unchecked(PK, [sc(x) for x in a])
    apkc = bytes(apk.to_compressed_bytes())
    wpk = [pk * sc(x) for pk, x in zip(PK, a)]
    H2 = [h_g1(DST_H2, enc(apk, j)) for j in range(1, n + 1)]
    m = b"MSP on-chain test message (keys in G2), n=%d" % n
    S = subset(n, rng)
    H0 = h_g1(DST_H0, enc(apk, m))
    ask = sum(x * y for x, y in zip(a, sk)) % R
    h2S = sum_points((H2[i - 1] for i in S), G1Point.identity())
    bdn = H0 * sc(sum(sk[i - 1] for i in S)) + h2S * sc(ask)
    pkS = sum_points((PK[i - 1] for i in S), G2Point.identity())
    assert GT.pairing(H0, pkS) * GT.pairing(h2S, apk) == GT.pairing(bdn, G2)
    sa = (H0 + h2S) * sc(sum(a[i - 1] * sk[i - 1] for i in S))
    spk = sum_points((wpk[i - 1] for i in S), G2Point.identity())
    assert GT.pairing(H0 + h2S, spk) == GT.pairing(sa, G2)
    return dict(n=n, apk=hx(e2(apk)), apkc=hx(apkc), wpk=[hx(e2(Q)) for Q in wpk],
                h2=[hx(e1(P)) for P in H2], S=hx(S_bytes(S)), m=hx(m),
                bdn=hx(e1(bdn) + e2(pkS)), asmwsa=hx(e1(sa)))


def rfc9380_check():
    """RFC 9380, Appendix J.10.1 (msg = "") for the G2 suite."""
    P = h_g2(b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_", b"")
    x0 = bytes(P.to_xy_bytes_be())[:48].hex()
    assert x0 == ("0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d"
                  "4ac44c1038e9dcdd5393faf5c41fb78a"), x0
    return dict(dst=hx(b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"), msg="0x",
                point=hx(e2(P)))


def main(ns=(4, 16, 64, 256)):
    rng = random.Random(2026)
    out = dict(
        note="keys in G1, signatures in G2 (EIP-2537); vasm_g2keys = orientation of the paper",
        neg_g1=hx(e1(-G1)), neg_g2=hx(e2(-G2)),
        rfc9380=rfc9380_check(),
        vasm=[vasm_vector(n, rng) for n in ns],
        vasm_g2keys=[vasm_vector(n, rng, keys_in_g2=True) for n in ns],
        msp=[msp_vector(n, rng) for n in ns],
        msp_g2keys=[msp_vector_g2keys(n, rng) for n in ns],
    )
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print("wrote", path)


if __name__ == "__main__":
    main()

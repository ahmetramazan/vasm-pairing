# vASM

Implementation of the schemes in "Pairing-based Accountable Subgroup Multi-signatures with
Verifiable Group Setup" (journal version of ePrint 2022/018), on BLS12-381
via `py_arkworks_bls12381`.

| file | content |
|---|---|
| `groups.py` | group operations, hash-to-curve, hashing to Z_r (works with old and new `py_arkworks_bls12381`) |
| `pok.py` | proof of knowledge of discrete logs: Schnorr proofs with one shared challenge, made non-interactive with Fiat-Shamir; the proof is (c, z_0..z_d), (d+2)*32 bytes |
| `vasm.py` | vASM (setup: input check that the keys in PK are distinct, PoK, per-dealer checks; H0(gid, m)); the products prod_k C_k^{i^k} are evaluated with Horner's rule |
| `msp_based.py` | BDN ASM (baseline), ASMwSA, ASMwCA; key proofs of knowledge for ASMwSA/ASMwCA; `msp_group(PK, proofs)`, the values a verifier computes once per group (apk, pk_j^{a_j}, optionally H2(apk, j)), after checking that the keys are distinct and their proofs verify. The verifier computes spk_S itself; it never takes it from the signer |
| `aggregate.py` | AvASM, AASMwSA/AASMwCA |
| `tests/` | correctness tests; the rogue-coefficient, shared-hash, duplicate-key replay and subset-sum attacks on the real curve, and the checks that stop them |
| `bench.py` | benchmarks for the evaluation section; writes `results.csv` (with `--setup`: `results_setup.csv`; with `--verify`: `results_verify.csv` with keys in G2, `results_verify_swap.csv` with keys in G1, `results_ops.csv` with single operations): median, min and max in ms and the number of runs |
| `swapped.py` | verification of all schemes with the groups swapped (keys in G1, hashes and signatures in G2), for the second verification table |
| `verification/` | symbolic and numerical checks of the attacks (exponent arithmetic, sympy) |
| `results/` | the measurements reported in the paper (Apple M2 Pro, Python 3.12, library 0.5.0) |

```
python3 -m venv .venv && source .venv/bin/activate
pip install py_arkworks_bls12381 pytest
python -m pytest -v tests
python bench.py --quick
```

Benchmark options:

```
python bench.py            # full run, n = 4, 16, 64
python bench.py --big      # also n = 256 (slow)
python bench.py --msp      # setup of ASM and of ASMwSA/ASMwCA (with key-proof check)
python bench.py --setup    # setup per member of ASM, ASMwSA/ASMwCA and vASM, n = 4, 16, 64, 256
python bench.py --sign     # signing in ASMwSA and ASMwCA
python bench.py --vasm256  # vASM signing and verification at n = 256
python bench.py --verify   # verification only, n = 4, 16, 64, 256: vASM, BDN ASM and ASMwSA/ASMwCA,
                           # the last two with H2(apk, j) hashed in each verification or stored per group
```

Benchmarks for the paper should be run with Python 3.10 or newer: on older Pythons pip installs
`py_arkworks_bls12381` 0.3.x, which has no RFC 9380 hash-to-curve, and `groups.py` falls back
to a slower try-and-increment hash.

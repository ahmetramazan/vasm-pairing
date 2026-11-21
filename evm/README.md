# On-chain verification (Ethereum, EIP-2537)

`contracts/ASMVerifier.sol` verifies vASM, BDN's ASM and ASMwSA/ASMwCA with the BLS12-381
precompiles of EIP-2537 (active since the Prague/Pectra upgrade). Every scheme is available in
both orientations: keys in G1 and signatures in G2, or keys in G2 and signatures in G1 (the
orientation of the paper). Hash-to-curve is RFC 9380 (checked against its test vector).

A group's public data (vASM: MPK; ASM/ASMwSA: apk, pk_j^{a_j} and optionally H2(apk, j)) is
written to storage once and read on every verification. The contract does not check it: as in
the paper's model, registration must be done or authorised by the group itself. In BDN's ASM
the aggregated key pk comes with the signature, as in its paper.

## Measure gas on a local chain

Needs Node.js 18 or newer.

    cd evm
    npm install
    node compile.js
    npx hardhat node          # leave running, open a second terminal
    node measure.js           # writes results_gas_local.csv

`python vectors.py` regenerates `vectors.json` (needs py_arkworks_bls12381 0.5.0).

## Run on Sepolia

Needs a Sepolia account with test ETH and an RPC URL (for example from Infura or Alchemy).
The private key stays on your machine; use an account that holds only test ETH.

    RPC_URL=https://... PRIVATE_KEY=0x... NS=4,16 node measure.js

`NS` selects the group sizes (registering n = 256 costs a lot of gas). The script prints the
contract address and writes `results_gas_sepolia.csv` with one transaction hash per
measurement, which can be looked up on sepolia.etherscan.io.

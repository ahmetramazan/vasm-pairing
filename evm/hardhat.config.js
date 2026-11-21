// Local test chain with the current Ethereum rules (Osaka: EIP-2537 precompiles,
// EIP-7825 transaction gas cap). Start it with `npx hardhat node`.
module.exports = {
  networks: {
    hardhat: { hardfork: "osaka", blockGasLimit: 60_000_000 },
  },
};

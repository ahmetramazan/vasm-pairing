// Compiles contracts/*.sol with solc-js (no compiler download needed) into build/ASMVerifier.json.
const fs = require("fs");
const path = require("path");
const solc = require("solc");

const dir = path.join(__dirname, "contracts");
const sources = {};
for (const f of fs.readdirSync(dir)) if (f.endsWith(".sol")) sources[f] = { content: fs.readFileSync(path.join(dir, f), "utf8") };

const input = {
  language: "Solidity",
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    viaIR: true,
    evmVersion: "prague",
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
let failed = false;
for (const e of out.errors || []) {
  console.error(e.formattedMessage);
  if (e.severity === "error") failed = true;
}
if (failed) process.exit(1);
const c = out.contracts["ASMVerifier.sol"].ASMVerifier;
fs.mkdirSync(path.join(__dirname, "build"), { recursive: true });
fs.writeFileSync(path.join(__dirname, "build", "ASMVerifier.json"),
  JSON.stringify({ compiler: solc.version(), abi: c.abi, bytecode: "0x" + c.evm.bytecode.object }, null, 1));
console.log("compiled with solc", solc.version(), "-> build/ASMVerifier.json,", c.evm.bytecode.object.length / 2, "bytes");

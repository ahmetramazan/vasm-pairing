// Deploys ASMVerifier, registers the groups of vectors.json and measures the gas of one
// verification transaction per scheme and group size.
//
// Local chain:  npx hardhat node          (in another terminal), then  node measure.js
// Sepolia:      RPC_URL=<https url> PRIVATE_KEY=<key> NS=16,64 node measure.js
//
// Writes results_gas_<network>.csv: scheme, n, l, gas used by the transaction, tx hash.
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
// Hardhat's well-known first development key; only for the local chain.
const DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const NS = (process.env.NS || "4,16,64,256").split(",").map(Number);

const V = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors.json"), "utf8"));
const B = JSON.parse(fs.readFileSync(path.join(__dirname, "build", "ASMVerifier.json"), "utf8"));
const cat = (xs) => "0x" + xs.map((x) => x.slice(2)).join("");
const flip = (h) => h.slice(0, -2) + (h.slice(-2) === "00" ? "01" : "00"); // tamper with the last byte

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const net = await provider.getNetwork();
  const name = net.chainId === 31337n ? "local" : net.name;
  if (name !== "local" && !process.env.PRIVATE_KEY) throw new Error("set PRIVATE_KEY for a public network");
  const wallet = new ethers.NonceManager(new ethers.Wallet(process.env.PRIVATE_KEY || DEV_KEY, provider));
  console.log("network", name, "chainId", net.chainId.toString(), "account", await wallet.getAddress());

  const C = await new ethers.ContractFactory(B.abi, B.bytecode, wallet).deploy();
  await C.waitForDeployment();
  const addr = await C.getAddress();
  console.log("ASMVerifier deployed at", addr, "(solc", B.compiler + ")");

  // RFC 9380, Appendix J.10.1: hash-to-G2 of the empty message
  const h = await C.hashToG2(V.rfc9380.msg, V.rfc9380.dst);
  if (h.toLowerCase() !== V.rfc9380.point.toLowerCase()) throw new Error("hash-to-G2 does not match RFC 9380");
  console.log("hash-to-G2 matches the RFC 9380 test vector");

  // Public RPC endpoints are load balanced: a node may not yet see the previous transaction
  // when the next one is estimated, so retry a few times (resetting the nonce manager).
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const send = async (fn, ...args) => {
    for (let t = 0; ; t++) {
      try { return await (await C[fn](...args)).wait(); }
      catch (e) { if (name === "local" || t >= 6 || e.action !== "estimateGas") throw e; wallet.reset(); await sleep(5000); }
    }
  };
  const rows = [["network", "scheme", "n", "l", "gas_used", "tx"]];
  const seed = BigInt(Date.now());           // fresh group ids for every run
  let gid = seed * 1000n;

  const measure = async (scheme, code, id, vec, sig) => {
    // a wrong signature must be rejected
    let rejected = false;
    try { await C.submit.estimateGas(code, id, vec.S, vec.m, flip(sig)); } catch (e) { rejected = true; }
    if (!rejected) throw new Error(scheme + ": tampered signature accepted");
    const r = await send("submit", code, id, vec.S, vec.m, sig);
    const l = (vec.S.length - 2) / 4;
    rows.push([name, scheme, vec.n, l, r.gasUsed.toString(), r.hash]);
    console.log(scheme.padEnd(23), "n =", String(vec.n).padStart(3), " l =", String(l).padStart(3), " gas", r.gasUsed.toString());
  };

  for (const [list, inG2, scheme, code] of [[V.vasm, false, "vASM", 0], [V.vasm_g2keys, true, "vASM_G2keys", 1]]) {
    for (const vec of list.filter((v) => NS.includes(v.n))) {
      const id = gid++;
      await send("registerVasm", id, vec.gid, vec.n, inG2);
      const chunk = inG2 ? 24 : 48;
      for (let s = 0; s < vec.n; s += chunk) await send("addVasmKeys", id, s + 1, cat(vec.keys.slice(s, s + chunk)));
      await measure(scheme, code, id, vec, vec.sig);
    }
  }
  for (const vec of V.msp.filter((v) => NS.includes(v.n))) {
    const id = gid++;
    await send("registerMsp", id, vec.n, vec.apk, vec.apkc);
    for (let s = 0; s < vec.n; s += 16)
      await send("addMspKeys", id, s + 1, cat(vec.pk.slice(s, s + 16)), cat(vec.wpk.slice(s, s + 16)), cat(vec.h2.slice(s, s + 16)));
    await measure("BDN_H2hashed", 2, id, vec, vec.bdn);
    await measure("BDN_H2stored", 3, id, vec, vec.bdn);
    await measure("ASMwSA_H2hashed", 4, id, vec, vec.asmwsa);
    await measure("ASMwSA_H2stored", 5, id, vec, vec.asmwsa);
  }
  for (const vec of V.msp_g2keys.filter((v) => NS.includes(v.n))) {
    const id = gid++;
    await send("registerMsp2", id, vec.n, vec.apk, vec.apkc);
    for (let s = 0; s < vec.n; s += 16)
      await send("addMspKeys2", id, s + 1, cat(vec.wpk.slice(s, s + 16)), cat(vec.h2.slice(s, s + 16)));
    await measure("BDN_G2keys_H2hashed", 6, id, vec, vec.bdn);
    await measure("BDN_G2keys_H2stored", 7, id, vec, vec.bdn);
    await measure("ASMwSA_G2keys_H2hashed", 8, id, vec, vec.asmwsa);
    await measure("ASMwSA_G2keys_H2stored", 9, id, vec, vec.asmwsa);
  }
  const out = path.join(__dirname, `results_gas_${name}.csv`);
  fs.writeFileSync(out, rows.map((r) => r.join(",")).join("\n") + "\n");
  console.log("wrote", out, "| contract", addr);
}

main().catch((e) => { console.error(e); process.exit(1); });

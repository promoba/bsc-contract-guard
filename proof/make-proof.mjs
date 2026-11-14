#!/usr/bin/env node
/**
 * make-proof.mjs — turn a BSC Contract Guard verdict JSON into a real
 * Groth16 proof of the verdict commitment.
 *
 *   node make-proof.mjs [path-to-verdict.json] [name]
 *
 * Reads commitment.inputs from the verdict, splits the report hash into
 * two 128-bit limbs, computes the expected Poseidon commitment with
 * circomlibjs (independent implementation), generates the proof with
 * snarkjs fullprove, verifies it against the verification key, and
 * cross-checks circuit public output == circomlibjs commitment.
 * Writes proof/out/<name>/{input.json,proof.json,public.json,
 * kurier-register-vk.json,kurier-submit.json}.
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { buildPoseidon } = require("circomlibjs");

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUILD = path.join(HERE, "circuit", "build");

async function main() {
  const verdictPath = process.argv[2] || path.join(HERE, "..", "samples", "cake.json");
  const name = process.argv[3] || path.basename(verdictPath).replace(/\.json$/, "");
  const verdict = JSON.parse(fs.readFileSync(verdictPath, "utf8"));
  const ci = verdict.commitment && verdict.commitment.inputs;
  if (!ci || !ci.reportHash) throw new Error("verdict JSON has no commitment.inputs.reportHash");

  const hash = BigInt(ci.reportHash);
  const MASK128 = (1n << 128n) - 1n;
  const input = {
    contractAddress: BigInt(ci.address).toString(),
    blockNumber: String(ci.block),
    reportHashLo: (hash & MASK128).toString(),
    reportHashHi: (hash >> 128n).toString(),
    verdictCode: String(ci.verdictCode),
  };

  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const expected = F.toObject(
    poseidon([
      BigInt(input.contractAddress),
      BigInt(input.blockNumber),
      BigInt(input.reportHashLo),
      BigInt(input.reportHashHi),
      BigInt(input.verdictCode),
    ])
  ).toString();

  const outDir = path.join(HERE, "out", name);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "input.json"), JSON.stringify(input, null, 2));

  const snarkjs = path.join(HERE, "node_modules", ".bin", "snarkjs");
  execFileSync(
    snarkjs,
    [
      "groth16", "fullprove",
      path.join(outDir, "input.json"),
      path.join(BUILD, "verdict_js", "verdict.wasm"),
      path.join(BUILD, "verdict_final.zkey"),
      path.join(outDir, "proof.json"),
      path.join(outDir, "public.json"),
    ],
    { stdio: "inherit" }
  );
  execFileSync(
    snarkjs,
    [
      "groth16", "verify",
      path.join(BUILD, "verification_key.json"),
      path.join(outDir, "public.json"),
      path.join(outDir, "proof.json"),
    ],
    { stdio: "inherit" }
  );

  const pub = JSON.parse(fs.readFileSync(path.join(outDir, "public.json"), "utf8"));
  const vk = JSON.parse(fs.readFileSync(path.join(BUILD, "verification_key.json"), "utf8"));

  // Exact Kurier payloads (docs.zkverify.io "Verifying proofs with Kurier").
  fs.writeFileSync(
    path.join(outDir, "kurier-register-vk.json"),
    JSON.stringify(
      { proofType: "groth16", proofOptions: { library: "snarkjs", curve: "bn128" }, vk },
      null, 2
    )
  );
  fs.writeFileSync(
    path.join(outDir, "kurier-submit.json"),
    JSON.stringify(
      {
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: {
          proof: JSON.parse(fs.readFileSync(path.join(outDir, "proof.json"), "utf8")),
          publicSignals: pub,
          vk: "<vkHash returned by register-vk>",
        },
      },
      null, 2
    )
  );

  console.log(JSON.stringify({
    name,
    address: ci.address,
    block: ci.block,
    verdict: verdict.verdict,
    expectedCommitment: expected,
    circuitCommitment: pub[0],
    commitmentMatch: expected === pub[0],
    outDir,
  }, null, 2));
  if (expected !== pub[0]) process.exit(2);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

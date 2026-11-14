#!/usr/bin/env node
/**
 * submit-proof.mjs — submit a generated verdict-commitment proof to
 * zkVerify via Kurier and poll until Finalized; the returned txHash is
 * the Agent Games Wildcard form's proof reference.
 *
 *   KURIER_API_KEY=<key> KURIER_ENV=mainnet|testnet node submit-proof.mjs [name]
 *
 * Flow (docs.zkverify.io "Verifying proofs with Kurier"):
 *   POST {API}/register-vk/{key}    -> { vkHash }   (cached per circuit)
 *   POST {API}/submit-proof/{key}   -> { jobId, optimisticVerify }
 *   GET  {API}/job-status/{key}/{jobId} -> ... -> { status:"Finalized", txHash, blockHash }
 *
 * Without a key this exits with the precise blocker: both Kurier APIs
 * answer 401 "Unauthorized or disabled API key" (probed 2026-11-14).
 * Keys are free: mainnet https://kurier.xyz · testnet https://testnet.kurier.xyz
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const KEY = process.env.KURIER_API_KEY || "";
const ENV = (process.env.KURIER_ENV || "mainnet").toLowerCase();
const API =
  ENV === "testnet" ? "https://api-testnet.kurier.xyz/api/v1" : "https://api.kurier.xyz/api/v1";

async function call(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep raw */ }
  return { status: res.status, json, text };
}

async function main() {
  const name = process.argv[2] || "cake";
  if (!KEY) {
    console.error(
      "BLOCKED: no KURIER_API_KEY in env. Get a free key at " +
        (ENV === "testnet" ? "https://testnet.kurier.xyz" : "https://kurier.xyz") +
        " (web signup), then re-run. Both Kurier APIs return 401 without one."
    );
    process.exit(3);
  }
  const outDir = path.join(HERE, "out", name);
  const registerBody = JSON.parse(fs.readFileSync(path.join(outDir, "kurier-register-vk.json"), "utf8"));
  const submitBody = JSON.parse(fs.readFileSync(path.join(outDir, "kurier-submit.json"), "utf8"));

  const cacheFile = path.join(HERE, `vk-hash-${ENV}.json`);
  let vkHash = null;
  if (fs.existsSync(cacheFile)) vkHash = JSON.parse(fs.readFileSync(cacheFile, "utf8")).vkHash;
  if (!vkHash) {
    const reg = await call("POST", `${API}/register-vk/${KEY}`, registerBody);
    if (reg.status !== 200 && reg.status !== 201) {
      console.error("register-vk failed", reg.status, reg.text.slice(0, 400));
      process.exit(1);
    }
    vkHash = reg.json.vkHash || (reg.json.meta && reg.json.meta.vkHash);
    if (!vkHash) {
      console.error("register-vk returned no vkHash", reg.text.slice(0, 400));
      process.exit(1);
    }
    fs.writeFileSync(cacheFile, JSON.stringify({ vkHash, env: ENV }, null, 2));
    console.log("vk registered:", vkHash);
  }
  submitBody.proofData.vk = vkHash;

  const sub = await call("POST", `${API}/submit-proof/${KEY}`, submitBody);
  if (sub.status !== 200 && sub.status !== 201) {
    console.error("submit-proof failed", sub.status, sub.text.slice(0, 400));
    process.exit(1);
  }
  console.log("submitted:", JSON.stringify(sub.json));
  if (sub.json.optimisticVerify !== "success") {
    console.error("optimisticVerify != success — check proof artifacts");
    process.exit(1);
  }
  const jobId = sub.json.jobId;
  const deadline = Date.now() + 10 * 60 * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 5000));
    const st = await call("GET", `${API}/job-status/${KEY}/${jobId}`);
    const s = st.json && st.json.status;
    console.log("job status:", s);
    if (s === "Finalized") {
      const result = { env: ENV, jobId, txHash: st.json.txHash, blockHash: st.json.blockHash, status: s };
      fs.writeFileSync(path.join(outDir, "submission-result.json"), JSON.stringify(result, null, 2));
      console.log("PROOF REFERENCE (txHash):", result.txHash);
      return;
    }
    if (s === "Failed") {
      console.error("job failed", st.text.slice(0, 400));
      process.exit(1);
    }
  }
  console.error("timed out waiting for Finalized");
  process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

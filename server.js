#!/usr/bin/env node
/**
 * BSC Contract Guard — public endpoint wrapper for the production
 * bsc-contract-audit skill (~/workspace/custom-skills/bsc-contract-audit).
 *
 * Read-only by construction: it only ever runs the skill's rpc.py helper
 * (eth_call / eth_getCode / eth_getStorageAt / eth_getBalance) and a Sourcify
 * lookup. It holds no keys, signs nothing, and sends no transactions.
 * Verdicts are ADVISORY (GO / CAUTION / BLOCK) — the same evidence-graded
 * discipline as the underlying skill: on-chain state first, verified source
 * second, simulation third, third-party claims never taken at face value.
 *
 * Routes:
 *   GET  /health                 -> { status, service, block }
 *   GET  /audit?address=0x...    -> verdict JSON (demo convenience)
 *   POST /audit                  -> verdict JSON
 *        body: { "address": "0x..." }
 *        or a platform task envelope:
 *        { "type": "...", "task_id": "...", "input": { "address": "0x..." } }
 *
 * HMAC dispatch: if GUARD_HMAC_SECRET is set and the caller sends a
 * signature header (x-signature / x-agent-games-signature /
 * x-hmac-sha256, hex HMAC-SHA256 of the raw body, optional "sha256="
 * prefix), the signature is verified and an invalid one is rejected
 * with 401. Tasks without a signature header are still served (the
 * Wildcard track is panel-judged); the response records what happened
 * under `dispatch`.
 */
"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");
const path = require("node:path");

const PORT = Number(process.env.PORT || 8791);
const SKILL_DIR = (() => {
  const fs = require("node:fs");
  const candidates = [
    process.env.BSC_AUDIT_SKILL_DIR,
    path.join(process.env.HOME || "", "workspace/custom-skills/bsc-contract-audit"),
    path.join(__dirname, "vendor/bsc-contract-audit"),
  ].filter(Boolean);
  return (
    candidates.find((d) => {
      try { return fs.existsSync(path.join(d, "scripts/rpc.py")); } catch { return false; }
    }) || candidates[0]
  );
})();
const RPC_PY = path.join(SKILL_DIR, "scripts/rpc.py");
const SELECTORS = path.join(SKILL_DIR, "references/selectors.md");
const HMAC_SECRET = process.env.GUARD_HMAC_SECRET || "";
const RPC_TIMEOUT_MS = 45000;
const AUDIT_BUDGET_MS = 55000;

const VERDICT_CODE = { BLOCK: 0, CAUTION: 1, GO: 2 };

// ---------------------------------------------------------------- rpc.py --
function runRpc(args) {
  return new Promise((resolve) => {
    execFile(
      "python3",
      [RPC_PY, ...args],
      { timeout: RPC_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        resolve({
          code: err ? err.code ?? 1 : 0,
          out: (stdout || "").trim(),
          err: (stderr || "").trim(),
        });
      }
    );
  });
}

function curlJson(url) {
  return new Promise((resolve) => {
    execFile(
      "curl",
      ["-s", "--max-time", "25", "-w", "\n%{http_code}", url],
      { timeout: 30000, maxBuffer: 32 * 1024 * 1024 },
      (err, stdout) => {
        if (err) return resolve({ ok: false, status: 0, json: null });
        const nl = stdout.lastIndexOf("\n");
        const status = Number(stdout.slice(nl + 1)) || 0;
        let json = null;
        try {
          json = JSON.parse(stdout.slice(0, nl));
        } catch {
          /* not json */
        }
        resolve({ ok: status >= 200 && status < 300, status, json });
      }
    );
  });
}

// keccak256 via the skill's own rpc.py keccak (single source of truth).
function keccakHex(hexNoPrefix) {
  return new Promise((resolve, reject) => {
    const code =
      "import sys; sys.path.insert(0, " +
      JSON.stringify(path.dirname(RPC_PY)) +
      "); import rpc; print(rpc.keccak(bytes.fromhex(sys.argv[1])).hex())";
    execFile("python3", ["-c", code, hexNoPrefix], { timeout: 20000 }, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout.trim());
    });
  });
}

// ------------------------------------------------------------- sourcify --
async function sourcifyStatus(address) {
  const url = `https://sourcify.dev/server/v2/contract/56/${address}`;
  const res = await curlJson(url);
  if (!res.ok || !res.json) return { status: "none", detail: `HTTP ${res.status}` };
  const j = res.json;
  const runtime = j.runtimeMatch || j.match || null;
  const creation = j.creationMatch || null;
  const m = String(runtime || creation || "").toLowerCase();
  // Sourcify v2 spells an exact match as "match" (newer) or "exact_match" (older records).
  if (m === "match" || m === "exact_match" || m === "exact") return { status: "exact_match", detail: `runtimeMatch=${runtime}` };
  if (m.includes("partial")) return { status: "partial_match", detail: `runtimeMatch=${runtime}` };
  if (j.abi) return { status: "partial_match", detail: "abi present, match field absent" };
  return { status: "none", detail: "no verified source record" };
}

// ---------------------------------------------------------------- audit --
async function audit(rawAddress) {
  const started = Date.now();
  const evidence = [];
  const findings = [];
  const unproven = [];
  let eid = 0;
  const E = (check, result) => {
    evidence.push({ id: `E${++eid}`, check, result: String(result).slice(0, 300) });
  };

  const address = String(rawAddress || "").trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) {
    return { httpStatus: 400, body: { error: "invalid_address", address: rawAddress } };
  }

  // E: pinned block
  const blk = await runRpc(["block"]);
  const block = blk.code === 0 ? Number(blk.out) : null;
  E("eth_blockNumber", block ?? `failed: ${blk.err}`);

  // E: code presence
  const codeRes = await runRpc(["code", address]);
  const code = codeRes.out || "0x";
  if (codeRes.code !== 0 || code === "0x" || code.length <= 4) {
    E("eth_getCode", "empty — not a contract");
    return {
      httpStatus: 200,
      body: verdictBody({
        address, block, implementation: null, classification: "NOT_A_CONTRACT",
        source: { status: "none" }, score: 0, verdict: "BLOCK",
        reason: "Address holds no contract bytecode on BSC.",
        bindingCap: null, findings: [{ severity: "Critical", title: "Not a contract", evidence: "E2" }],
        unproven: [], evidence, codeHash: null, started,
      }),
    };
  }
  const codeHash = await keccakHex(code.slice(2)).catch(() => null);
  E("eth_getCode", `${(code.length - 2) / 2} bytes, keccak256=${codeHash}`);

  // EIP-7702 delegation designator (0xef0100 + delegate): an EOA, not a
  // standalone contract — the delegate is the auditable code.
  if (code.toLowerCase().startsWith("0xef0100") && code.length === 48) {
    const delegate = "0x" + code.slice(8).toLowerCase();
    E("EIP-7702 designator", `delegate=${delegate}`);
    return {
      httpStatus: 200,
      body: verdictBody({
        address, block, implementation: delegate, classification: "EOA_7702_DELEGATED",
        source: { status: "none" }, score: 55, verdict: "CAUTION",
        reason: `Address is an EOA with an EIP-7702 delegation to ${delegate}; re-run the audit on the delegate for a code verdict.`,
        bindingCap: null,
        findings: [{ severity: "Moderate", title: "EIP-7702 delegated EOA — bytecode is a delegation designator, not contract logic", evidence: "E2,E3" }],
        unproven: ["Delegate contract logic — audit the delegate address directly"], evidence, codeHash, started,
      }),
    };
  }

  // E: proxy resolution (EIP-1967)
  let implementation = null;
  let proxyAdmin = null;
  const proxy = await runRpc(["proxy", address]);
  if (proxy.code === 0) {
    const mi = proxy.out.match(/implementation\s+(0x[0-9a-f]{40})/i);
    const ma = proxy.out.match(/admin\s+(0x[0-9a-f]{40})/i);
    if (mi && !/^0x0{40}$/.test(mi[1])) implementation = mi[1].toLowerCase();
    if (ma && !/^0x0{40}$/.test(ma[1])) proxyAdmin = ma[1].toLowerCase();
  }
  E("proxy slots (EIP-1967)", implementation ? `implementation=${implementation} admin=${proxyAdmin ?? "none(UUPS)"}` : "no EIP-1967 proxy pattern");
  const auditTarget = implementation || address;
  if (implementation) {
    findings.push({
      severity: "Moderate",
      title: "Upgradeable proxy — audited implementation; logic can be replaced by the admin",
      evidence: "E3",
    });
  }

  // E: meta (ERC20/721 identity)
  const meta = await runRpc(["meta", address]);
  const metaMap = {};
  if (meta.code === 0) {
    for (const line of meta.out.split("\n")) {
      const mm = line.match(/^(\S+)\s+(.*)$/);
      if (mm) metaMap[mm[1]] = mm[2];
    }
  }
  const isToken = metaMap["decimals()"] && metaMap["decimals()"] !== "(revert)";
  const hasSupply = metaMap["totalSupply()"] && metaMap["totalSupply()"] !== "(revert)";
  E("meta name/symbol/decimals/totalSupply", JSON.stringify(metaMap));

  // E: selector scan on the audited code
  const scan = await runRpc(["scan", auditTarget, SELECTORS]);
  const hits = [];
  if (scan.code === 0) {
    for (const line of scan.out.split("\n")) {
      const mh = line.match(/^HIT\s+(.+?)\s+0x([0-9a-f]{8})\s+x(\d+)/);
      if (mh) hits.push({ label: mh[1].trim(), selector: "0x" + mh[2], count: Number(mh[3]) });
    }
  }
  E(`selector scan (${path.basename(SELECTORS)})`, `${hits.length} hits: ${hits.map((h) => h.label).join(", ") || "none"}`);
  const hitLabels = hits.map((h) => h.label.toLowerCase());
  const hasHit = (...subs) => hitLabels.some((l) => subs.some((s) => l.includes(s)));

  // classification
  let classification = "CONTRACT";
  if (isToken && hasSupply) classification = "TOKEN";
  else if (hasHit("mint") && (metaMap["name()"] || metaMap["symbol()"])) classification = "MINT";
  else if (hasHit("deposit", "lock", "unlock")) classification = "LOCK";

  // E: ownership / pause liveness
  const ownerRes = await runRpc(["call", auditTarget, "owner()(address)"]);
  let owner = null;
  if (ownerRes.code === 0 && /^0x[0-9a-f]{40}$/i.test(ownerRes.out)) owner = ownerRes.out.toLowerCase();
  E("owner()", owner ?? `no live owner() (${ownerRes.code === 2 ? "revert" : "n/a"})`);
  const pausedRes = await runRpc(["call", auditTarget, "paused()(bool)"]);
  const paused = pausedRes.code === 0 ? pausedRes.out === "True" || pausedRes.out === "true" : null;
  E("paused()", paused === null ? "no paused()" : String(paused));

  // E: native balance (escrow principal check)
  const nbalRes = await runRpc(["nbal", address]);
  const nbalWei = nbalRes.code === 0 ? BigInt(nbalRes.out || "0") : 0n;
  E("eth_getBalance (contract)", `${nbalWei} wei`);

  // E: Sourcify verified source
  const src = await sourcifyStatus(auditTarget);
  E("Sourcify v2 verified source", `${src.status} (${src.detail})`);

  // ------------------------------------------------------------ scoring --
  let score = 100;
  let cap = null;
  const applyCap = (c, why, finding) => {
    if (cap === null || c < cap) cap = c;
    if (finding) findings.push(finding);
    return why;
  };

  if (src.status === "none") {
    applyCap(55, "no verified source", {
      severity: "Moderate", title: "No verified source on Sourcify — logic cannot be read, only probed", evidence: "E8",
    });
  } else if (src.status === "partial_match") {
    applyCap(84, "partial source match", {
      severity: "Moderate", title: "Source is only a partial match — deployed bytecode differs somewhere", evidence: "E8",
    });
  }

  const ownerLive = owner !== null && owner !== "0x0000000000000000000000000000000000000000";
  const ownerRenounced = owner === "0x0000000000000000000000000000000000000000";
  if (ownerRenounced) {
    findings.push({ severity: "Info", title: "Ownership renounced on-chain (owner() = 0x0)", evidence: "E6" });
  }
  if (ownerLive) {
    if (hasHit("settax", "setfee", "setfees", "changetax", "blacklist", "setmaxtx", "setmaxwallet", "trading")) {
      score -= 15;
      findings.push({
        severity: "Moderate",
        title: "Live owner + live fee/gate/blacklist setters — trading terms can change unilaterally",
        evidence: "E5,E6",
      });
    }
    if (hasHit("paus") && paused === null) {
      score -= 5;
      findings.push({ severity: "Low", title: "Owner-callable pause present (currently not confirmed paused)", evidence: "E5" });
    }
    // unlimited-mint cap: mint selector live, owner live, no supply cap found.
    // If the owner is itself a contract (e.g. MasterChef-style minter), the
    // cap does not bind — the residual question is that contract's governance.
    if (hasHit("mint")) {
      const capRes = await runRpc(["call", auditTarget, "maxSupply()(uint256)"]);
      const capRes2 = capRes.code !== 0 ? await runRpc(["call", auditTarget, "cap()(uint256)"]) : capRes;
      const hasCap = capRes2.code === 0 && /^[0-9]+$/.test(capRes2.out) && BigInt(capRes2.out) > 0n;
      E("maxSupply()/cap()", hasCap ? capRes2.out : "no on-chain supply cap found");
      const ownerCode = await runRpc(["code", owner]);
      const ownerIsContract = ownerCode.code === 0 && ownerCode.out && ownerCode.out.length > 4;
      E("owner() code size", ownerIsContract ? "owner is a contract" : "owner is an EOA");
      if (!hasCap && !ownerIsContract) {
        applyCap(60, "unlimited mint + live owner", {
          severity: "Moderate", title: "Mint path present, owner (EOA) live, and no supply cap is enforced on-chain", evidence: "E5,E6,E9",
        });
      } else if (!hasCap && ownerIsContract) {
        findings.push({
          severity: "Low",
          title: `Mint authority is a contract (${owner}) with no supply cap — that contract's governance is the residual risk`,
          evidence: "E5,E6,E10",
        });
      }
    }
    // escrow-drain cap: LOCK-shaped contract holding principal + owner fund-moving selectors
    const drainHit = hasHit("sweep", "rescue", "emergencywithdraw") || hitLabels.some((l) => l === "withdraw" || l.startsWith("withdraw("));
    if (classification === "LOCK" && drainHit && nbalWei > 10n ** 17n) {
      applyCap(40, "escrow drain path + held principal", {
        severity: "Critical", title: "Escrow holds >0.1 BNB and owner-callable fund-moving selectors are present", evidence: "E5,E7",
      });
    } else if (drainHit) {
      findings.push({
        severity: "Low", title: "Owner fund-moving selectors present (sweep/rescue/withdraw) — principal-drain not proven in quick triage", evidence: "E5",
      });
    }
  }
  if (paused === true) {
    score -= 10;
    findings.push({ severity: "Moderate", title: "Contract is currently paused — transfers/exits may be frozen", evidence: "E6" });
  }
  if (implementation && proxyAdmin) {
    score -= 10;
    findings.push({
      severity: "Moderate", title: "Proxy admin is a live external account; no timelock evidence on-chain", evidence: "E3",
    });
  }

  if (score < 0) score = 0;
  if (cap !== null && score > cap) score = cap;

  let verdict;
  if (cap !== null && cap <= 40) verdict = "BLOCK";
  else if (score < 55) verdict = "BLOCK";
  else if (score <= 84) verdict = "CAUTION";
  else verdict = "GO";

  unproven.push("Buy/sell tax rate — not proven from source in quick triage (needs exact-match source read or simulation)");
  unproven.push("Holder concentration — log-reconstruction not run by the endpoint quick triage");
  if (classification === "MINT") unproven.push("Mint price, mint-fund destination, and baseURI/reveal mutability — full MINT path not probed by quick triage");
  if (classification === "LOCK") unproven.push("LOCK five-check (permissionless refund, timer immutability, refund pausability, pool integrity, CEI order) — requires the full LOCK review, not quick triage");
  if (classification === "TOKEN") unproven.push("Transfer-gate simulation (sell path) — honeypot class is excluded by source read in full audits, not by quick triage");
  if (implementation) unproven.push("Admin timelock/multisig nature — not determinable from slots alone");

  const reason =
    verdict === "GO"
      ? "No binding caps triggered; live state and verified source agree at the pinned block."
      : verdict === "CAUTION"
        ? `Score capped/deducted to ${score}: ${cap ? `binding cap ${cap}` : "live privilege findings"} — read the findings before transacting.`
        : `Blocking evidence at the pinned block (score ${score}${cap ? `, cap ${cap}` : ""}) — do not transact without a full manual audit.`;

  return {
    httpStatus: 200,
    body: verdictBody({
      address, block, implementation, classification, source: src,
      score, verdict, reason, bindingCap: cap, findings, unproven, evidence,
      codeHash, started,
    }),
  };
}

function verdictBody(o) {
  const verdictCode = VERDICT_CODE[o.verdict];
  const timestamp = new Date(Date.now() + 7 * 3600 * 1000).toISOString().replace("Z", "+07:00");
  return {
    service: "bsc-contract-guard",
    version: "0.1.0",
    chainId: 56,
    address: o.address,
    implementation: o.implementation,
    classification: o.classification,
    block: o.block,
    timestamp,
    source: { provider: "Sourcify", status: o.source.status },
    score: o.score,
    verdict: o.verdict,
    verdictCode,
    bindingCap: o.bindingCap,
    decision: `${o.verdict} — ${o.reason} (ADVISORY — the user's explicit approval is the only transaction gate)`,
    findings: o.findings,
    unproven: o.unproven,
    evidenceLog: o.evidence,
    commitment: {
      scheme: "poseidon5(address, block, reportHashLo, reportHashHi, verdictCode)",
      inputs: {
        address: o.address,
        block: o.block,
        verdictCode,
        reportHash: o.codeHash ? `0x${o.codeHash}` : null,
      },
      note: "Feed these inputs to proof/circuit to obtain the Groth16 verdict-commitment proof; the finalized zkVerify tx hash / aggregation id is the competition proof reference.",
    },
    elapsedMs: Date.now() - o.started,
  };
}

// ---------------------------------------------------------------- server --
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 1024 * 1024) reject(new Error("body too large"));
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function checkHmac(req, rawBody) {
  const sig =
    req.headers["x-signature"] || req.headers["x-agent-games-signature"] || req.headers["x-hmac-sha256"];
  if (!sig) return { provided: false, verified: null };
  if (!HMAC_SECRET) return { provided: true, verified: null, note: "no secret configured" };
  const expected = crypto.createHmac("sha256", HMAC_SECRET).update(rawBody).digest("hex");
  const given = String(sig).replace(/^sha256=/, "").trim().toLowerCase();
  const ok =
    given.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
  return { provided: true, verified: ok };
}

const server = http.createServer(async (req, res) => {
  const send = (status, obj) => {
    const data = JSON.stringify(obj, null, 2);
    res.writeHead(status, { "content-type": "application/json" });
    res.end(data);
  };
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    if (req.method === "GET" && url.pathname === "/health") {
      const blk = await runRpc(["block"]);
      return send(200, {
        status: "ok",
        service: "bsc-contract-guard",
        version: "0.1.0",
        chainId: 56,
        block: blk.code === 0 ? Number(blk.out) : null,
        readOnly: true,
      });
    }
    if (req.method === "GET" && url.pathname === "/audit") {
      const { httpStatus, body } = await audit(url.searchParams.get("address"));
      return send(httpStatus, body);
    }
    if (req.method === "POST" && (url.pathname === "/audit" || url.pathname === "/task")) {
      const raw = await readBody(req);
      const hmac = checkHmac(req, raw);
      if (hmac.provided && hmac.verified === false) {
        return send(401, { error: "invalid_hmac_signature" });
      }
      let parsed = {};
      try {
        parsed = JSON.parse(raw.toString("utf8") || "{}");
      } catch {
        return send(400, { error: "invalid_json" });
      }
      const address =
        parsed.address ||
        parsed.contractAddress ||
        (parsed.input && (parsed.input.address || parsed.input.contractAddress)) ||
        (parsed.payload && parsed.payload.address);
      const { httpStatus, body } = await audit(address);
      body.dispatch = {
        taskId: parsed.task_id || parsed.taskId || null,
        type: parsed.type || null,
        hmac,
      };
      return send(httpStatus, body);
    }
    return send(404, { error: "not_found", routes: ["GET /health", "GET /audit?address=0x..", "POST /audit {address}"] });
  } catch (err) {
    return send(500, { error: "internal", detail: String(err && err.message || err).slice(0, 200) });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`bsc-contract-guard listening on :${PORT} (skill: ${SKILL_DIR})`);
  });
}

module.exports = { audit };

// BSC Contract Guard — Deno port of the Node endpoint (../server.js).
//
// Faithful port of the production wrapper around the bsc-contract-audit
// skill: same evidence order, same scoring/caps, same response shape.
// The Python rpc.py transport is reimplemented as direct JSON-RPC fetches
// (primary https://bsc-dataseed.bnbchain.org, fallback
// https://bsc-rpc.publicnode.com; a JSON-RPC error payload is a chain
// answer/revert and is NOT retried on the fallback — same rule as rpc.py).
// Keccak-256 is a line-by-line port of rpc.py's implementation.
// Read-only: eth_call / eth_getCode / eth_getStorageAt / eth_getBalance
// plus a Sourcify lookup. No keys, no signing, no transactions.

import { SELECTORS } from "./selectors.ts";

const HMAC_SECRET = Deno.env.get("GUARD_HMAC_SECRET") || "";
const VERDICT_CODE: Record<string, number> = { BLOCK: 0, CAUTION: 1, GO: 2 };

// ---------------------------------------------------------------- keccak --
// Ported from rpc.py (Keccak-256, legacy 0x01..0x80 padding, rate 136).
const M64 = (1n << 64n) - 1n;
const RC = [
  1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an,
  0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n,
];
const ROT = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];

function rol(x: bigint, n: number): bigint {
  if (!n) return x;
  const bn = BigInt(n);
  return ((x << bn) | (x >> (64n - bn))) & M64;
}

function perm(st: bigint[][]): void {
  for (let rnd = 0; rnd < 24; rnd++) {
    const c = [0, 1, 2, 3, 4].map((x) => st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4]);
    const d = [0, 1, 2, 3, 4].map((x) => c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) st[x][y] ^= d[x];
    const b: bigint[][] = Array.from({ length: 5 }, () => [0n, 0n, 0n, 0n, 0n]);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) b[y][(2 * x + 3 * y) % 5] = rol(st[x][y], ROT[x][y]);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) st[x][y] = b[x][y] ^ ((M64 ^ b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
    }
    st[0][0] ^= RC[rnd];
  }
}

function keccak(data: Uint8Array): Uint8Array {
  const st: bigint[][] = Array.from({ length: 5 }, () => [0n, 0n, 0n, 0n, 0n]);
  // Build padded buffer exactly like rpc.py: data + 0x01, zero-pad to a
  // multiple of 136, then XOR 0x80 into the final byte.
  let padded = new Uint8Array(data.length + 1);
  padded.set(data);
  padded[data.length] = 0x01;
  while (padded.length % 136 !== 0) {
    const next = new Uint8Array(padded.length + 1);
    next.set(padded);
    padded = next;
  }
  padded[padded.length - 1] ^= 0x80;
  for (let off = 0; off < padded.length; off += 136) {
    const blk = padded.subarray(off, off + 136);
    for (let i = 0; i < 17; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(blk[i * 8 + j]);
      st[i % 5][Math.floor(i / 5)] ^= lane;
    }
    perm(st);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = st[i % 5][Math.floor(i / 5)];
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function keccakHex(hexNoPrefix: string): string {
  return bytesToHex(keccak(hexToBytes(hexNoPrefix)));
}
function selectorOf(sig: string): string {
  if (sig.startsWith("0x") && sig.length === 10) return sig.slice(2);
  const base = sig.includes(")(") ? sig.split(")(")[0] + ")" : sig;
  return bytesToHex(keccak(new TextEncoder().encode(base))).slice(0, 8);
}

// ------------------------------------------------------------------- rpc --
// Mirrors rpc.py: returns { code, out } where code 0 = ok, 2 = revert
// (JSON-RPC error payload), 1 = transport failure on every endpoint.
const RPC_URLS = (Deno.env.get("RPC_URL") || "")
  ? [Deno.env.get("RPC_URL") as string]
  : ["https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com"];

type RpcResult = { code: number; result?: string; err?: string };

async function rpcRaw(method: string, params: unknown[]): Promise<RpcResult> {
  let lastErr = "no endpoint answered";
  for (const url of RPC_URLS) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "bsc-contract-audit/1.0" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(30000),
      });
      const payload = await resp.json();
      if (payload && typeof payload === "object" && "error" in payload && payload.error) {
        return { code: 2, err: String(payload.error.message || "rpc error") };
      }
      return { code: 0, result: payload.result };
    } catch (e) {
      lastErr = String((e as Error)?.message || e);
      continue;
    }
  }
  return { code: 1, err: lastErr };
}

async function rpcBlock(): Promise<{ code: number; out: string; err?: string }> {
  const r = await rpcRaw("eth_blockNumber", []);
  return r.code === 0
    ? { code: 0, out: String(parseInt(r.result as string, 16)) }
    : { code: r.code, out: "", err: r.err };
}

async function rpcCode(address: string): Promise<{ code: number; out: string }> {
  const r = await rpcRaw("eth_getCode", [address, "latest"]);
  return r.code === 0 ? { code: 0, out: r.result as string } : { code: r.code, out: "" };
}

async function rpcNbal(address: string): Promise<{ code: number; out: string }> {
  const r = await rpcRaw("eth_getBalance", [address, "latest"]);
  return r.code === 0 ? { code: 0, out: BigInt(r.result as string).toString() } : { code: r.code, out: "0" };
}

async function rpcStorage(address: string, slot: string): Promise<string> {
  const r = await rpcRaw("eth_getStorageAt", [address, slot, "latest"]);
  return r.code === 0 ? (r.result as string) : "0x" + "0".repeat(64);
}

function decode(hexdata: string, outype: string): string {
  if (!hexdata || hexdata === "0x") return "";
  const body = hexdata.slice(2);
  if (outype.includes(",")) {
    return outype
      .split(",")
      .map((t, i) => decode("0x" + body.slice(i * 64, (i + 1) * 64), t))
      .join(", ");
  }
  const word = body.slice(0, 64);
  if (outype === "address") return "0x" + word.slice(-40);
  if (outype === "bool") return parseInt(word || "0", 16) !== 0 ? "True" : "False";
  if (outype.startsWith("uint")) return BigInt("0x" + (word || "0")).toString();
  if (outype === "string") {
    const off = parseInt(word, 16) * 2;
    const ln = parseInt(body.slice(off, off + 64) || "0", 16) * 2;
    return new TextDecoder("utf-8", { fatal: false }).decode(hexToBytes(body.slice(off + 64, off + 64 + ln)));
  }
  return hexdata;
}

// rpc.py call: sig like "owner()(address)" (no arguments are used by the
// endpoint) or a bare signature "name()" for meta probes.
async function rpcCall(address: string, sigWithRet: string): Promise<{ code: number; out: string }> {
  const data = "0x" + selectorOf(sigWithRet);
  const r = await rpcRaw("eth_call", [{ to: address, data }, "latest"]);
  if (r.code !== 0) return { code: r.code, out: "" };
  const out = r.result as string;
  if (!sigWithRet.includes(")(")) return { code: 0, out };
  const retType = sigWithRet.split(")(")[1].slice(0, -1);
  return { code: 0, out: decode(out, retType) };
}

async function rpcProxy(address: string): Promise<{ implementation: string | null; admin: string | null }> {
  const ZERO = "0".repeat(64);
  const imp = (await rpcStorage(address, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")).slice(2);
  const adm = (await rpcStorage(address, "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")).slice(2);
  const bcn = (await rpcStorage(address, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")).slice(2);
  if (imp !== ZERO) {
    return {
      implementation: "0x" + imp.slice(-40),
      admin: adm === ZERO ? null : "0x" + adm.slice(-40),
    };
  }
  if (bcn !== ZERO) {
    const beacon = "0x" + bcn.slice(-40);
    const r = await rpcRaw("eth_call", [{ to: beacon, data: "0x5c60da1b" }, "latest"]);
    if (r.code === 0 && typeof r.result === "string" && r.result.length >= 42) {
      return { implementation: "0x" + r.result.slice(-40), admin: null };
    }
    return { implementation: null, admin: null };
  }
  return { implementation: null, admin: null };
}

async function rpcMeta(address: string): Promise<Record<string, string>> {
  const map: Record<string, string> = {};
  const probes: [string, string][] = [
    ["name()", "string"],
    ["symbol()", "string"],
    ["decimals()", "uint8"],
    ["totalSupply()", "uint256"],
  ];
  for (const [sig, typ] of probes) {
    const r = await rpcRaw("eth_call", [{ to: address, data: "0x" + selectorOf(sig) }, "latest"]);
    map[sig] = r.code === 0 ? decode(r.result as string, typ) : "(revert)";
  }
  return map;
}

function countOccurrences(haystack: string, needle: string): number {
  let n = 0;
  let i = haystack.indexOf(needle);
  while (i !== -1) {
    n++;
    i = haystack.indexOf(needle, i + needle.length);
  }
  return n;
}

async function rpcScan(address: string): Promise<{ label: string; selector: string; count: number }[]> {
  const codeRes = await rpcCode(address);
  const code = (codeRes.out || "0x").toLowerCase();
  const hits: { label: string; selector: string; count: number }[] = [];
  for (const [label, sel] of SELECTORS) {
    const n = countOccurrences(code, "63" + sel);
    if (n) hits.push({ label, selector: "0x" + sel, count: n });
  }
  return hits;
}

// ------------------------------------------------------------- sourcify --
async function sourcifyStatus(address: string): Promise<{ status: string; detail: string }> {
  const url = `https://sourcify.dev/server/v2/contract/56/${address}`;
  let res: Response;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(25000) });
  } catch {
    return { status: "none", detail: "HTTP 0" };
  }
  if (!res.ok) return { status: "none", detail: `HTTP ${res.status}` };
  let j: Record<string, unknown>;
  try {
    j = await res.json();
  } catch {
    return { status: "none", detail: `HTTP ${res.status}` };
  }
  const runtime = (j.runtimeMatch as string) || (j.match as string) || null;
  const creation = (j.creationMatch as string) || null;
  const m = String(runtime || creation || "").toLowerCase();
  if (m === "match" || m === "exact_match" || m === "exact") return { status: "exact_match", detail: `runtimeMatch=${runtime}` };
  if (m.includes("partial")) return { status: "partial_match", detail: `runtimeMatch=${runtime}` };
  if (j.abi) return { status: "partial_match", detail: "abi present, match field absent" };
  return { status: "none", detail: "no verified source record" };
}

// ---------------------------------------------------------------- audit --
type Finding = { severity: string; title: string; evidence: string };
type Evidence = { id: string; check: string; result: string };

function verdictBody(o: {
  address: string; block: number | null; implementation: string | null;
  classification: string; source: { status: string }; score: number;
  verdict: string; reason: string; bindingCap: number | null;
  findings: Finding[]; unproven: string[]; evidence: Evidence[];
  codeHash: string | null; started: number;
}) {
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

async function audit(rawAddress: unknown): Promise<{ httpStatus: number; body: Record<string, unknown> }> {
  const started = Date.now();
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const unproven: string[] = [];
  let eid = 0;
  const E = (check: string, result: unknown) => {
    evidence.push({ id: `E${++eid}`, check, result: String(result).slice(0, 300) });
  };

  const address = String(rawAddress || "").trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) {
    return { httpStatus: 400, body: { error: "invalid_address", address: rawAddress } };
  }

  // E: pinned block
  const blk = await rpcBlock();
  const block = blk.code === 0 ? Number(blk.out) : null;
  E("eth_blockNumber", block ?? `failed: ${blk.err ?? ""}`);

  // E: code presence
  const codeRes = await rpcCode(address);
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
  let codeHash: string | null = null;
  try {
    codeHash = keccakHex(code.slice(2));
  } catch {
    codeHash = null;
  }
  E("eth_getCode", `${(code.length - 2) / 2} bytes, keccak256=${codeHash}`);

  // EIP-7702 delegation designator (0xef0100 + delegate)
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
  const proxy = await rpcProxy(address);
  let implementation: string | null = null;
  let proxyAdmin: string | null = null;
  if (proxy.implementation && !/^0x0{40}$/.test(proxy.implementation)) implementation = proxy.implementation.toLowerCase();
  if (proxy.admin && !/^0x0{40}$/.test(proxy.admin)) proxyAdmin = proxy.admin.toLowerCase();
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
  const metaMap = await rpcMeta(address);
  const isToken = Boolean(metaMap["decimals()"]) && metaMap["decimals()"] !== "(revert)";
  const hasSupply = Boolean(metaMap["totalSupply()"]) && metaMap["totalSupply()"] !== "(revert)";
  E("meta name/symbol/decimals/totalSupply", JSON.stringify(metaMap));

  // E: selector scan on the audited code
  const hits = await rpcScan(auditTarget);
  E("selector scan (selectors.md)", `${hits.length} hits: ${hits.map((h) => h.label).join(", ") || "none"}`);
  const hitLabels = hits.map((h) => h.label.toLowerCase());
  const hasHit = (...subs: string[]) => hitLabels.some((l) => subs.some((s) => l.includes(s)));

  // classification
  let classification = "CONTRACT";
  if (isToken && hasSupply) classification = "TOKEN";
  else if (hasHit("mint") && (metaMap["name()"] || metaMap["symbol()"])) classification = "MINT";
  else if (hasHit("deposit", "lock", "unlock")) classification = "LOCK";

  // E: ownership / pause liveness
  const ownerRes = await rpcCall(auditTarget, "owner()(address)");
  let owner: string | null = null;
  if (ownerRes.code === 0 && /^0x[0-9a-f]{40}$/i.test(ownerRes.out)) owner = ownerRes.out.toLowerCase();
  E("owner()", owner ?? `no live owner() (${ownerRes.code === 2 ? "revert" : "n/a"})`);
  const pausedRes = await rpcCall(auditTarget, "paused()(bool)");
  const paused = pausedRes.code === 0 ? pausedRes.out === "True" || pausedRes.out === "true" : null;
  E("paused()", paused === null ? "no paused()" : String(paused));

  // E: native balance (escrow principal check)
  const nbalRes = await rpcNbal(address);
  const nbalWei = nbalRes.code === 0 ? BigInt(nbalRes.out || "0") : 0n;
  E("eth_getBalance (contract)", `${nbalWei} wei`);

  // E: Sourcify verified source
  const src = await sourcifyStatus(auditTarget);
  E("Sourcify v2 verified source", `${src.status} (${src.detail})`);

  // ------------------------------------------------------------ scoring --
  let score = 100;
  let cap: number | null = null;
  const applyCap = (c: number, finding?: Finding) => {
    if (cap === null || c < cap) cap = c;
    if (finding) findings.push(finding);
  };

  if (src.status === "none") {
    applyCap(55, {
      severity: "Moderate", title: "No verified source on Sourcify — logic cannot be read, only probed", evidence: "E8",
    });
  } else if (src.status === "partial_match") {
    applyCap(84, {
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
    if (hasHit("mint")) {
      const capRes = await rpcCall(auditTarget, "maxSupply()(uint256)");
      const capRes2 = capRes.code !== 0 ? await rpcCall(auditTarget, "cap()(uint256)") : capRes;
      const hasCap = capRes2.code === 0 && /^[0-9]+$/.test(capRes2.out) && BigInt(capRes2.out) > 0n;
      E("maxSupply()/cap()", hasCap ? capRes2.out : "no on-chain supply cap found");
      const ownerCode = await rpcCode(owner as string);
      const ownerIsContract = ownerCode.code === 0 && Boolean(ownerCode.out) && ownerCode.out.length > 4;
      E("owner() code size", ownerIsContract ? "owner is a contract" : "owner is an EOA");
      if (!hasCap && !ownerIsContract) {
        applyCap(60, {
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
    const drainHit = hasHit("sweep", "rescue", "emergencywithdraw") || hitLabels.some((l) => l === "withdraw" || l.startsWith("withdraw("));
    if (classification === "LOCK" && drainHit && nbalWei > 10n ** 17n) {
      applyCap(40, {
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

  let verdict: string;
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

// ---------------------------------------------------------------- server --
async function hmacHex(secret: string, raw: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, raw as BufferSource);
  return bytesToHex(new Uint8Array(sig));
}

async function checkHmac(
  req: Request,
  rawBody: Uint8Array,
): Promise<{ provided: boolean; verified: boolean | null; note?: string }> {
  const sig = req.headers.get("x-signature") || req.headers.get("x-agent-games-signature") || req.headers.get("x-hmac-sha256");
  if (!sig) return { provided: false, verified: null };
  if (!HMAC_SECRET) return { provided: true, verified: null, note: "no secret configured" };
  const expected = await hmacHex(HMAC_SECRET, rawBody);
  const given = String(sig).replace(/^sha256=/, "").trim().toLowerCase();
  let ok = given.length === expected.length;
  if (ok) {
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= given.charCodeAt(i) ^ expected.charCodeAt(i);
    ok = diff === 0;
  }
  return { provided: true, verified: ok };
}

function send(status: number, obj: unknown): Response {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function handler(req: Request): Promise<Response> {
  try {
    const url = new URL(req.url);
    if (req.method === "GET" && url.pathname === "/health") {
      const blk = await rpcBlock();
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
      const raw = new Uint8Array(await req.arrayBuffer());
      if (raw.byteLength > 1024 * 1024) throw new Error("body too large");
      const hmac = await checkHmac(req, raw);
      if (hmac.provided && hmac.verified === false) {
        return send(401, { error: "invalid_hmac_signature" });
      }
      let parsed: Record<string, unknown> = {};
      try {
        parsed = JSON.parse(new TextDecoder().decode(raw) || "{}");
      } catch {
        return send(400, { error: "invalid_json" });
      }
      const p = parsed as Record<string, never>;
      const input = (p.input || {}) as Record<string, never>;
      const payload = (p.payload || {}) as Record<string, never>;
      const address = p.address || p.contractAddress || input.address || input.contractAddress || payload.address;
      const { httpStatus, body } = await audit(address);
      body.dispatch = {
        taskId: p.task_id || p.taskId || null,
        type: p.type || null,
        hmac,
      };
      return send(httpStatus, body);
    }
    return send(404, { error: "not_found", routes: ["GET /health", "GET /audit?address=0x..", "POST /audit {address}"] });
  } catch (err) {
    return send(500, { error: "internal", detail: String((err as Error)?.message || err).slice(0, 200) });
  }
}

const portEnv = Deno.env.get("PORT");
if (portEnv) {
  Deno.serve({ port: Number(portEnv) }, handler);
} else {
  Deno.serve(handler);
}

# BSC Contract Guard — endpoint

Thin public-HTTPS wrapper around the production `bsc-contract-audit` skill
(`~/workspace/custom-skills/bsc-contract-audit`). Given a BSC contract
address, it reads **live on-chain state in the same minute** (pinned block,
bytecode, EIP-1967 proxy slots, ownership/pause liveness, selector-privilege
scan, native balance) and cross-checks the verified source on Sourcify
(exact-match only), then applies the skill's rubric + binding hard caps and
returns an evidence-graded verdict: **GO / CAUTION / BLOCK**, with an
evidence log and an explicit *Unproven* list. **Advisory only** — it never
signs, never transacts, and holds no keys.

## Run

```bash
PORT=8791 node server.js
# optional HMAC dispatch verification:
GUARD_HMAC_SECRET=<secret> PORT=8791 node server.js
```

## API

- `GET /health` → `{status, service, chainId, block}`
- `GET /audit?address=0x…` → verdict JSON
- `POST /audit` with `{"address":"0x…"}` or a platform task envelope
  `{"type":"…","task_id":"…","input":{"address":"0x…"}}` → verdict JSON

If a signature header (`x-signature`, `x-agent-games-signature`,
`x-hmac-sha256`; hex HMAC-SHA256 of the raw body) is present and
`GUARD_HMAC_SECRET` is configured, it is verified; an invalid signature
gets `401`. Responses echo the dispatch context under `dispatch`.

## Verdict JSON (abridged)

`address, implementation, classification (TOKEN|MINT|LOCK|CONTRACT|
EOA_7702_DELEGATED|NOT_A_CONTRACT), block, source.status
(exact_match|partial_match|none), score, verdict, verdictCode
(0 BLOCK · 1 CAUTION · 2 GO), bindingCap, decision, findings[],
unproven[], evidenceLog[], commitment.inputs{address, block, verdictCode,
reportHash}` — the commitment inputs feed `proof/` (Groth16
verdict-commitment circuit) whose finalized zkVerify reference anchors
the audit to chain state at the pinned block.

Sample outputs from local end-to-end tests live in `samples/`.

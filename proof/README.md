# proof/ — Groth16 verdict-commitment pipeline

Turns a BSC Contract Guard verdict into a zkVerify-checkable commitment.

- `circuit/verdict.circom` — `Poseidon(address, block, reportHashLo, reportHashHi, verdictCode)`; 321 constraints. Compiled artifacts + local trusted-setup output in `circuit/build/` (circom 2.1.9 binary vendored as `./circom`; ptau 2^12 — do not raise it, see `../wildcard-phase1.md` build note).
- `node make-proof.mjs <verdict.json> <name>` — builds inputs from the verdict's `commitment.inputs`, generates + verifies a proof with snarkjs, cross-checks the commitment against circomlibjs, and writes `out/<name>/` including the exact Kurier request bodies.
- `KURIER_API_KEY=<key> KURIER_ENV=mainnet|testnet node submit-proof.mjs <name>` — register-vk → submit-proof → poll job-status → prints the finalized **txHash** (the Wildcard form's proof reference). Without a key it exits 3 with the blocker text; keys are free at kurier.xyz / testnet.kurier.xyz.

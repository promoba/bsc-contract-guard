pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";

// VerdictCommitment — binds one BSC Contract Guard audit verdict to the
// exact on-chain state it was derived from.
//
// The audit service pins (contractAddress, blockNumber, reportHash,
// verdictCode), where reportHash is the keccak256 of the audited bytecode
// at the pinned block (split into two 128-bit limbs to fit the BN254
// field). The commitment is Poseidon over those five field elements.
// The tuple is published next to the verdict; anyone can recompute the
// Poseidon commitment off-chain and confirm that the finalized zkVerify
// proof attests to exactly the audit that was served — the verdict cannot
// be quietly swapped after the fact without invalidating the commitment.
template VerdictCommitment() {
    signal input contractAddress;
    signal input blockNumber;
    signal input reportHashLo;
    signal input reportHashHi;
    signal input verdictCode; // 0 = BLOCK, 1 = CAUTION, 2 = GO

    signal output commitment;

    component h = Poseidon(5);
    h.inputs[0] <== contractAddress;
    h.inputs[1] <== blockNumber;
    h.inputs[2] <== reportHashLo;
    h.inputs[3] <== reportHashHi;
    h.inputs[4] <== verdictCode;

    commitment <== h.out;
}

component main = VerdictCommitment();

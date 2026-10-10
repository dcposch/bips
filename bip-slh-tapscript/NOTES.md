# Notes on the BIP text

These notes list problems in `bip-slh-tapscript.md` (version 0.1.0) that the work on the
reference code and the test vectors found.
They also list the decisions that the code makes where the BIP does not give a rule.
None of the problems changes the consensus rules.

## 1. The witness sizes in "Resource use" are wrong

The section counts a 1-byte length prefix for each chunk.
A witness element of 253 bytes or more has a 3-byte prefix (`0xfd` and 2 bytes).
So each 520-byte chunk uses 523 bytes, not 521 bytes.

The correct size of one signature in the witness is:
15 x 523 + 57 + 2 = 7,904 bytes.

The vectors confirm this number.
The witness of `slhdsa/single/valid_bitflip_chunk1` is 7,976 bytes.
The witness of `slhdsa/multisig/2of3_valid_AC_1of3` is 15,953 bytes.

The 2-of-3 row also has a separate error of 1 byte.
With the old arithmetic, the witness is 15,893 bytes, not 15,892 bytes.
The `<0>` element for the key that does not sign uses 1 byte.

Proposed text for "Resource use":

```
One signature adds 7,904 bytes to the witness.
This is 15 chunks of 523 bytes, one chunk of 57 bytes, and 2 bytes for the count.
Each size includes the length prefix of the element.
A 520-byte element has a 3-byte length prefix.
```

| Spend (leaf depth 1, P2MR control block) | Witness (WU) | Input (WU) | Input (vB) |
|---|---|---|---|
| Single signature | 7,976 | 8,140 | 2,035 |
| 2-of-3 multisignature | 15,953 | 16,117 | about 4,029 |
| BIP 341 key path (for comparison) | 66 | 230 | 57.5 |

Proposed text for the last paragraph of "Resource use":

```
One signature adds 7,904 units to the budget, so an honest signature pays for its own check.
```

The conclusion does not change.
One signature still pays for its own check.
The vectors in the group `slhdsa/budget` show that one signature can be checked 4 times, but not 5 times.

## 2. The worst case of a verification

The Rationale says: "An attacker can choose a message that needs this number."
This is not correct.
The WOTS+ digits in each layer come from a hash output.
An attacker can only grind for a slow input.
To get the worst case in all 7 layers, all 224 message digits must be 0.
`research/bench-slh-verify.md` also says that this is not expected to be reachable.
The charge of 2,000 units uses the worst case, so it is conservative.

The count of 3,894 compressions in the BIP is 4 too low.
The benchmark note counts `H_msg` with a message `M'` of 34 bytes (a 32-byte digest).
This BIP passes `M` to `slh_verify` without a hash.
`M` is 276 bytes, or 308 bytes with an annex, so `M'` is 278 or 310 bytes.
The inner SHA256 of `H_msg` then needs 6 compressions, not 2.
With this change, the worst case is 3,898 compressions.
The count of `slhdsa.py` agrees:

* 1 for the first block of `PK.seed`, which the verifier reuses.
* 8 for `H_msg` (6 for the inner SHA256 of 326 or 358 bytes, 2 for MGF1).
* 182 for the FORS leaves and authentication paths, and 4 for `T_k`.
* 529 for each of the 7 layers (at most 510 chain steps, 10 for `T_len`, 9 for the path).

The difference is about 0.1 percent, so the charge does not change.
The forced worst case benchmark should use a message of 276 bytes to match the BIP.

Proposed text for the Rationale:

```
The worst-case SLH-DSA-SHA2-128s verification needs 3,898 SHA256 compressions.
This is an upper bound.
An attacker cannot choose an input that reaches it, but can grind for a slow input.
```

## 3. Two names for the same chunk (resolved)

Resolved on 2026-10-10. The BIP now uses only `chunk_1` to `chunk_c`, in witness order.


The section "Signature encoding" names the chunks `chunk_1` to `chunk_16` in witness order.
The rules name them `t_1` to `t_16` from the top of the stack.
So `t_1` is `chunk_16` and `t_16` is `chunk_1`.
Both sections are correct, but a reader can confuse them.
The size rule in step 8.2.2 (`t_1` is 56 bytes) and the witness form (`chunk_16` is 56 bytes)
agree only with this mapping.

Proposed sentence after the witness form in "Signature encoding":

```
In the rules below, t_1 is chunk_16 and t_16 is chunk_1.
```

## 4. Policy for unknown key types

The BIP says that wallets must not create scripts with unknown key types.
It does not say if a spend that uses an unknown key type is standard.
BIP 342 makes unknown public key types non-standard with `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`.
Without the same policy, nodes relay spends that a later soft fork can make invalid.

Proposed sentence for "Backwards Compatibility" or for a new "Policy" note:

```
Implementations should treat an OP_CHECKSIGPQADD with an unknown key type as non-standard,
as for unknown public key types in BIP 342.
```

`reference.py` implements consensus rules only, so it does not apply this policy.

## 5. Decisions in the code and the vectors

These points are not problems in the BIP text.
They record choices that the code had to make.

* **Flag names.**
  `P2MR` enables BIP 360 validation of witness version 2.
  `PQSIG` enables this BIP in the enabled output types.
  In the vectors, P2MR is the only enabled output type.
  `PQSIG` has no effect without `P2MR`.
  `run_vectors.py` tests all combinations of the two flags, also the combinations that a deployment does not use.
* **Error codes.**
  The BIP does not name errors.
  `reference.py` uses the Bitcoin Core names where they exist, and 4 new names:
  `SLH_COUNT` (step 4), `SLH_PUBKEY_SIZE` (step 8.1), `SLH_SIG_SIZE` (steps 8.2.1 and 8.2.2),
  and `SLH_SIG` (step 8.2.3).
  An empty key gives `TAPSCRIPT_EMPTY_PUBKEY`, as for `OP_CHECKSIGADD`.
  For an `n` of more than 4 bytes, `reference.py` gives `SCRIPTNUM`.
  Bitcoin Core gives `UNKNOWN_ERROR` for this case, because `CScriptNum` throws an exception.
* **Order of the steps.**
  The order of steps 6, 7, and 8 changes only the error code, not the result.
  `run_vectors.py` checks the order through the error code where the order is visible.
  `slhdsa/pubkey/empty_c1` shows that step 6 comes before step 7.
  `slhdsa/single/count_1_small_witness` shows that step 7 comes before step 8.
* **Non-minimal `n`.**
  The BIP refers to BIP 342 for CScriptNum.
  In BIP 342, a minimal encoding of `n` is a policy rule (`MINIMALDATA`), not a consensus rule.
  The vector `slhdsa/n/n_non_minimal_unknown_key` is therefore a success.
* **P2MR trees of depth zero.**
  BIP 360 version 0.12.0 makes a tree of depth zero spendable by anyone.
  The vector `slhdsa/inactive/p2mr_depth_zero_garbage_signature` follows this rule.
  Bitcoin Core pull request 35107 (April 2026) does not have this rule.
  BIP 360 added it in version 0.12.0 (June 2026).
  An implementation based on that pull request fails this vector until it adds the rule.
* **Signatures.**
  All signatures in the vectors use the deterministic variant of `slh_sign` (`opt_rand` is `PK.seed`).
  The verifier does not depend on the variant.

```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: SLH-DSA Signature Checks for Tapscript
  Authors: DC Posch <dc@dcpos.ch>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
  Version: 0.1.0
  Requires: 340, 341, 342
```

## Abstract

This document specifies `OP_CHECKSIGPQADD`, a tapscript opcode that verifies post-quantum
signatures.
Each public key starts with a key type, and this BIP defines one: SLH-DSA-SHA2-128s as
standardized in [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
The opcode can be enabled in any output type that uses tapscript, except witness version 1
(P2TR).
It follows the rules of `OP_CHECKSIGADD` from [BIP 342](bip-0342.mediawiki), so one opcode
supports single-signature and k-of-n scripts.
The security of this key type depends only on properties of SHA256.

## Copyright

This BIP is licensed under the BSD 3-clause license.

## Motivation

All signature opcodes in tapscript verify BIP 340 signatures over secp256k1.
Their security depends on the hardness of the discrete logarithm problem.
An efficient algorithm for this problem, on a quantum computer or on a classical computer,
would make it possible to forge these signatures.

Several proposals define new output types that use tapscript.
Examples are P2MR ([BIP 360](bip-0360.mediawiki)), which has no key path, and P2TRv2, which
has the same structure as P2TR at a new witness version.
None of these proposals defines a signature check that is secure without the discrete
logarithm assumption.

This BIP defines that signature check as a new opcode, agnostic to output type.
It uses SLH-DSA-SHA2-128s, a hash-based signature scheme whose security depends only on the
security of SHA256.
This BIP adds no new cryptographic assumptions.

## Specification

### Notation

* `||` is byte string concatenation.
* `ser_tag(tag)` is the 64-byte string `SHA256(tag) || SHA256(tag)`.
* `SigMsg(hash_type, ext_flag)` is the common signature message of
  [BIP 341](bip-0341.mediawiki#common-signature-message).
* `SLH-DSA.Verify(pk, M, sig, ctx)` is the verification algorithm `slh_verify` of FIPS 205,
  in its pure form, for the parameter set SLH-DSA-SHA2-128s.
* A CScriptNum is a number encoded as in BIP 342.

### Scope

This BIP does not define where the opcode is active.
An output type is an *enabled output type* if the deployment of this BIP lists it.
Each must execute tapscript according to BIP 342, and P2TR must not be listed.

The rules below apply to a transaction input only when all of these conditions are true:

* The input spends an output of an enabled output type.
* The spend executes a leaf with leaf version `0xc0`, so it is a tapscript spend.

In this context, opcode 202 (`0xca`) is `OP_CHECKSIGPQADD` instead of `OP_SUCCESS202`.
All other rules of BIP 342 apply without change, including stack limits.

In tapscript of an output type that is not enabled, opcode 202 remains `OP_SUCCESS202`.

### Public keys

A public key is a byte string `P`.
The first byte `P[0]` is the key type.

| Key type | Length of `P` | Scheme | Signature length | Budget charge |
|---|---|---|---|---|
| `0x01` | 33 bytes | SLH-DSA-SHA2-128s, with `P[1:33]` as the FIPS 205 public key | 7,856 bytes | 2,000 |

All other key types are unknown key types.
Signatures for unknown key types are not verified and are treated as valid.
The budget charge for an unknown key type is 50.

### Signature encoding

A signature is not one stack element.
It is a count `c`, followed by `c` chunks.
This keeps every stack element at 520 bytes or fewer.

* The count `c` is a single stack element.
  It must be the empty vector (the value 0), or a single byte with a value from `0x01` to
  `0x7f`.
* If `c` is 0, there is no signature.
* If `c` is larger than 0, the chunks are named `chunk_1` to `chunk_c` in witness order.
  `chunk_1` is the deepest in the stack, and `chunk_c` is directly below the count.
  The signature is `chunk_1 || chunk_2 || ... || chunk_c`.

In a witness, a signature for key type `0x01` has this form:

```
<chunk_1> <chunk_2> ... <chunk_16> <0x10>
```

Each of `chunk_1` to `chunk_15` is 520 bytes, and `chunk_16` is 56 bytes.

### Rules for `OP_CHECKSIGPQADD`

When `OP_CHECKSIGPQADD` is executed, these steps are done in order:

1. If fewer than 3 elements are on the stack, fail.
2. Pop the public key `P` (top element), then the CScriptNum `n`, then the count `c`.
3. If `n` is larger than 4 bytes, fail.
   `n` is decoded as for `OP_CHECKSIGADD` in BIP 342.
4. If `c` is not encoded as given in "Signature encoding", fail.
5. If fewer than `c` elements are on the stack, fail.
   Pop `c` elements. The first element popped is `chunk_c`, and the last is `chunk_1`.
   Let `sig = chunk_1 || chunk_2 || ... || chunk_c`.
6. If `P` is empty, fail.
7. If `c` is larger than 0, decrement the validation budget of BIP 342 by the budget charge of
   the key type `P[0]`.
   If the budget is now below zero, fail.
8. If `P[0]` is `0x01` and `P` is not 33 bytes, fail.
9. If `P[0]` is `0x01` and `c` is larger than 0:
   1. If `c` is not 16, fail.
   2. If any of `chunk_1` to `chunk_15` is not 520 bytes, fail.
      If `chunk_16` is not 56 bytes, fail.
   3. If `SLH-DSA.Verify(P[1:33], M, sig, "")` is false, fail.
      The message `M` is given in "Signature message".
10. If `c` is 0, push `n` as a CScriptNum.
    Otherwise, push `n + 1` as a CScriptNum.

### Signature message

The message is:

```
ext = tapleaf_hash || key_version || codesep_pos
M   = ser_tag("SLHSighash") || 0x00 || SigMsg(0x00, 1) || ext
```

* `tapleaf_hash` and `codesep_pos` are as defined in BIP 342.
* `key_version` is the key type, `0x01`.
* `0x00` after the tag is an epoch byte, as in BIP 341.
* `SigMsg(0x00, 1)` uses `hash_type = 0x00` (`SIGHASH_DEFAULT`).
  No other `hash_type` is available.

`M` is passed to `SLH-DSA.Verify` as it is.
It is not hashed to 32 bytes first.
The context string `ctx` is empty.

## Script examples

These examples show leaf scripts.
`<pk_X>` is a 33-byte public key with key type `0x01`.
`<sig_X>` is the 17 witness elements of a signature (16 chunks and the count).
`<0>` is the empty vector, which means no signature.

Single signature:

```
script:  OP_0 <pk_A> OP_CHECKSIGPQADD
witness: <sig_A>
```

A valid signature leaves the value 1 on the stack, and the script succeeds.

2-of-3 multisignature, signed by A and C:

```
script:  OP_0 <pk_A> OP_CHECKSIGPQADD <pk_B> OP_CHECKSIGPQADD <pk_C> OP_CHECKSIGPQADD
         OP_2 OP_NUMEQUAL
witness: <sig_C> <0> <sig_A>
```

2-of-3 with a recovery key after a delay. The script tree has two leaves:

```
leaf 1:  the 2-of-3 script above
leaf 2:  <52560> OP_CHECKSEQUENCEVERIFY OP_DROP OP_0 <pk_R> OP_CHECKSIGPQADD
```

Hash time-locked contract. The script tree has two leaves:

```
leaf 1:  OP_SHA256 <h> OP_EQUALVERIFY OP_0 <pk_recipient> OP_CHECKSIGPQADD
leaf 2:  <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_0 <pk_sender> OP_CHECKSIGPQADD
```

## Resource use

One signature adds 7,904 bytes to the witness.
This is 15 chunks of 523 bytes, one chunk of 57 bytes, and 2 bytes for the count.
Each size includes the length prefix of the element.
A 520-byte element has a 3-byte length prefix.

| Spend (leaf depth 1, P2MR control block) | Witness (WU) | Input (WU) | Input (vB) |
|---|---|---|---|
| Single signature | 7,976 | 8,140 | 2,035 |
| 2-of-3 multisignature | 15,953 | 16,117 | about 4,029 |
| BIP 341 key path (for comparison) | 66 | 230 | 57.5 |

The input weight includes 164 WU for the outpoint, the empty scriptSig, and the sequence
number.
The control block is 33 bytes, as in P2MR.
An output type that puts an internal key in the control block, such as P2TRv2, adds 32 WU.

A check with an SLH-DSA-SHA2-128s signature costs 2,000 units of the BIP 342 validation budget.
One signature adds 7,904 units to the budget, which more than covers that cost.

## Rationale

**Why SLH-DSA-SHA2-128s?**
SLH-DSA depends only on properties of its hash function.
The SHA2 parameter sets use SHA256, which Bitcoin already uses.
Parameter set 128s has the smallest signature within FIPS 205's security category 1.
It needs no signature counter, so a wallet restored from a backup can sign safely.
Category 1 matches the security level of secp256k1 and of the BIP 341 commitments.

**Why one opcode with `OP_CHECKSIGADD` rules?**
One opcode supports both single-signature and k-of-n scripts.
A single-signature script needs one extra byte (`OP_0`) compared with an `OP_CHECKSIG` form.

**Why is the signature split into chunks?**
An SLH-DSA-SHA2-128s signature is 7,856 bytes.
BIP 342 limits each stack element to 520 bytes.
BIP 342's budget does not count hashing opcodes.
A higher limit lets a script hash a large element many times at little cost in witness bytes.
Chunks keep all BIP 342 resource limits as they are.
The fixed chunk sizes give each signature exactly one encoding, avoiding malleability.

**Why is there an explicit count?**
The count makes the number of elements that the opcode pops independent of the key type.
A later soft fork can then define a new key type with a different signature length.
Scripts that are valid under the new rules are also valid under the rules of this BIP.

**Why does a check cost 2,000 budget units?**
A script can duplicate a signature and check it many times, so the budget must limit the
number of checks.
BIP 342 charges 50 units for a BIP 340 check.
The worst-case SLH-DSA-SHA2-128s verification needs 3,898 SHA256 compressions.
This is an upper bound.
An attacker cannot choose an input that reaches it, but can grind for a slow input.
On an Apple M2 and an Intel Sapphire Rapids CPU, the worst case took 8 to 35 times as long as
a BIP 340 verification.
The low value is with SHA256 hardware instructions, and the high value is without them.
A charge of 2,000 units covers a factor of 40.
With this charge, a block of repeated checks takes less time than the worst case that BIP 342
permits today.
Benchmark details will be added to this BIP's auxiliary files.
The benchmark must be repeated on more hardware before this BIP is final.

**Why does the charge depend on the key type?**
Other hash-based schemes have different signature sizes and verification costs.
For example, a stateful SHRINCS signature is 548 bytes.
A charge of 2,000 units would need more budget than such a signature adds.
A soft fork can raise a charge, because that only adds a failure condition.
It cannot lower a charge.
So unknown key types have the lowest charge, 50 units, the same as a BIP 340 check.
A later soft fork that defines a key type also sets its charge.

**Why only `SIGHASH_DEFAULT`?**
One message for each input makes the rules smaller.
There is no `hash_type` byte to parse and no invalid `hash_type` to reject.
Some protocols need other sighash types.
For example, Lightning anchor channels use `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY`.
A later soft fork can add them with a new key type.

**Why do unknown key types succeed?**
This follows the BIP 342 rule for unknown public key types.
A later soft fork can define a new key type by adding failure conditions.
If unknown key types failed, a new key type would need a hard fork.

**Why does the message include `key_version`?**
BIP 342 sets `key_version` to `0x00` for BIP 340 keys.
This BIP sets it to the key type, `0x01`.
A signature for one key type is therefore never valid for another key type.

**Why is the message not hashed to 32 bytes?**
SLH-DSA hashes the message together with a random value from the signer.
Its security therefore does not depend on collision resistance of a message digest.
The component hashes inside `SigMsg` are still single SHA256 values, as in BIP 341.

**Why does this BIP not choose an output type?**
The choice of output type is a separate question, and several designs are under discussion.
All of them need a signature check that does not depend on secp256k1.
If the opcode is defined once, each output type can enable it with no change to its rules.
In an output type with a key path, such as P2TRv2, a break of secp256k1 still allows a key
path spend.
That output type needs a separate rule that disables the key path.
In P2MR, an output whose leaves use only `OP_CHECKSIGPQADD` has no secp256k1 dependency.

**Why not P2TR?**
A P2TR output has a key path that is secured only by secp256k1.
No existing rule can disable that key path for P2TR outputs.

## Backwards Compatibility

This BIP is a soft fork.
Before activation, a tapscript that contains opcode 202 is valid without further checks,
because of `OP_SUCCESS202`.
After activation, such a script must also pass the rules above.
The rules only add failure conditions, so every spend that is valid after activation is also
valid before activation.

This BIP has no effect until at least one enabled output type is active.
It can activate at the same time as an output type, such as BIP 360, or later.

Wallets that do not implement this BIP cannot sign for these scripts, but can still send to
the enabled output types.

## Policy

Implementations should treat an `OP_CHECKSIGPQADD` with an unknown key type as non-standard.
This matches the policy for unknown public key types in BIP 342.
Bitcoin Core limits the size of tapscript stack elements to 80 bytes by policy.
Implementations that have such a limit should allow elements of 520 bytes in enabled output
types.

## Deployment

The activation method and parameters are not specified here.
A deployment must list the enabled output types.

## Test Vectors

The file [vectors.json](bip-slh-tapscript/vectors.json) has 85 test vectors.
The format is the format of the `script_assets_test` unit test of Bitcoin Core.
The flag `P2MR` enables BIP 360, and the flag `PQSIG` enables this BIP.
The vectors use P2MR as the enabled output type.
The expected error of each failure case is in its comment.

## Reference Implementation

The directory [bip-slh-tapscript](bip-slh-tapscript/) has a Python reference implementation.
* `slhdsa.py` implements SLH-DSA-SHA2-128s as specified in FIPS 205.
  It passes the NIST ACVP test vectors for this parameter set.
* `reference.py` implements the rules of this BIP and a minimal P2MR verifier.
* `gen_vectors.py` generates the test vectors, and `run_vectors.py` checks them.

## Acknowledgements

To be added.

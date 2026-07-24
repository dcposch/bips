```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: Pay-to-SLH-DSA-Hash (P2SLH)
  Authors: DC Posch <dc@dcpos.ch>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
  Version: 0.1.0
  Requires: 141, 340, 341, 350
```

## Abstract

This BIP defines a new output type, Pay-to-SLH-DSA-Hash (P2SLH): SegWit version 3 with a
32-byte witness program, spendable only with an SLH-DSA signature as standardized in
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final). The witness program commits to a hash
of the public key; the witness reveals the key and a signature. There is no script and no key
aggregation. **No secp256k1 operation appears anywhere in the validation of this output
type.** Existing output types are unchanged.

The two parameter sets active at deployment, SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f, are
instantiated entirely with SHA-256 and its standard keyed modes. P2SLH therefore introduces
no cryptographic primitive that consensus does not already contain, and no assumption beyond
the hash-function properties that already underpin proof-of-work and every existing address
type.

Activation parameters are deliberately out of scope, following the precedent of BIP 341.

## Motivation

A cryptographically relevant quantum computer (CRQC) recovers secp256k1 private keys from
public keys. Every output type in active use exposes a public key no later than spend time.
P2PK and P2TR outputs expose a spendable key for their entire lifetime, and reused addresses
expose theirs from the first spend. Exposed keys can be attacked for as long as the coins
remain unmoved; all other coins become attackable in the mempool window once CRQCs are fast
enough.

No known device is close to cryptographic relevance, and this proposal takes no position on
CRQC timelines. The argument for acting now is lead time, not imminence. A consensus change
plus ecosystem migration is most of a decade under favorable conditions. Institutional
custody already faces fixed external deadlines: CNSA 2.0 requires post-quantum cryptography
in new deployments by 2030-2033, and NIST IR 8547 plans to disallow ECC in the US federal
context after 2035. Waiting for evidence also fails structurally: key recovery from exposed
keys is invisible, so Q-day may be recognizable only in retrospect, and an active threat is
the worst time to standardize new cryptography.

Every live proposal for a post-quantum output type or spending path presupposes a
consensus-validated post-quantum signature. [BIP 360](bip-0360.mediawiki) provides a
quantum-resistant commitment structure and explicitly defers the signature scheme to a
separate proposal. [BIP 361](bip-0361.mediawiki) declares `Requires: TBD Post Quantum
Signature BIP`. This BIP supplies that missing piece and nothing else: a standardized,
minimal, opt-in destination whose security does not depend on the discrete logarithm problem,
usable today and reusable as the verification layer for every successor design.

### Who this is for

The initial constituency is deliberately narrow: high-value, low-velocity storage such as
cold vaults, treasuries, and custodians under post-quantum compliance mandates, plus every
future protocol document that needs a post-quantum signature to point at. A P2SLH spend
weighs roughly 35x a Taproot key-path spend, and this proposal makes no attempt to hide that.

P2SLH is single-signature by construction. No threshold, aggregate, or multiparty SLH-DSA
scheme exists in standardized form, so consensus-enforced m-of-n is out of scope. Operations
that require it today must split seeds or value operationally, or wait for the successor
tapscript opcode described in the Rationale, which brings script-level multisig. Mass-market
wallets are likewise expected to reach post-quantum security later and more cheaply through
successors that reuse this BIP's verification layer. An insurance rail must exist before it
is needed.

### Non-goals

This BIP does not:

* propose an activation mechanism;
* deprecate, restrict, freeze, or schedule any change to existing output types; it neither
  requires nor endorses BIP 361 or any migration policy;
* add opcodes, script capabilities, multisignature semantics, or covenants;
* change block size, weight accounting, or the witness discount;
* define key or signature aggregation or batch verification;
* standardize wallet key derivation, which is left to a follow-up informational BIP.

## Specification

### Notation

* `TaggedHash(tag, m)` is as defined in BIP 340: `SHA256(SHA256(tag) || SHA256(tag) || m)`.
* `ser_tag(tag)` denotes the 64-byte prefix `SHA256(tag) || SHA256(tag)`.
* `SigMsg(hash_type, ext_flag)` is the common signature message of BIP 341, unchanged,
  including the `spend_type = 2*ext_flag + annex_present` byte and the annex commitment.
* `SLH-DSA.Verify(pk, M, sig, ctx)` is the pure, non-pre-hashed verification algorithm of
  FIPS 205 for the parameter set in question.
* `pk_len(id)` and `sig_len(id)` denote the "pk" and "Signature" columns of Table 1.
* All failures below render the spending transaction invalid.

### Public keys and parameter sets

A P2SLH public key is the byte string `P = id || pk`, where `id` is a single byte selecting a
parameter set and `pk` is an SLH-DSA public key of length `pk_len(id)`.

**Table 1: parameter sets active at deployment**

| `id`   | Parameter set (FIPS 205) | pk (bytes) | Signature (bytes) | Role |
|--------|--------------------------|------------|-------------------|------|
| `0x01` | SLH-DSA-SHA2-128s        | 32         | 7,856             | Default: smallest signature, slow signing |
| `0x05` | SLH-DSA-SHA2-128f        | 32         | 17,088            | Alternative: ~19x faster signing, larger signature |

Both sets are NIST security category 1 and use SHA-256 exclusively, with HMAC-SHA-256 and
MGF1-SHA-256 as keyed modes. The SHAKE instantiations are not valid: they would add Keccak to
consensus and verify 1.4-2x slower on common hardware, for no security benefit at this level.

All other `id` values are undefined. Spends presenting an undefined `id` succeed under rule
V6 below; this is the mechanism by which future soft forks activate additional parameter sets
or schemes with no new address format. SLH-DSA-SHA2-192s is the expected first candidate.
Undefined-id spends are nonstandard by policy, and wallets MUST NOT create outputs committing
to undefined ids. An output does not reveal its id, so only spends are policy-visible.

The following `id` values are permanently ineligible for future assignment. This restricts
future BIPs, not validators, which treat them like any other undefined id:

* `0x00`: reserved as a null value.
* `0x02`, `0x03`, `0x04`, `0x06`, `0x07`: the leading bytes of serialized secp256k1 public
  keys. Excluding them guarantees that a P2SLH key can never be parsed as an EC key in any
  present or future script context that adopts this encoding.
* `0x50`: the annex tag. A two-element spend of a key with this leading byte mis-parses as
  annex-bearing under rule V2 and fails; a three-element spend reaches rule V6 and is
  anyone-can-spend. Such keys are unsafe by construction.

### Output construction

A P2SLH output's scriptPubKey is:

```
OP_3 <32-byte program>     (0x53 0x20 <program>, 34 bytes)
```

where

```
program = TaggedHash("SLHKeyHash", P)
```

The hash commits to the parameter-set id as well as the key, so a key cannot be reinterpreted
under a different parameter set at spend time.

### Address encoding

P2SLH addresses are bech32m per BIP 350 with witness version 3; mainnet addresses begin
`bc1r`. All parameter sets, present and future, share one uniform address format. The
parameter set becomes visible at spend time; see Privacy. Wallets and services that can send
to bech32m already produce valid P2SLH outputs without modification.

### Spending: witness structure

A P2SLH input's witness stack is exactly two elements, optionally followed by a BIP 341-style
annex:

```
<signature_field>  <P>  [annex]
```

### Validation rules

The rules below apply to any input spending an output whose scriptPubKey is exactly a
version-3 native witness program of length 32 bytes, under the rules of BIP 141; in
particular the scriptSig must be empty. Version-3 programs of other lengths, and P2SH-wrapped
version 3, are not constrained by this BIP and remain unencumbered.

To nodes without these rules active, such spends are valid under the existing
unknown-witness-version rule. Every rule below only adds failure conditions, so this proposal
is a soft fork.

Let `program` be the 32-byte witness program. Evaluate in order:

* **V1.** If the witness stack is empty, fail.
* **V2.** If there are at least two witness elements, and the last element is non-empty and
  its first byte is `0x50`, this element is the annex and is removed from the witness stack.
  The annex or its absence is always committed by the signature message and contributes to
  transaction weight, but is otherwise ignored. Until a use is defined by a future BIP, annex
  inclusion is discouraged by policy.
* **V3.** If exactly two elements do not remain, fail. Call the first `signature_field` and
  the last `P`.
* **V4.** If `P` is empty, fail. Let `id = P[0]`.
* **V5.** If `TaggedHash("SLHKeyHash", P) != program`, fail. Every subsequent success path,
  including V6, lies behind this 256-bit commitment.
* **V6.** If `id` is not listed in Table 1, succeed. This is the upgrade rule;
  `signature_field` is unconstrained. See Rationale for why this is not a theft risk.
* **V7.** If `len(P) != 1 + pk_len(id)`, fail.
* **V8.** Parse `signature_field`:
  * if `len(signature_field) == sig_len(id)`: `hash_type = 0x00` and
    `sig = signature_field`;
  * else if `len(signature_field) == sig_len(id) + 1`: `hash_type` is the final byte and
    `sig` is the remainder; if `hash_type == 0x00`, fail, since a redundant encoding of the
    default would be a malleability vector;
  * otherwise, fail.
* **V9.** If `hash_type` is not one of `{0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}`, fail.
* **V10.** Compute the message

  ```
  M = ser_tag("SLHSighash") || 0x00 || SigMsg(hash_type, 0)
  ```

  where `0x00` is the epoch byte and `SigMsg` is BIP 341's common signature message with
  `ext_flag = 0`, so `spend_type = annex_present`. As in BIP 341, if
  `(hash_type & 3) == SIGHASH_SINGLE` and there is no corresponding output, fail. All seven
  `hash_type` values have exactly their BIP 341 semantics.
* **V11.** If `SLH-DSA.Verify(pk = P[1:], M, sig, ctx = "")` is false under parameter set
  `id`, fail. The pure variant of FIPS 205 is used, with an empty context string.
* **V12.** Succeed.

`M` is passed to SLH-DSA verification as a message, not as a digest: the validator does not
hash `M` before verification. `M` is byte-identical to what a BIP 341-style tagged sighash
would hash; only the outer SHA-256 collapse is omitted. See Rationale.

**Reservation.** `ext_flag = 0` is exclusive to this BIP's spend type. Any future BIP that
reuses the `SLHSighash` message in a script context, such as a tapscript verification opcode,
MUST use `ext_flag >= 1` with a BIP 342-style extension committing to its execution context,
so that no message signed in one context can be valid in another.

### Resource accounting

P2SLH spends contribute zero toward the block sigop limit. Transaction weight is the sole
limiter, and with enormous margin: one P2SLH verification requires at least ~7,890 weight
units of witness data, against Taproot's floor of 50 weight units per Schnorr verification. A
block filled with P2SLH-128s inputs performs ~496 verifications in ~0.14 s single-threaded,
versus ~17,400 Schnorr verifications in ~0.9-1.0 s for a block of Taproot key-path spends.
Per weight unit the worst-case P2SLH block is roughly 5-8x cheaper to validate than the
worst-case Taproot block. No new limits are required.

| Set (id) | Witness (WU) | Input total (WU) | vbytes/input | x P2TR key path | Max inputs/block | Full-block verify, serial |
|----------|--------------|------------------|--------------|-----------------|------------------|---------------------------|
| 128s (`0x01`) | 7,894 | 8,058 | ~2,015 | ~35x | ~496 | ~0.14 s |
| 128f (`0x05`) | 17,126 | 17,290 | ~4,323 | ~75x | ~231 | ~0.17 s |
| *192s, future* | *16,278* | *16,442* | *~4,111* | *~71x* | *~243* | *~0.11 s* |

Witness WU assumes the default hash_type and no annex; an explicit hash_type adds 1 WU.
Verify times are average-case reference benchmarks at ~3 GHz. A signer can inflate the
verification cost of its own signature by a bounded factor under 2x.

## Rationale

**Why a hash-based scheme?** Consensus code should buy the oldest assumption and the simplest
verifier available and pay for them in bytes. Bytes are priced continuously by the fee
market; a broken assumption is priced once, catastrophically. SLH-DSA verification is a few
thousand SHA-256 evaluations, with no floating point, no algebraic structure, and no
constant-time hazards. Its security reduces to preimage-type and PRF properties of SHA-256,
the assumption family Bitcoin already relies on for proof-of-work and every address type, and
the underlying constructions of Lamport and Merkle predate Bitcoin by three decades. If these
assumptions fail, Bitcoin fails with them, P2SLH or not. It is also the only standardized
signature family whose failure is uncorrelated with the event it insures against: a
cryptanalytic surprise in structured algebra. FIPS 205 targets SUF-CMA, the same
non-malleability property BIP 340 provides, and SPHINCS+ carries a machine-checked tight
security proof.

The alternatives fall short. ML-DSA rides 2005-era structured lattices, younger assumptions
in a monoculture shared with the entire TLS migration. FN-DSA remains unstandardized as of
July 2026, with published key-recovery side-channel attacks against its floating-point
signer. Stateful schemes such as XMSS and LMS are disqualified because a wallet restored from
backup can fatally reuse state. No NIST onramp candidate can be standardized before roughly
2028, and several were broken or weakened by 2025-2026 cryptanalysis, which is precisely the
case against being early to young mathematics.

**Why exactly one scheme?** Reviewer bandwidth is the scarcest resource in consensus changes,
and each additional scheme multiplies implementation, test-vector, and DoS-analysis surface.
One conservative scheme with a commitment-protected upgrade path dominates: if a better
scheme matures, activating it is an ordinary soft fork with no new address format and no
coordination cost for receivers.

**The security parameter.** The tunable parameter of this proposal is the SLH-DSA parameter
set, deliberately left open to final review. The three candidates:

* **SLH-DSA-SHA2-128s, default, active:** smallest signatures and cheapest verification;
  signing takes ~0.2 s on desktop hardware but minutes on legacy microcontrollers without
  SHA-256 acceleration. Category 1 matches the 128-bit security level of everything else in
  Bitcoin: secp256k1, SHA-256 collision resistance, and Taproot's commitment security. A
  higher tier defends no asset the rest of the system doesn't already cap at 128 bits.
* **SLH-DSA-SHA2-128f, active:** ~19x faster signing at 2.2x the bytes and ~2.5x the
  verification cost. The pragmatic choice for hardware wallets and HSMs, active from day one
  so no follow-up fork is needed for a predictable constituency.
* **SLH-DSA-SHA2-192s, deliberately deferred:** category 3 for defense-in-depth maximalists
  at ~2x the fees of 128s. FIPS 205 instantiates the 192-bit SHA2 sets with SHA-512 in
  addition to SHA-256, so activating 192s would add a new primitive to consensus validation.
  Deferring it keeps this BIP's headline claim of no new primitives exactly true, and rule V6
  makes later activation cheap.

**Why commit to a hash of the key rather than the key itself?** Uniformity: future sets with
48- or 64-byte keys could not fit BIP 141's 40-byte program limit, while every key size hides
behind the same 32-byte program and one address format. Defense in depth: the key reaches the
chain only at spend time, so even a hypothetical break of SLH-DSA itself would not endanger
unspent P2SLH outputs. This restores the hash shielding that P2PKH had and P2TR gave up.
Domain separation: the tag isolates this commitment from every other use of SHA-256 in
Bitcoin. The cost is 33 witness bytes at spend time, about 0.4% of the witness.

**Why do unknown ids succeed?** The alternative freezes the parameter registry forever:
converting an invalid spend into a valid one later is a hard fork, while converting
V6-success into defined rules is a soft fork. The rule is not a theft vector. V6 is reachable
only after the V5 hash check, so stealing an output whose committed key has a defined id
requires a second preimage of a tagged SHA-256 hash, a strictly stronger break than any this
BIP defends against. Only an output deliberately committed to an undefined id is
anyone-can-spend, exactly the status quo for sending to witness version 4 today, and no
wallet can do it by accident. The same reasoning is why registry entries can be added but
never removed: retiring a used id would confiscate. The mitigation is a minimal, maximally
conservative active set.

**Why strict two-element arity?** A tolerated-but-ignored witness element would be a free
malleability vector: third parties could pad witnesses in relay, churning wtxids and
degrading compact-block reconstruction. With fixed arity, fixed per-id lengths, the
0x00-hash_type prohibition, and the annex committed by the signature, no byte of a P2SLH
witness can be modified by anyone but the signer. Future flexibility lives in three places
that are each safe: undefined ids, the annex, and `ext_flag >= 1` message contexts.

**Why is the message not pre-hashed to 32 bytes?** SLH-DSA hashes the message together with a
per-signature randomizer, so the scheme's unforgeability does not rest on collision
resistance of its message hash. Collapsing SigMsg to a digest first, as BIP 341 does for
Schnorr, would reintroduce a collision target at the outer digest and discard a robustness
property the scheme was designed to provide. Passing the tagged SigMsg preimage directly
costs nothing: the FIPS pure interface accepts arbitrary-length messages, and BIP 341's
cached component hashes are reused unchanged. The scope is worth stating precisely: the
component hashes inside SigMsg remain plain SHA-256, so multi-party construction such as PSBT
workflows and coinjoins retains the same collision-resistance reliance as BIP 341. A signer
who constructs its entire transaction, the normal cold-storage case, exposes no collision
surface at all. The HashSLH-DSA prehash variant is not used.

**Why a bare output type instead of a tapscript opcode in a P2MR leaf?** The two are
complements, and this BIP is deliberately the smaller half. A tapscript opcode is the right
successor: it brings multisig, timelocks, and vault scripts, and it belongs inside whichever
commitment container the community converges on. But the container question is exactly what
remains in flux as of mid-2026, between P2MR, P2TRv2-style proposals, P2TRH, and per-input
witness carriage, and no container is activated. Coupling the signature scheme to one
container makes the insurance hostage to that debate. A bare output type is self-sufficient:
one new branch in witness validation, no script-engine interaction, no element-size or
budget-rule changes, auditable end to end in twelve rules. It protects coins moved to it
today rather than after a second fork. The verification layer defined here, meaning the key
encoding, tags, message structure, and V-rules, is written to be lifted verbatim into the
successor opcode under `ext_flag >= 1`. This BIP is the dependency of that roadmap, not a
fork of it. A single-leaf P2MR is not an alternative: BIP 360 makes depth-zero trees
anyone-can-spend, and a P2MR tree whose leaves await a signature opcode cannot be spent
post-quantum-securely until the equivalent of this BIP activates anyway.

**Why no EC hybrid?** Requiring both a Schnorr and an SLH-DSA signature hedges the failure of
the post-quantum scheme. That hedge has real value for lattice schemes. For SLH-DSA it
protects only against a failure of SHA-256 preimage resistance, an event that destroys
Bitcoin globally regardless of output type. A hybrid would also add a secp256k1 code path to
an output type whose entire purpose is to have none, and re-import the harvest-now
key-exposure problem. No secp256k1 anywhere in validation is a design conclusion, not merely
a requirement.

**Fees and capacity, honestly.** At 1 sat/vB a P2SLH-128s spend costs ~2,015 sats in fees,
about 35x a Taproot key-path spend. The asymmetry matters: entering P2SLH is cheap, since a
migration input is an ordinary EC spend toward a 34-byte output, roughly 10,000 migrations
per block and identical for every signature scheme. What P2SLH cannot carry is the network's
ongoing spend volume, about 500 inputs per block at 128s. This output type is a vault, not a
payment rail, and no signature scheme changes that. Future aggregation and carriage work is
the scaling path; hash-based signatures are the friendliest known target for STARK-style
aggregation, but none of it can retroactively compress P2SLH spends and none of it is needed
for the rail to serve its purpose. Wallets should treat sub-economic P2SLH UTXOs as a footgun
and consolidate.

**Why witness version 3?** Among post-quantum proposals, BIP 360 claims version 2. No merged
BIP and no open PR to the BIPs repository claims version 3 as of July 2026. Several informal
proposals have floated version 3 in discussion, including an ML-DSA-65 key-path sketch and
P2WOTS; none has an assigned number or in-repo text. This BIP claims only the version-3,
32-byte, native point and leaves all other version-3 program lengths open. The final version
number is expected to be coordinated with the BIP editors at assignment time, and nothing in
this design depends on the specific number.

## Backward compatibility

Creating P2SLH outputs requires no consensus change and is already standard: bech32m-capable
wallets can send to `bc1r` addresses today. To nodes without this BIP's rules, P2SLH spends
are anyone-can-spend under the BIP 141 unknown-version rule, so **no value should be sent to
P2SLH addresses until the new rules are active**. Spending is doubly nonstandard until
activation under existing policy. All new rules strictly add failure conditions, so
activation is a soft fork. No existing output type, transaction form, or wallet behavior
changes.

## Security

**Assumptions.** P2SLH validation introduces no primitive beyond SHA-256 and its standard
keyed modes, and no assumptions beyond preimage-type and PRF properties of that family, which
proof-of-work and every existing address type already depend on. Current cryptanalysis is
nowhere near threatening them. The signature scheme itself does not rest on collision
resistance of its message hash; see the pre-hashing rationale for the precise scope.

**Blast radius.** If SLH-DSA were somehow broken, unspent P2SLH outputs remain protected by
the key hash until first spend, unlike P2TR outputs under an EC break today. If SHA-256
preimage resistance were broken, all of Bitcoin fails together; P2SLH adds no marginal
exposure.

**Multi-target.** An attacker targeting N outputs at once gains at most a factor-N advantage
against the 256-bit commitment, irrelevant at that size. Within SLH-DSA, multi-target attacks
are addressed by FIPS 205's tweakable-hash constructions, and the security categories hold to
2^64 signatures per key. Key reuse is cryptographically safe; wallets should still avoid
address reuse for privacy.

**Denial of service.** The worst-case P2SLH block is ~5-8x cheaper to verify per weight unit
than the worst-case Taproot block; signatures this large are their own rate limiter.
Verification is a pure function of public data. The script-execution cache applies unchanged;
the signature cache extends with one new fixed-size entry type. Validation parallelizes
across inputs as today. Peak additional memory is bounded by block weight.

**Malleability.** SLH-DSA targets SUF-CMA, keys and signatures are fixed-length with a single
canonical encoding, and rules V3, V7, and V8 pin the witness shape exactly. No third party
can alter a P2SLH spend's wtxid. Signatures are not canonical across signers, since the
hedged variant is randomized; this matches BIP 340 behavior and has no consensus impact.

**Privacy.** A P2SLH output is identifiable at creation time, so early adopters form a small
anonymity set that flags high-value storage; this is true of every new output type and
diminishes with adoption. The parameter set is hidden until spend, then revealed by witness
sizes. Within one parameter set all spends look alike.

## Policy recommendations (informative)

* Relay and mempool acceptance for version-3, 32-byte spends whose witness matches Table 1
  shapes, analogous to the Taproot standardness carve-outs; witness elements up to 17,089
  bytes should be permitted for this spend type.
* A policy flag treating undefined-id spends as nonstandard, mirroring the existing
  discourage-upgradable precedents.
* Annex-bearing spends remain nonstandard until an annex use is defined.
* Wallets should account for true spend cost when funding P2SLH outputs: an output worth less
  than its own spend cost at prevailing feerates is a footgun, and implementations may raise
  the effective dust threshold for these outputs accordingly.

## Wallet guidance (informative)

* **Key hygiene, normative for wallets:** a P2SLH key MUST be used exclusively to sign
  `SLHSighash` messages as defined here or under future `ext_flag >= 1` contexts. Wallets and
  HSMs MUST NOT expose a generic pure-SLH-DSA signing interface with an empty context string
  over a key that controls P2SLH outputs, since a generic oracle could be fed a well-formed
  sighash message and produce a coin-moving signature. Devices signing non-Bitcoin data with
  SLH-DSA keys must use distinct keys or a non-empty FIPS 205 context string.
* **Derivation:** post-quantum keys have no public homomorphism, so non-hardened BIP 32
  derivation and xpub watch-only wallets are impossible. Hardened-only derivation works: key
  generation consumes 48 seed bytes for the active sets, derivable from a master seed via
  existing hardened-HMAC constructions. A follow-up BIP should standardize the derivation and
  descriptor form. Watch-only deployments use explicit key or address lists.
* **Performance:** key generation is ~85 Mcycles for 128s, so cache derived addresses.
  Signing is ~0.2 s for 128s or ~10 ms for 128f on desktop hardware. Microcontroller-class
  signers without SHA-256 acceleration should use 128f or hardware SHA-256.
* **Signing mode:** use the hedged variant with verify-after-sign as fault hardening.
  Verification is identical for both variants. SLH-DSA is stateless: keys may be restored
  from seed backups and used from multiple devices safely, and seed words remain a complete
  backup.
* **Do not send to P2SLH addresses before activation.**

## Relationship to other work

* **BIP 360, P2MR:** complementary. P2MR supplies a quantum-resistant script-tree container
  and defers the signature scheme; this BIP supplies the scheme in self-contained form. A
  successor tapscript opcode can adopt this BIP's key encoding, tags, message structure, and
  test vectors verbatim, bringing post-quantum multisig to P2MR or any future container.
* **BIP 361:** this BIP satisfies its `Requires: TBD Post Quantum Signature BIP` dependency
  while neither endorsing nor opposing it or any migration policy.
* **P2TRv2, EC-disabling triggers, and post-quantum witness carriage:** complementary. Those
  designs optimize low-friction mass adoption and EC-disable mechanics. P2SLH is EC-free by
  construction, so its guarantees need no tripwire, no EC-disable fork, and no carriage
  change, and all of those designs presuppose a standardized post-quantum verifier such as
  this one. P2SLH data lives entirely in the existing BIP 141 witness; no new transaction
  identifier or commitment structure is introduced.
* **Commit/reveal and recovery schemes:** orthogonal and compatible; they protect existing
  coins without new signatures, while this BIP provides the forward-looking destination they
  do not.
* **Research schemes such as SHRINCS and SHRIMPS:** promising directions for cheaper
  hash-based signatures, excluded here because consensus should adopt externally standardized
  cryptography. Rule V6 gives them a clean landing path if they mature into standards.

This design draws directly on Matt Corallo's
["Trivial QC signatures with a clean upgrade path"](https://groups.google.com/g/bitcoindev/c/8O857bRSVV8),
Antoine Poinsot's
["In defense of a PQ output type"](https://groups.google.com/g/bitcoindev/c/JA3kDl8AmQg),
Tim Ruffing's post-quantum analysis of taproot commitments in
[eprint 2025/1307](https://eprint.iacr.org/2025/1307), the hash-based signature research of
Kudinov and Nick, SLH-DSA benchmarking by conduition, and the BIP 360 and 361 groundwork by
their respective authors.

## Test vectors and reference implementation

To be shipped in `bip-XXXX/` before any request for number assignment:

* SLH-DSA verify vectors cross-checked against the NIST ACVP set for both active parameter
  sets;
* valid and invalid spend vectors exercising every V-rule: each valid `hash_type`; invalid
  `hash_type` values failing V9; annex present and absent; undefined-id success; `0x50`-key
  two-element failure and three-element success; empty last element not treated as an annex;
  four-element witness failing V3 after annex removal; wrong key and signature lengths;
  explicit `hash_type` byte `0x00` failure; `SIGHASH_SINGLE` without a corresponding output;
* a Bitcoin Core branch implementing validation with a vendored verify-only SLH-DSA-SHA2,
  roughly 2.5k LOC with no heap allocation and no floating point, plus worst-case block
  benchmarks and a Bitcoin Inquisition patch for signet.

## Deployment

Activation is expected via version bits. Parameters are deliberately unspecified and should
be proposed only after the specification has converged under review, following the BIP 341
precedent.

## Changelog

* **0.1.0** (2026-07-23): initial draft.

## Copyright

This document is licensed under the 3-clause BSD license.

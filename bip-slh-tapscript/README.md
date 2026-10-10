# Auxiliary files for the SLH-DSA tapscript BIP

This directory holds the reference code and the test vectors for `OP_CHECKSIGPQADD`.
All code is Python 3 and uses only the standard library.

## Files

| File | Contents |
|---|---|
| `slhdsa.py` | FIPS 205 SLH-DSA-SHA2-128s. Key generation from seeds, deterministic and randomized signing, and verification. It has the pure interface with a context string and the internal functions. |
| `test_slhdsa_acvp.py` | Checks `slhdsa.py` against the NIST ACVP vectors for SLH-DSA-SHA2-128s. |
| `reference.py` | The rules of `OP_CHECKSIGPQADD`, the signature message, and the signature encoding in chunks. It also has a minimal verifier for P2MR and P2TR script path spends, with the BIP 342 validation budget. |
| `gen_vectors.py` | Generates `vectors.json`. The output is deterministic. |
| `vectors.json` | The test vectors, in the format of the Bitcoin Core unit test `script_assets_test`. |
| `run_vectors.py` | Checks each vector in `vectors.json` against `reference.py`. |
| `NOTES.md` | Problems found in the BIP text, decisions, and proposed changes. |

## How to run

Run all commands in this directory.

```
python3 test_slhdsa_acvp.py [cache_dir]
python3 gen_vectors.py
python3 run_vectors.py [-v]
```

The ACVP test downloads about 70 MB of JSON files the first time.
It stores them in `cache_dir`, or in `$ACVP_CACHE`, or in `<tmpdir>/acvp-cache`.
Do not add these files to the repository.
The test takes about 30 seconds on 12 cores.

`gen_vectors.py` takes about 1 minute.
It writes `vectors.json`, which is about 1.2 MB.
Two runs give the same file, byte for byte.
`run_vectors.py` takes about 10 seconds.

## ACVP test results

The vectors come from the NIST ACVP-Server repository at commit
`975de31eb83d87039ec88934fdc47d8c312b892d`
(directories `gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205`).
The test reads `internalProjection.json`, which contains the inputs and the expected results.
Only the cases for SLH-DSA-SHA2-128s are used.

| Test | Groups | Passed | Failed | Skipped |
|---|---|---|---|---|
| keyGen | 1 | 10 | 0 | 0 |
| sigGen | external/pure and internal, each deterministic and randomized | 28 | 0 | 24 |
| sigVer | external/pure and internal | 28 | 0 | 14 |

The sigGen and sigVer cases for the external interface have non-empty context strings.
The skipped cases use the pre-hash interface (HashSLH-DSA).
This BIP does not use the pre-hash interface, so `slhdsa.py` does not implement it.

## Test vector format

`vectors.json` is a JSON array.
Each object has the fields of `script_assets_test` in Bitcoin Core (`src/test/script_assets_tests.cpp`):

* `tx`: the spending transaction, serialized without witness.
* `prevouts`: the spent outputs, one for each input.
* `index`: the input to verify.
* `flags`: the script verification flags.
* `comment`: the name of the vector.
* `final`: if true, the `success` witness is valid under all flags.
* `success`: a `scriptSig` and a `witness` that must be valid under each subset of `flags`.
* `failure`: a `scriptSig` and a `witness` that must be invalid under each superset of `flags`.

The flag names are the names in Bitcoin Core, and two new names:

* `P2MR`: validation of witness version 2 outputs as in BIP 360.
  This matches `SCRIPT_VERIFY_P2MR` in Bitcoin Core pull request 35107.
* `PQSIG`: the rules of this BIP, in the enabled output types.
  The vectors use P2MR as the only enabled output type.

If a vector has a `failure` witness, its comment ends with `[failure: <ERROR>]`.
`ERROR` is the error code in `reference.py` for the rule that fails.
`script_assets_test` does not read this part.
`run_vectors.py` checks it.

## Test vector results

`python3 run_vectors.py` gives this result:

```
85 vectors, 256 flag combinations
Witnesses: 23 success, 67 failure
85 of 85 vectors passed
```

| Group | Vectors | Rules that the group tests |
|---|---|---|
| `slhdsa/single` | 43 | Valid signature, bit flips, each wrong count encoding, wrong chunk sizes at each position, missing and extra elements, cross-leaf replay, `key_version` 0x00, annex added, inactive opcode, P2MR parity bit |
| `slhdsa/annex` | 2 | The message commits to the annex |
| `slhdsa/multisig` | 6 | Valid 2-of-3 with an empty count for the key that does not sign, threshold not met, swapped signatures |
| `slhdsa/n` | 7 | `n` accumulates, negative `n`, `n` of 4 and 5 bytes, `n + 1` of 5 bytes, non-minimal `n` |
| `slhdsa/codesep` | 2 | `codesep_pos` is in the message |
| `slhdsa/pubkey` | 6 | Empty key, key type `0x01` with the wrong length |
| `slhdsa/unknown_key` | 10 | Unknown key types succeed, and each check with `c` larger than 0 costs 50 budget units |
| `slhdsa/stack` | 2 | Fewer than 3 stack elements |
| `slhdsa/budget` | 2 | One signature checked 4 times is valid, 5 times exceeds the budget |
| `slhdsa/inactive` | 5 | P2TR (opcode 202 is `OP_SUCCESS202`), leaf version `0xc2`, P2MR tree of depth zero, another `OP_SUCCESSx` |

Failure witnesses by expected error:

| Error | Count |
|---|---|
| `SLH_SIG_SIZE` | 21 |
| `SLH_SIG` | 15 |
| `SLH_COUNT` | 8 |
| `EVAL_FALSE` | 5 |
| `INVALID_STACK_OPERATION` | 4 |
| `SLH_PUBKEY_SIZE` | 4 |
| `TAPSCRIPT_VALIDATION_WEIGHT` | 3 |
| `SCRIPTNUM` | 2 |
| `TAPSCRIPT_EMPTY_PUBKEY` | 2 |
| `CLEANSTACK` | 1 |
| `PUSH_SIZE` | 1 |
| `WITNESS_PROGRAM_MISMATCH` | 1 |

`run_vectors.py` also checks the soft fork property.
Each failure that this BIP causes must be a success when `PQSIG` is not set.

The signature message in `reference.py` was also compared with `TaprootSignatureMsg` in the Bitcoin Core test framework.
The P2MR Merkle roots were compared with `p2mr.py` of BIP 360.
These checks are not part of this directory.

## Limits of `reference.py`

* The tapscript interpreter implements only the opcodes that the vectors use.
  Other opcodes raise `NotImplementedError`.
* It does not implement BIP 340 signatures or the P2TR key path.
* It requires an empty `scriptSig` and a witness program of 32 bytes.
* `slhdsa.py` is not constant time. Do not use it with real keys.

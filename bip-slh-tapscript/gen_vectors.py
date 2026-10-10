#!/usr/bin/env python3
"""Generate vectors.json, the test vectors for OP_CHECKSIGPQADD.

The output uses the format of Bitcoin Core's script_assets_test
(src/test/script_assets_tests.cpp). Each vector has the fields tx, prevouts,
index, flags, comment, an optional final, and success and/or failure.

Harness rules (from script_assets_test):
* A success witness must be valid under every subset of "flags".
  With "final": true, it must be valid under every flag combination.
* A failure witness must be invalid under every superset of "flags".

The comment has the form "slhdsa/<group>/<name>". If the vector has a failure
witness, the comment ends with "[failure: <ERROR>]". ERROR is the error code
of reference.py for the rule that fails. run_vectors.py checks it.

All keys and signatures are deterministic, so the output is reproducible.

Usage: python3 gen_vectors.py [output_path]
"""

import json
import os
import sys

import reference as ref
import slhdsa
from reference import (OP_0, OP_1, OP_1NEGATE, OP_16, OP_CHECKSIGPQADD as CSA,
                       OP_CODESEPARATOR, OP_EQUAL, OP_NOP, OP_NUMEQUAL, OP_PICK, Tx, TxIn, TxOut,
                       sha256)

ALL_FLAGS = "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT,P2MR,PQSIG"
FLAGS_NO_PQSIG = "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT,P2MR"
OP_SUCCESS80 = 0x50
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_2 = 0x52


def det_bytes(label, n):
    """Deterministic pseudo-random bytes."""
    out = b""
    i = 0
    while len(out) < n:
        out += sha256(("%s/%d" % (label, i)).encode())
        i += 1
    return out[:n]


def push(data):
    """Minimal push of data (for data that is not a small number)."""
    n = len(data)
    if n == 0:
        return bytes([OP_0])
    if n < 0x4c:
        return bytes([n]) + data
    if n <= 0xff:
        return bytes([0x4c, n]) + data
    return bytes([0x4d]) + n.to_bytes(2, "little") + data


def script(*parts):
    out = b""
    for p in parts:
        out += bytes([p]) if isinstance(p, int) else p
    return out


class Key:
    def __init__(self, name):
        seeds = [det_bytes("slh-tapscript/key/%s/%s" % (name, s), slhdsa.N)
                 for s in ("sk_seed", "sk_prf", "pk_seed")]
        self.sk, pk = slhdsa.slh_keygen(*seeds)
        self.pubkey = bytes([ref.KEY_TYPE_SLH_DSA_SHA2_128S]) + pk


KEY_A = Key("A")
KEY_B = Key("B")
KEY_C = Key("C")
PK_A = push(KEY_A.pubkey)
PK_B = push(KEY_B.pubkey)
PK_C = push(KEY_C.pubkey)
PK_UNKNOWN = push(b"\x02" + det_bytes("unknown key", 32))


class Fixture:
    """A transaction that spends one P2MR (or P2TR) output with a script tree.

    leaves: list of scripts. One leaf gets a hidden sibling, so it is at depth 1.
    With depth0=True, a single leaf is the whole tree (depth zero).
    """

    def __init__(self, name, leaves, index=0, leaf_version=ref.LEAF_VERSION_TAPSCRIPT,
                 witness_version=2, depth0=False):
        self.name = name
        self.leaves = leaves
        self.leaf_version = leaf_version
        self.witness_version = witness_version
        hashes = [ref.tapleaf_hash(s, leaf_version) for s in leaves]
        if depth0:
            assert len(leaves) == 1
            root = hashes[0]
            self.paths = [b""]
        elif len(leaves) == 1:
            sibling = sha256(b"hidden sibling " + name.encode())
            root = ref.tapbranch_hash(hashes[0], sibling)
            self.paths = [sibling]
        else:
            assert len(leaves) == 2
            root = ref.tapbranch_hash(hashes[0], hashes[1])
            self.paths = [hashes[1], hashes[0]]
        if witness_version == 1:
            # P2TR: use the BIP 341 NUMS point as the internal key.
            self.internal_key = bytes.fromhex(
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
            self.output_key, self.parity = ref.taproot_tweak(self.internal_key, root)
            spk = bytes([OP_1, 0x20]) + self.output_key
        else:
            spk = bytes([OP_1 + 1, 0x20]) + root
        self.index = index
        other = TxOut(50000, bytes([0x00, 0x14]) + det_bytes(name + "/other spk", 20))
        mine = TxOut(100000, spk)
        self.prevouts = [other, other]
        self.prevouts[index] = mine
        vin = [TxIn(det_bytes(name + "/prevout%d" % i, 32) + (i).to_bytes(4, "little"),
                    sequence=0xfffffffd) for i in range(2)]
        vout = [TxOut(140000, bytes([OP_1, 0x20]) + det_bytes(name + "/dest", 32))]
        self.tx = Tx(version=2, vin=vin, vout=vout, locktime=0)

    def control(self, leaf):
        if self.witness_version == 1:
            return bytes([self.leaf_version | self.parity]) + self.internal_key + self.paths[leaf]
        return bytes([self.leaf_version | 1]) + self.paths[leaf]

    def witness(self, stack, leaf=0, annex=None, control=None):
        w = list(stack) + [self.leaves[leaf], self.control(leaf) if control is None else control]
        if annex is not None:
            w.append(annex)
        return w

    def sign(self, key, leaf=0, annex=None, codesep_pos=0xffffffff, key_version=0x01):
        leaf_hash = ref.tapleaf_hash(self.leaves[leaf], self.leaf_version)
        msg = ref.slh_signature_msg(self.tx, self.prevouts, self.index, annex, leaf_hash,
                                    codesep_pos, key_version)
        sig = slhdsa.slh_sign(msg, b"", key.sk, deterministic=True)
        return ref.encode_signature(sig)

    def vector(self, comment, flags=ALL_FLAGS, success=None, failure=None, error=None, final=False):
        assert (failure is None) == (error is None)
        if error is not None:
            comment += " [failure: %s]" % error
        v = {
            "tx": self.tx.serialize_without_witness().hex(),
            "prevouts": [o.serialize().hex() for o in self.prevouts],
            "index": self.index,
            "flags": flags,
            "comment": comment,
        }
        if final:
            v["final"] = True
        if success is not None:
            v["success"] = {"scriptSig": "", "witness": [e.hex() for e in success]}
        if failure is not None:
            v["failure"] = {"scriptSig": "", "witness": [e.hex() for e in failure]}
        return v


def garbage_sig(label):
    """A correctly sized but invalid signature."""
    return ref.encode_signature(det_bytes("garbage/" + label, slhdsa.SIG_BYTES))


def flip(sig, chunk, pos):
    """Flip one bit in chunk number `chunk` (1-based, witness order) at byte `pos`."""
    s = [bytearray(e) for e in sig]
    s[chunk - 1][pos] ^= 0x01
    return [bytes(e) for e in s]


def dup17():
    """Copy the top 17 stack elements (one signature with its count)."""
    return bytes([OP_16, OP_PICK] * 17)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "vectors.json")
    V = []

    # Single signature. The P2MR input is at index 1. The tree has two leaves
    # with the same key, for the cross-leaf replay test.
    leaf_single = script(OP_0, PK_A, CSA)
    leaf_single2 = script(OP_0, PK_A, CSA, OP_1, OP_NUMEQUAL)
    f = Fixture("single", [leaf_single, leaf_single2], index=1)
    sig = f.sign(KEY_A)
    chunks, count = sig[:16], sig[16]
    G = "slhdsa/single/"
    V.append(f.vector(G + "valid_bitflip_chunk1", success=f.witness(sig),
                      failure=f.witness(flip(sig, 1, 0)), error=ref.ERR_SLH_SIG, final=True))
    V.append(f.vector(G + "bitflip_chunk16", failure=f.witness(flip(sig, 16, 55)), error=ref.ERR_SLH_SIG))
    V.append(f.vector(G + "bitflip_chunk8", failure=f.witness(flip(sig, 8, 300)), error=ref.ERR_SLH_SIG))
    V.append(f.vector(G + "swap_chunk1_chunk2",
                      failure=f.witness([chunks[1], chunks[0]] + chunks[2:] + [count]), error=ref.ERR_SLH_SIG))
    V.append(f.vector(G + "no_signature", failure=f.witness([b""]), error=ref.ERR_EVAL_FALSE))

    # Wrong count encodings. The chunks stay the same.
    for name, c in [("count_0x00", b"\x00"), ("count_0x80", b"\x80"), ("count_0x81", b"\x81"),
                    ("count_0x90", b"\x90"), ("count_0xff", b"\xff"),
                    ("count_two_bytes_0x1000", b"\x10\x00"), ("count_two_bytes_0x0010", b"\x00\x10")]:
        V.append(f.vector(G + name, failure=f.witness(chunks + [c]), error=ref.ERR_SLH_COUNT))
    # Count 15 and 17 with a matching number of elements.
    V.append(f.vector(G + "count_15", failure=f.witness(chunks[1:] + [b"\x0f"]), error=ref.ERR_SLH_SIG_SIZE))
    V.append(f.vector(G + "count_17", failure=f.witness([b"\x00" * 520] + chunks + [b"\x11"]),
                      error=ref.ERR_SLH_SIG_SIZE))
    # Count 1. Chunks 1 to 15 stay on the stack as padding, so the budget is not exceeded.
    V.append(f.vector(G + "count_1", failure=f.witness(chunks + [b"\x01"]), error=ref.ERR_SLH_SIG_SIZE))
    # Count 1 with a small witness. The budget charge (step 7) comes before the size checks (step 8).
    V.append(f.vector(G + "count_1_small_witness", failure=f.witness([chunks[15], b"\x01"]),
                      error=ref.ERR_VALIDATION_WEIGHT))
    # Too few and too many stack elements.
    V.append(f.vector(G + "missing_chunk1", failure=f.witness(chunks[1:] + [count]),
                      error=ref.ERR_INVALID_STACK_OPERATION))
    V.append(f.vector(G + "extra_element_below", failure=f.witness([b"\x01"] + sig), error=ref.ERR_CLEANSTACK))
    # Wrong chunk sizes, at each position. Chunks 1 to 15 lose their last byte.
    # Chunk 16 gets one extra byte.
    for k in range(1, 17):
        bad = list(chunks)
        bad[k - 1] = bad[k - 1][:-1] if k < 16 else bad[k - 1] + b"\x00"
        V.append(f.vector(G + "chunk%d_wrong_size" % k, failure=f.witness(bad + [count]),
                          error=ref.ERR_SLH_SIG_SIZE))
    # The same 7,856 bytes, split at a different place.
    joined = b"".join(chunks)
    resplit = [joined[i * 520:(i + 1) * 520] for i in range(14)] + [joined[14 * 520:15 * 520 - 1],
                                                                   joined[15 * 520 - 1:]]
    V.append(f.vector(G + "chunk15_519_chunk16_57", failure=f.witness(resplit + [count]),
                      error=ref.ERR_SLH_SIG_SIZE))
    resplit = [joined[:56]] + [joined[56 + i * 520:56 + (i + 1) * 520] for i in range(15)]
    V.append(f.vector(G + "short_chunk_first", failure=f.witness(resplit + [count]), error=ref.ERR_SLH_SIG_SIZE))
    # An element larger than 520 bytes fails before the opcode runs.
    V.append(f.vector(G + "chunk1_521_bytes", failure=f.witness([chunks[0] + b"\x00"] + chunks[1:] + [count]),
                      error=ref.ERR_PUSH_SIZE))
    # Cross-leaf replay: the signature for leaf 0 is used in leaf 1 of the same tree.
    V.append(f.vector(G + "other_leaf_replay", failure=f.witness(sig, leaf=1), error=ref.ERR_SLH_SIG))
    # Signature over a message with key_version 0x00 instead of 0x01.
    sig_kv0 = f.sign(KEY_A, key_version=0x00)
    V.append(f.vector(G + "key_version_0x00", failure=f.witness(sig_kv0), error=ref.ERR_SLH_SIG))
    # Signature of another key.
    sig_b = f.sign(KEY_B)
    V.append(f.vector(G + "signature_of_other_key", failure=f.witness(sig_b), error=ref.ERR_SLH_SIG))
    # A valid signature with an annex added. The message commits to the annex.
    V.append(f.vector(G + "annex_added", failure=f.witness(sig, annex=b"\x50"), error=ref.ERR_SLH_SIG))
    # Before activation of this BIP (PQSIG not set), opcode 202 is OP_SUCCESS202 in P2MR too.
    V.append(f.vector(G + "inactive_garbage_signature", flags=FLAGS_NO_PQSIG,
                      success=f.witness(garbage_sig("inactive"))))
    # The P2MR parity bit must be 1.
    V.append(f.vector(G + "p2mr_parity_bit_0",
                      failure=f.witness(sig, control=bytes([0xc0]) + f.paths[0]),
                      error=ref.ERR_WITNESS_PROGRAM_MISMATCH))

    # Annex.
    annex = b"\x50" + det_bytes("annex", 20)
    f = Fixture("annex", [leaf_single])
    sig = f.sign(KEY_A, annex=annex)
    G = "slhdsa/annex/"
    V.append(f.vector(G + "valid_other_annex", success=f.witness(sig, annex=annex),
                      failure=f.witness(sig, annex=annex[:-1] + b"\x00"), error=ref.ERR_SLH_SIG))
    V.append(f.vector(G + "annex_removed", failure=f.witness(sig), error=ref.ERR_SLH_SIG))

    # 2-of-3 multisignature.
    leaf_2of3 = script(OP_0, PK_A, CSA, PK_B, CSA, PK_C, CSA, OP_2, OP_NUMEQUAL)
    f = Fixture("2of3", [leaf_2of3])
    sig_a = f.sign(KEY_A)
    sig_c = f.sign(KEY_C)
    G = "slhdsa/multisig/"
    V.append(f.vector(G + "2of3_valid_AC_1of3", success=f.witness(sig_c + [b""] + sig_a),
                      failure=f.witness([b""] + [b""] + sig_a), error=ref.ERR_EVAL_FALSE, final=True))
    V.append(f.vector(G + "2of3_only_C", failure=f.witness(sig_c + [b""] + [b""]), error=ref.ERR_EVAL_FALSE))
    V.append(f.vector(G + "2of3_none", failure=f.witness([b"", b"", b""]), error=ref.ERR_EVAL_FALSE))
    V.append(f.vector(G + "2of3_swapped", failure=f.witness(sig_a + [b""] + sig_c), error=ref.ERR_SLH_SIG))
    V.append(f.vector(G + "2of3_garbage_for_B", failure=f.witness(sig_c + garbage_sig("B") + sig_a),
                      error=ref.ERR_SLH_SIG))
    V.append(f.vector(G + "2of3_missing_count_for_B", failure=f.witness(sig_c + sig_a),
                      error=ref.ERR_SLH_SIG))

    # CScriptNum n.
    G = "slhdsa/n/"
    f = Fixture("n5", [script(OP_5, PK_A, CSA, OP_6, OP_NUMEQUAL)])
    sig = f.sign(KEY_A)
    V.append(f.vector(G + "n5_plus_1_valid_no_signature", success=f.witness(sig),
                      failure=f.witness([b""]), error=ref.ERR_EVAL_FALSE, final=True))
    f = Fixture("nneg1", [script(OP_1NEGATE, PK_A, CSA, OP_0, OP_NUMEQUAL)])
    sig = f.sign(KEY_A)
    V.append(f.vector(G + "n_minus1_plus_1_valid", success=f.witness(sig), final=True))
    # n with 4 bytes is allowed, n with 5 bytes fails. An unknown key type and c = 0
    # isolate the rule.
    f = Fixture("n4bytes", [script(push(b"\xff\xff\xff\x7f"), PK_UNKNOWN, CSA, push(b"\xff\xff\xff\x7f"),
                                   OP_NUMEQUAL)])
    V.append(f.vector(G + "n_4_bytes_unknown_key", success=f.witness([b""])))
    f = Fixture("n5bytes", [script(push(b"\x00\x00\x00\x00\x00"), PK_UNKNOWN, CSA, OP_0, OP_NUMEQUAL)])
    V.append(f.vector(G + "n_5_bytes_unknown_key", failure=f.witness([b""]), error=ref.ERR_SCRIPTNUM))
    f = Fixture("n5bytes_a", [script(push(b"\x00\x00\x00\x00\x00"), PK_A, CSA)])
    V.append(f.vector(G + "n_5_bytes_key_a", failure=f.witness(garbage_sig("n5")), error=ref.ERR_SCRIPTNUM))
    # n + 1 can be 5 bytes, as for OP_CHECKSIGADD. The budget needs a large witness.
    f = Fixture("nmaxplus1", [script(push(b"\xff\xff\xff\x7f"), PK_UNKNOWN, CSA,
                                     push(b"\x00\x00\x00\x80\x00"), OP_EQUAL)])
    big = [det_bytes("nmax%d" % i, 520) for i in range(4)]
    V.append(f.vector(G + "n_max_plus_1_is_5_bytes", success=f.witness(big + [b"\x04"])))
    # A non-minimal n is valid under consensus rules (MINIMALDATA is policy only).
    f = Fixture("nnonminimal", [script(push(b"\x01\x00"), PK_UNKNOWN, CSA, OP_1, OP_NUMEQUAL)])
    V.append(f.vector(G + "n_non_minimal_unknown_key", success=f.witness([b""])))

    # OP_CODESEPARATOR. codesep_pos is the position of the last executed
    # OP_CODESEPARATOR (here 1), or 0xffffffff if there is none.
    G = "slhdsa/codesep/"
    f = Fixture("codesep", [script(OP_NOP, OP_CODESEPARATOR, OP_0, PK_A, CSA)])
    sig = f.sign(KEY_A, codesep_pos=1)
    sig_none = f.sign(KEY_A)
    V.append(f.vector(G + "codesep_pos_1_valid_none", success=f.witness(sig),
                      failure=f.witness(sig_none), error=ref.ERR_SLH_SIG, final=True))
    sig0 = f.sign(KEY_A, codesep_pos=0)
    V.append(f.vector(G + "codesep_pos_0", failure=f.witness(sig0), error=ref.ERR_SLH_SIG))

    # Public keys.
    G = "slhdsa/pubkey/"
    f = Fixture("emptypk", [script(OP_1, OP_0, CSA)])
    V.append(f.vector(G + "empty_c0", failure=f.witness([b""]), error=ref.ERR_EMPTY_PUBKEY))
    # With c = 1, the empty key fails at step 6, before the budget charge.
    V.append(f.vector(G + "empty_c1", failure=f.witness([b"\xaa", b"\x01"]), error=ref.ERR_EMPTY_PUBKEY))
    for name, pk in [("type1_1_byte", b"\x01"), ("type1_32_bytes", KEY_A.pubkey[:32]),
                     ("type1_34_bytes", KEY_A.pubkey + b"\x00")]:
        f = Fixture("pk_" + name, [script(OP_1, push(pk), CSA)])
        V.append(f.vector(G + name + "_c0", failure=f.witness([b""]), error=ref.ERR_SLH_PUBKEY_SIZE))
    f = Fixture("pk_type1_34_sig", [script(OP_0, push(KEY_A.pubkey + b"\x00"), CSA)])
    V.append(f.vector(G + "type1_34_bytes_with_signature", failure=f.witness(garbage_sig("34")),
                      error=ref.ERR_SLH_PUBKEY_SIZE))

    # Unknown key types. No verification. c > 0 costs 50 budget units.
    G = "slhdsa/unknown_key/"
    for name, pk in [("type0x00_1_byte", b"\x00"), ("type0x02_33_bytes", b"\x02" + det_bytes("u2", 32)),
                     ("type0xff_100_bytes", b"\xff" + det_bytes("uff", 99))]:
        f = Fixture("unk_c0_" + name, [script(OP_1, push(pk), CSA)])
        V.append(f.vector(G + name + "_c0", success=f.witness([b""])))
    f = Fixture("unk_c", [script(OP_0, PK_UNKNOWN, CSA)])
    big = [det_bytes("big%d" % i, 520) for i in range(3)] + [det_bytes("big3", 400)]
    V.append(f.vector(G + "c4_budget_ok", success=f.witness(big + [b"\x04"])))
    # A small signature is enough. The charge is 50, not 2,000.
    V.append(f.vector(G + "c1_small_witness_ok", success=f.witness([b"\xaa", b"\x01"])))
    # Many checks with small signatures. Each check adds about 38 bytes to the witness but costs
    # 50 budget units, so 3 checks pass and 40 checks exceed the budget.
    for n_checks, ok in [(3, True), (40, False)]:
        ops = [OP_0]
        for _ in range(n_checks):
            ops += [PK_UNKNOWN, CSA]
        ops += [push(bytes([n_checks])), OP_NUMEQUAL]
        f2 = Fixture("unk_many_%d" % n_checks, [script(*ops)])
        wit = f2.witness([b"\xaa", b"\x01"] * n_checks)
        if ok:
            V.append(f2.vector(G + "many_checks_%d_ok" % n_checks, success=wit))
        else:
            V.append(f2.vector(G + "many_checks_%d_budget_exceeded" % n_checks, failure=wit,
                               error=ref.ERR_VALIDATION_WEIGHT))
    small = [det_bytes("s%d" % i, 16) for i in range(127)]
    V.append(f.vector(G + "c127_budget_ok", success=f.witness(small + [b"\x7f"])))
    V.append(f.vector(G + "c128_bad_count", failure=f.witness(small + [b"\x80"]),
                      error=ref.ERR_SLH_COUNT))
    V.append(f.vector(G + "c_too_few_elements", failure=f.witness(big + [b"\x05"]),
                      error=ref.ERR_INVALID_STACK_OPERATION))

    # Fewer than 3 stack elements.
    G = "slhdsa/stack/"
    f = Fixture("stack2", [script(OP_0, PK_A, CSA)])
    V.append(f.vector(G + "two_elements", failure=f.witness([]), error=ref.ERR_INVALID_STACK_OPERATION))
    f = Fixture("stack1", [script(PK_A, CSA)])
    V.append(f.vector(G + "one_element", failure=f.witness([]), error=ref.ERR_INVALID_STACK_OPERATION))

    # Budget. The witness holds one signature, so the budget allows 4 checks but not 5.
    G = "slhdsa/budget/"
    s4 = script(dup17() * 3, OP_0, PK_A, CSA, PK_A, CSA, PK_A, CSA, PK_A, CSA, OP_4, OP_NUMEQUAL)
    f = Fixture("reuse4", [s4])
    sig = f.sign(KEY_A)
    V.append(f.vector(G + "reuse_4_checks_valid", success=f.witness(sig), final=True))
    s5 = script(dup17() * 4, OP_0, PK_A, CSA, PK_A, CSA, PK_A, CSA, PK_A, CSA, PK_A, CSA, OP_5, OP_NUMEQUAL)
    f = Fixture("reuse5", [s5])
    sig = f.sign(KEY_A)
    V.append(f.vector(G + "reuse_5_checks", failure=f.witness(sig), error=ref.ERR_VALIDATION_WEIGHT))

    # Spends where the opcode is not active.
    G = "slhdsa/inactive/"
    f = Fixture("p2tr", [leaf_single], witness_version=1)
    V.append(f.vector(G + "p2tr_op_success202_garbage_signature", success=f.witness(garbage_sig("p2tr"))))
    V.append(f.vector(G + "p2tr_op_success202_no_stack", success=f.witness([])))
    f = Fixture("leafver", [leaf_single], leaf_version=0xc2)
    V.append(f.vector(G + "p2mr_leaf_version_0xc2_garbage_signature", success=f.witness(garbage_sig("lv"))))
    f = Fixture("depth0", [leaf_single], depth0=True)
    V.append(f.vector(G + "p2mr_depth_zero_garbage_signature", success=f.witness(garbage_sig("d0"))))
    # Another OP_SUCCESSx in the script still makes it succeed.
    f = Fixture("success80", [script(OP_0, PK_A, CSA, OP_SUCCESS80)])
    V.append(f.vector(G + "p2mr_op_success80_garbage_signature", success=f.witness(garbage_sig("s80"))))

    with open(out_path, "w") as fh:
        fh.write("[\n" + ",\n".join(json.dumps(v) for v in V) + "\n]\n")
    print("wrote %d vectors to %s (%d bytes)" % (len(V), out_path, os.path.getsize(out_path)))


if __name__ == "__main__":
    main()

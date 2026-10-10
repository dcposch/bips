"""Reference implementation of OP_CHECKSIGPQADD.

This module contains:

* the rules of OP_CHECKSIGPQADD (op_checksigpqadd),
* the signature message (slh_signature_msg),
* the signature encoding in chunks (encode_signature, decode_signature),
* a minimal verifier for P2MR (BIP 360) and P2TR (BIP 341) script path spends
  that runs tapscript (BIP 342), including the validation budget.

The tapscript interpreter implements only the opcodes that the test vectors
use. Any other opcode raises NotImplementedError, so it can never make a test
pass by accident. The P2TR key path (a BIP 340 signature) is not implemented.

The transaction serialization and the BIP 341 signature message are adapted
from Bitcoin Core's test/functional/test_framework (messages.py and script.py).
Copyright (c) 2010-present The Bitcoin Core developers. MIT license.
"""

import hashlib
from functools import lru_cache

import slhdsa

# Script verification flags. The names match Bitcoin Core's script_assets_test.
# P2MR matches SCRIPT_VERIFY_P2MR of Bitcoin Core PR #35107. PQSIG is this BIP.
CONSENSUS_FLAGS = ["P2SH", "DERSIG", "NULLDUMMY", "CHECKLOCKTIMEVERIFY",
                   "CHECKSEQUENCEVERIFY", "WITNESS", "TAPROOT", "P2MR", "PQSIG"]

MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_STACK_SIZE = 1000
VALIDATION_WEIGHT_OFFSET = 50
VALIDATION_WEIGHT_PER_SLH_SIGOP = 2000          # key type 0x01
VALIDATION_WEIGHT_PER_UNKNOWN_KEY_SIGOP = 50    # unknown key types
ANNEX_TAG = 0x50
LEAF_VERSION_TAPSCRIPT = 0xc0
TAPROOT_LEAF_MASK = 0xfe
CONTROL_NODE_SIZE = 32
CONTROL_MAX_NODE_COUNT = 128

# Key types of OP_CHECKSIGPQADD.
KEY_TYPE_SLH_DSA_SHA2_128S = 0x01
SLH_PUBKEY_SIZE = 33
SLH_CHUNK_COUNT = 16
SLH_CHUNK_SIZE = 520
SLH_LAST_CHUNK_SIZE = slhdsa.SIG_BYTES - 15 * SLH_CHUNK_SIZE   # 56

# Opcodes.
OP_0 = 0x00
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE = 0x4f
OP_1 = 0x51
OP_16 = 0x60
OP_NOP = 0x61
OP_VERIFY = 0x69
OP_DROP = 0x75
OP_DUP = 0x76
OP_PICK = 0x79
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_NUMEQUAL = 0x9c
OP_NUMEQUALVERIFY = 0x9d
OP_SHA256 = 0xa8
OP_CODESEPARATOR = 0xab
OP_CHECKSIGPQADD = 0xca


class ScriptError(Exception):
    """Validation failure. The code names the rule that failed."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


# Error codes. Where Bitcoin Core has a matching ScriptError, the name follows it.
ERR_EVAL_FALSE = "EVAL_FALSE"
ERR_VERIFY = "VERIFY"
ERR_EQUALVERIFY = "EQUALVERIFY"
ERR_NUMEQUALVERIFY = "NUMEQUALVERIFY"
ERR_CLEANSTACK = "CLEANSTACK"
ERR_BAD_OPCODE = "BAD_OPCODE"
ERR_PUSH_SIZE = "PUSH_SIZE"
ERR_STACK_SIZE = "STACK_SIZE"
ERR_INVALID_STACK_OPERATION = "INVALID_STACK_OPERATION"
ERR_SCRIPTNUM = "SCRIPTNUM"   # Core reports this as UNKNOWN_ERROR (scriptnum_error)
ERR_VALIDATION_WEIGHT = "TAPSCRIPT_VALIDATION_WEIGHT"
ERR_WITNESS_PROGRAM_WITNESS_EMPTY = "WITNESS_PROGRAM_WITNESS_EMPTY"
ERR_WITNESS_PROGRAM_MISMATCH = "WITNESS_PROGRAM_MISMATCH"
ERR_WRONG_CONTROL_SIZE = "TAPROOT_WRONG_CONTROL_SIZE"
ERR_EMPTY_PUBKEY = "TAPSCRIPT_EMPTY_PUBKEY"
# New error codes for this BIP.
ERR_SLH_COUNT = "SLH_COUNT"               # step 4: bad encoding of c
ERR_SLH_PUBKEY_SIZE = "SLH_PUBKEY_SIZE"   # step 8.1: key type 0x01, P not 33 bytes
ERR_SLH_SIG_SIZE = "SLH_SIG_SIZE"         # steps 8.2.1 and 8.2.2: wrong c or chunk size
ERR_SLH_SIG = "SLH_SIG"                   # step 8.2.3: SLH-DSA verification failed


# Hashing and serialization.

def sha256(b):
    return hashlib.sha256(b).digest()


def tagged_hash(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)


def ser_tag(tag):
    t = sha256(tag.encode())
    return t + t


def ser_compact_size(n):
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b"\xfd" + n.to_bytes(2, "little")
    if n < 0x100000000:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def ser_string(s):
    return ser_compact_size(len(s)) + s


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("unexpected end of data")
        r = self.data[self.pos:self.pos + n]
        self.pos += n
        return r

    def int(self, n, signed=False):
        return int.from_bytes(self.read(n), "little", signed=signed)

    def compact_size(self):
        n = self.int(1)
        if n == 253:
            return self.int(2)
        if n == 254:
            return self.int(4)
        if n == 255:
            return self.int(8)
        return n

    def string(self):
        return self.read(self.compact_size())


class TxOut:
    def __init__(self, value, script_pubkey):
        self.value = value
        self.script_pubkey = script_pubkey

    def serialize(self):
        return self.value.to_bytes(8, "little", signed=True) + ser_string(self.script_pubkey)

    @classmethod
    def deserialize(cls, r):
        value = r.int(8, signed=True)
        return cls(value, r.string())


class TxIn:
    def __init__(self, prevout, script_sig=b"", sequence=0xffffffff, witness=None):
        self.prevout = prevout          # 36 bytes: txid (internal byte order) || vout
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = [] if witness is None else witness

    def serialize(self):
        return self.prevout + ser_string(self.script_sig) + self.sequence.to_bytes(4, "little")


class Tx:
    def __init__(self, version=2, vin=None, vout=None, locktime=0):
        self.version = version
        self.vin = [] if vin is None else vin
        self.vout = [] if vout is None else vout
        self.locktime = locktime

    def serialize_without_witness(self):
        r = self.version.to_bytes(4, "little", signed=True)
        r += ser_compact_size(len(self.vin)) + b"".join(i.serialize() for i in self.vin)
        r += ser_compact_size(len(self.vout)) + b"".join(o.serialize() for o in self.vout)
        return r + self.locktime.to_bytes(4, "little")

    @classmethod
    def deserialize_without_witness(cls, data):
        r = Reader(data)
        tx = cls(version=r.int(4, signed=True))
        for _ in range(r.compact_size()):
            prevout = r.read(36)
            script_sig = r.string()
            tx.vin.append(TxIn(prevout, script_sig, r.int(4)))
        for _ in range(r.compact_size()):
            tx.vout.append(TxOut.deserialize(r))
        tx.locktime = r.int(4)
        if r.pos != len(data):
            raise ValueError("trailing data in transaction")
        return tx


def ser_witness_stack(stack):
    """Serialized size basis of the BIP 342 validation budget (GetSerializeSize)."""
    return ser_compact_size(len(stack)) + b"".join(ser_string(e) for e in stack)


# BIP 341 signature message.

def bip341_sigmsg(tx, spent_outputs, input_index, annex):
    """SigMsg(0x00, 1) of BIP 341 (hash_type SIGHASH_DEFAULT, ext_flag 1).

    Adapted from TaprootSignatureMsg in Bitcoin Core's test_framework/script.py.
    """
    assert len(tx.vin) == len(spent_outputs)
    hash_type = 0x00
    ss = bytes([hash_type])
    ss += tx.version.to_bytes(4, "little", signed=True)
    ss += tx.locktime.to_bytes(4, "little")
    ss += sha256(b"".join(i.prevout for i in tx.vin))
    ss += sha256(b"".join(o.value.to_bytes(8, "little", signed=True) for o in spent_outputs))
    ss += sha256(b"".join(ser_string(o.script_pubkey) for o in spent_outputs))
    ss += sha256(b"".join(i.sequence.to_bytes(4, "little") for i in tx.vin))
    ss += sha256(b"".join(o.serialize() for o in tx.vout))
    ext_flag = 1
    spend_type = ext_flag * 2 + (1 if annex is not None else 0)
    ss += bytes([spend_type])
    ss += input_index.to_bytes(4, "little")
    if annex is not None:
        ss += sha256(ser_string(annex))
    assert len(ss) == 174 + (32 if annex is not None else 0)
    return ss


def tapleaf_hash(script, leaf_version=LEAF_VERSION_TAPSCRIPT):
    return tagged_hash("TapLeaf", bytes([leaf_version]) + ser_string(script))


def tapbranch_hash(a, b):
    return tagged_hash("TapBranch", min(a, b) + max(a, b))


def slh_signature_msg(tx, spent_outputs, input_index, annex, leaf_hash, codesep_pos,
                      key_version=KEY_TYPE_SLH_DSA_SHA2_128S):
    """The message M of "Signature message".

    M = ser_tag("SLHSighash") || 0x00 || SigMsg(0x00, 1) || ext
    ext = tapleaf_hash || key_version || codesep_pos

    key_version is a parameter only so that the test vectors can build a
    signature for the wrong key_version. Consensus always uses 0x01.
    """
    ext = leaf_hash + bytes([key_version]) + codesep_pos.to_bytes(4, "little")
    return ser_tag("SLHSighash") + b"\x00" + bip341_sigmsg(tx, spent_outputs, input_index, annex) + ext


# Signature encoding.

def encode_signature(sig):
    """Split a signature into witness elements: chunk_1 .. chunk_16, then c.

    The list is in witness order, so the last element is on top of the stack.
    """
    assert len(sig) == slhdsa.SIG_BYTES
    chunks = [sig[i:i + SLH_CHUNK_SIZE] for i in range(0, len(sig), SLH_CHUNK_SIZE)]
    assert len(chunks) == SLH_CHUNK_COUNT and len(chunks[-1]) == SLH_LAST_CHUNK_SIZE
    return chunks + [bytes([len(chunks)])]


def decode_count(c):
    """Step 4. Return the count, or None if c is not a valid encoding."""
    if len(c) == 0:
        return 0
    if len(c) == 1 and 0x01 <= c[0] <= 0x7f:
        return c[0]
    return None


def decode_signature(elements):
    """Inverse of encode_signature for witness-ordered elements (no checks of sizes)."""
    c = decode_count(elements[-1])
    assert c is not None and len(elements) == c + 1
    return b"".join(elements[:-1])


# CScriptNum.

def scriptnum_decode(v, max_size=4):
    if len(v) > max_size:
        raise ScriptError(ERR_SCRIPTNUM)
    if len(v) == 0:
        return 0
    r = int.from_bytes(v, "little")
    if v[-1] & 0x80:
        return -(r & ~(0x80 << (8 * (len(v) - 1))))
    return r


def scriptnum_encode(n):
    if n == 0:
        return b""
    neg = n < 0
    a = abs(n)
    r = bytearray()
    while a:
        r.append(a & 0xff)
        a >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0x00)
    elif neg:
        r[-1] |= 0x80
    return bytes(r)


def cast_to_bool(v):
    for i, x in enumerate(v):
        if x != 0:
            return not (i == len(v) - 1 and x == 0x80)
    return False


# The SLH-DSA verification is cached, like Bitcoin Core's signature cache.
# This makes the test vector runner fast, because it runs each vector under
# many flag combinations.
@lru_cache(maxsize=4096)
def slh_verify_cached(pk, msg, sig):
    return slhdsa.slh_verify(msg, sig, b"", pk)


class ExecContext:
    """The data that OP_CHECKSIGPQADD needs about the spend."""

    def __init__(self, tx, spent_outputs, input_index, annex, leaf_hash, budget):
        self.tx = tx
        self.spent_outputs = spent_outputs
        self.input_index = input_index
        self.annex = annex
        self.leaf_hash = leaf_hash
        self.codesep_pos = 0xffffffff
        self.budget = budget
        self.slh_checks = 0          # number of checks with c > 0 (for statistics)
        self.slh_verifications = 0   # number of SLH-DSA verifications run

    def message(self):
        return slh_signature_msg(self.tx, self.spent_outputs, self.input_index,
                                 self.annex, self.leaf_hash, self.codesep_pos)


def op_checksigpqadd(stack, ctx):
    """Execute OP_CHECKSIGPQADD. The steps match "Rules for OP_CHECKSIGPQADD".

    stack is a list with the top element last. Raise ScriptError on failure.
    """
    # 1.
    if len(stack) < 3:
        raise ScriptError(ERR_INVALID_STACK_OPERATION)
    # 2.
    pubkey = stack.pop()
    n_bytes = stack.pop()
    c_bytes = stack.pop()
    # 3.
    n = scriptnum_decode(n_bytes, 4)
    # 4.
    c = decode_count(c_bytes)
    if c is None:
        raise ScriptError(ERR_SLH_COUNT)
    # 5. Pop chunk_c (top) down to chunk_1. sig = chunk_1 || ... || chunk_c.
    if len(stack) < c:
        raise ScriptError(ERR_INVALID_STACK_OPERATION)
    t = [stack.pop() for _ in range(c)]       # t[0] is chunk_c
    sig = b"".join(reversed(t))
    # 6.
    if len(pubkey) == 0:
        raise ScriptError(ERR_EMPTY_PUBKEY)
    # 7.
    if c > 0:
        ctx.slh_checks += 1
        if pubkey[0] == KEY_TYPE_SLH_DSA_SHA2_128S:
            ctx.budget -= VALIDATION_WEIGHT_PER_SLH_SIGOP
        else:
            ctx.budget -= VALIDATION_WEIGHT_PER_UNKNOWN_KEY_SIGOP
        if ctx.budget < 0:
            raise ScriptError(ERR_VALIDATION_WEIGHT)
    if pubkey[0] == KEY_TYPE_SLH_DSA_SHA2_128S:
        # 8.
        if len(pubkey) != SLH_PUBKEY_SIZE:
            raise ScriptError(ERR_SLH_PUBKEY_SIZE)
        # 9.
        if c > 0:
            if c != SLH_CHUNK_COUNT:
                raise ScriptError(ERR_SLH_SIG_SIZE)
            # chunk_1 to chunk_15 (t[15] to t[1]) are 520 bytes, chunk_16 (t[0]) is 56 bytes.
            if any(len(t[i]) != SLH_CHUNK_SIZE for i in range(1, 16)) or len(t[0]) != SLH_LAST_CHUNK_SIZE:
                raise ScriptError(ERR_SLH_SIG_SIZE)
            ctx.slh_verifications += 1
            if not slh_verify_cached(pubkey[1:], ctx.message(), sig):
                raise ScriptError(ERR_SLH_SIG)
    # Unknown key type: no verification, the signature is treated as valid.
    # 10.
    stack.append(scriptnum_encode(n if c == 0 else n + 1))


# Tapscript (BIP 342).

def is_op_success(op, pq_enabled):
    if op == OP_CHECKSIGPQADD and pq_enabled:
        return False
    return (op == 80 or op == 98 or 126 <= op <= 129 or 131 <= op <= 134 or
            137 <= op <= 138 or 141 <= op <= 142 or 149 <= op <= 153 or 187 <= op <= 254)


def execute_tapscript(script, stack, ctx, pq_enabled):
    """Run a tapscript leaf. Return normally on success, raise ScriptError on failure."""
    # OP_SUCCESSx scan. A decoding failure before an OP_SUCCESSx fails the script.
    ops = []
    for op, data in _iter_ops(script):
        if is_op_success(op, pq_enabled):
            return
        ops.append((op, data))

    if len(stack) > MAX_STACK_SIZE:
        raise ScriptError(ERR_STACK_SIZE)
    if any(len(e) > MAX_SCRIPT_ELEMENT_SIZE for e in stack):
        raise ScriptError(ERR_PUSH_SIZE)

    for pos, (op, data) in enumerate(ops):
        if data is not None:
            if len(data) > MAX_SCRIPT_ELEMENT_SIZE:
                raise ScriptError(ERR_PUSH_SIZE)
            stack.append(data)
        elif op == OP_1NEGATE:
            stack.append(scriptnum_encode(-1))
        elif OP_1 <= op <= OP_16:
            stack.append(scriptnum_encode(op - OP_1 + 1))
        elif op == OP_NOP:
            pass
        elif op == OP_VERIFY:
            _need(stack, 1)
            if not cast_to_bool(stack.pop()):
                raise ScriptError(ERR_VERIFY)
        elif op == OP_DROP:
            _need(stack, 1)
            stack.pop()
        elif op == OP_DUP:
            _need(stack, 1)
            stack.append(stack[-1])
        elif op == OP_PICK:
            _need(stack, 2)
            k = scriptnum_decode(stack.pop())
            if k < 0 or k >= len(stack):
                raise ScriptError(ERR_INVALID_STACK_OPERATION)
            stack.append(stack[-1 - k])
        elif op in (OP_EQUAL, OP_EQUALVERIFY):
            _need(stack, 2)
            eq = stack.pop() == stack.pop()
            if op == OP_EQUALVERIFY:
                if not eq:
                    raise ScriptError(ERR_EQUALVERIFY)
            else:
                stack.append(b"\x01" if eq else b"")
        elif op in (OP_NUMEQUAL, OP_NUMEQUALVERIFY):
            _need(stack, 2)
            b = scriptnum_decode(stack.pop())
            a = scriptnum_decode(stack.pop())
            if op == OP_NUMEQUALVERIFY:
                if a != b:
                    raise ScriptError(ERR_NUMEQUALVERIFY)
            else:
                stack.append(scriptnum_encode(1 if a == b else 0))
        elif op == OP_SHA256:
            _need(stack, 1)
            stack.append(sha256(stack.pop()))
        elif op == OP_CODESEPARATOR:
            ctx.codesep_pos = pos
        elif op == OP_CHECKSIGPQADD:
            # Reached only when pq_enabled, because of the OP_SUCCESSx scan.
            op_checksigpqadd(stack, ctx)
        else:
            raise NotImplementedError("opcode 0x%02x is not implemented" % op)
        if len(stack) > MAX_STACK_SIZE:
            raise ScriptError(ERR_STACK_SIZE)

    # BIP 342: exactly one element must remain, and it must be true.
    if len(stack) != 1:
        raise ScriptError(ERR_CLEANSTACK)
    if not cast_to_bool(stack[0]):
        raise ScriptError(ERR_EVAL_FALSE)


def _iter_ops(script):
    """Decode a script into (opcode, push data or None) pairs, in order.

    Raise BAD_OPCODE at a truncated push.
    """
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        data = None
        if op <= OP_PUSHDATA4:
            if op < OP_PUSHDATA1:
                size = op
            else:
                width = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[op]
                if i + width > len(script):
                    raise ScriptError(ERR_BAD_OPCODE)
                size = int.from_bytes(script[i:i + width], "little")
                i += width
            if i + size > len(script):
                raise ScriptError(ERR_BAD_OPCODE)
            data = script[i:i + size]
            i += size
        yield op, data


def _need(stack, k):
    if len(stack) < k:
        raise ScriptError(ERR_INVALID_STACK_OPERATION)


# secp256k1, only for the BIP 341 commitment check of P2TR script path spends.

SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], SECP_P - 2, SECP_P)) % SECP_P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], SECP_P - 2, SECP_P)) % SECP_P
    x3 = (lam * lam - p1[0] - p2[0]) % SECP_P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % SECP_P)


def point_mul(p, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = point_add(r, p)
        p = point_add(p, p)
    return r


def lift_x(b):
    x = int.from_bytes(b, "big")
    if x >= SECP_P:
        return None
    y_sq = (pow(x, 3, SECP_P) + 7) % SECP_P
    y = pow(y_sq, (SECP_P + 1) // 4, SECP_P)
    if pow(y, 2, SECP_P) != y_sq:
        return None
    return (x, y if y & 1 == 0 else SECP_P - y)


def taproot_tweak(internal_key, merkle_root):
    """Return (output key x-only bytes, parity) as in BIP 341 taproot_tweak_pubkey."""
    t = int.from_bytes(tagged_hash("TapTweak", internal_key + merkle_root), "big")
    p = lift_x(internal_key)
    if p is None or t >= SECP_N:
        return None
    q = point_add(p, point_mul(SECP_G, t))
    if q is None:
        return None
    return q[0].to_bytes(32, "big"), q[1] & 1


# Script path verification for P2TR (BIP 341) and P2MR (BIP 360).

class SpendInfo:
    """Statistics about a verified spend, for the test runner."""

    def __init__(self):
        self.path = None   # "legacy", "unvalidated", "p2tr", "p2mr", "p2mr-depth0", "unknown-leaf"
        self.ctx = None


def _merkle_root(leaf_hash, path):
    k = leaf_hash
    for j in range(0, len(path), CONTROL_NODE_SIZE):
        k = tapbranch_hash(k, path[j:j + CONTROL_NODE_SIZE])
    return k


def verify_input(tx, spent_outputs, index, flags, info=None):
    """Verify input `index` of `tx` under `flags` (a set of flag names).

    Raise ScriptError on failure. Only the cases that the test vectors use are
    supported: an empty scriptSig and a witness v1 or v2 output.
    """
    info = SpendInfo() if info is None else info
    txin = tx.vin[index]
    spk = spent_outputs[index].script_pubkey
    witness = list(txin.witness)
    if txin.script_sig != b"":
        raise NotImplementedError("non-empty scriptSig")
    is_witness_program = (len(spk) == 34 and spk[1] == 0x20 and
                          (spk[0] == 0x00 or OP_1 <= spk[0] <= OP_16))
    if not is_witness_program:
        raise NotImplementedError("scriptPubKey is not a 32-byte witness program")
    version = 0 if spk[0] == 0 else spk[0] - OP_1 + 1
    program = spk[2:]

    if "WITNESS" not in flags:
        # The scriptPubKey runs as a legacy script: it pushes the version and the program.
        info.path = "legacy"
        if not cast_to_bool(program):
            raise ScriptError(ERR_EVAL_FALSE)
        return info

    if version == 1 and "TAPROOT" in flags:
        return _verify_p2tr(tx, spent_outputs, index, flags, witness, program, info)
    if version == 2 and "P2MR" in flags:
        return _verify_p2mr(tx, spent_outputs, index, flags, witness, program, info)
    if version in (1, 2):
        # Witness v1 and v2 outputs without the matching flag are not validated.
        info.path = "unvalidated"
        return info
    raise NotImplementedError("witness version %d" % version)


def _pop_annex(witness):
    if len(witness) >= 2 and len(witness[-1]) > 0 and witness[-1][0] == ANNEX_TAG:
        return witness[:-1], witness[-1]
    return witness, None


def _verify_p2tr(tx, spent_outputs, index, flags, witness, program, info):
    full = list(witness)
    if len(witness) == 0:
        raise ScriptError(ERR_WITNESS_PROGRAM_WITNESS_EMPTY)
    stack, annex = _pop_annex(witness)
    if len(stack) == 1:
        raise NotImplementedError("P2TR key path spend")
    control = stack[-1]
    script = stack[-2]
    stack = stack[:-2]
    m, rem = divmod(len(control) - 33, CONTROL_NODE_SIZE)
    if len(control) < 33 or rem != 0 or m > CONTROL_MAX_NODE_COUNT:
        raise ScriptError(ERR_WRONG_CONTROL_SIZE)
    leaf_version = control[0] & TAPROOT_LEAF_MASK
    leaf_hash = tapleaf_hash(script, leaf_version)
    tweaked = taproot_tweak(control[1:33], _merkle_root(leaf_hash, control[33:]))
    if tweaked is None or tweaked != (program, control[0] & 1):
        raise ScriptError(ERR_WITNESS_PROGRAM_MISMATCH)
    info.path = "p2tr"
    if leaf_version != LEAF_VERSION_TAPSCRIPT:
        info.path = "unknown-leaf"
        return info
    budget = len(ser_witness_stack(full)) + VALIDATION_WEIGHT_OFFSET
    info.ctx = ExecContext(tx, spent_outputs, index, annex, leaf_hash, budget)
    # In P2TR, opcode 202 always stays OP_SUCCESS202.
    execute_tapscript(script, stack, info.ctx, pq_enabled=False)
    return info


def _verify_p2mr(tx, spent_outputs, index, flags, witness, program, info):
    """BIP 360 "Script Validation", version 0.12.x."""
    full = list(witness)
    if len(witness) < 2:
        raise ScriptError(ERR_WITNESS_PROGRAM_WITNESS_EMPTY)
    stack, annex = _pop_annex(witness)
    if len(stack) < 2:
        # Exactly two elements, and the last one starts with 0x50.
        raise ScriptError(ERR_WITNESS_PROGRAM_WITNESS_EMPTY)
    control = stack[-1]
    script = stack[-2]
    stack = stack[:-2]
    m, rem = divmod(len(control) - 1, CONTROL_NODE_SIZE)
    if len(control) < 1 or rem != 0 or m > CONTROL_MAX_NODE_COUNT:
        raise ScriptError(ERR_WRONG_CONTROL_SIZE)
    if control[0] & 1 != 1:
        raise ScriptError(ERR_WITNESS_PROGRAM_MISMATCH)
    leaf_version = control[0] & TAPROOT_LEAF_MASK
    leaf_hash = tapleaf_hash(script, leaf_version)
    if _merkle_root(leaf_hash, control[1:]) != program:
        raise ScriptError(ERR_WITNESS_PROGRAM_MISMATCH)
    if m == 0:
        # BIP 360 v0.12.0: a depth-zero tree is anyone-can-spend.
        info.path = "p2mr-depth0"
        return info
    info.path = "p2mr"
    if leaf_version != LEAF_VERSION_TAPSCRIPT:
        info.path = "unknown-leaf"
        return info
    budget = len(ser_witness_stack(full)) + VALIDATION_WEIGHT_OFFSET
    info.ctx = ExecContext(tx, spent_outputs, index, annex, leaf_hash, budget)
    execute_tapscript(script, stack, info.ctx, pq_enabled="PQSIG" in flags)
    return info

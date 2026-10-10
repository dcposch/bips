#!/usr/bin/env python3
"""Check vectors.json against reference.py.

This follows the rules of Bitcoin Core's script_assets_test:
* A success witness must be valid under every flag combination that is a
  subset of the test flags (every combination if "final" is true).
* A failure witness must be invalid under every flag combination that is a
  superset of the test flags.

In addition, a failure witness must fail with the error code given in the
comment ("[failure: <ERROR>]") under each of those flag combinations.

The flag combinations use the dependencies of script_assets_test
(WITNESS requires P2SH, TAPROOT requires WITNESS). P2MR and PQSIG can be
set or unset freely, which tests more combinations than any deployment
needs.

Usage: python3 run_vectors.py [-v] [vectors.json]
"""

import itertools
import json
import os
import re
import sys
from collections import Counter

import reference as ref


def all_flag_combinations():
    out = []
    for bits in itertools.product([False, True], repeat=len(ref.CONSENSUS_FLAGS)):
        flags = {f for f, on in zip(ref.CONSENSUS_FLAGS, bits) if on}
        if "WITNESS" in flags and "P2SH" not in flags:
            continue
        if "TAPROOT" in flags and "WITNESS" not in flags:
            continue
        out.append(frozenset(flags))
    return out


ALL_COMBINATIONS = all_flag_combinations()

# Errors from the P2MR rules (BIP 360), not from this BIP.
P2MR_ERRORS = {ref.ERR_WITNESS_PROGRAM_MISMATCH, ref.ERR_WRONG_CONTROL_SIZE,
               ref.ERR_WITNESS_PROGRAM_WITNESS_EMPTY}


def build_tx(v, which):
    tx = ref.Tx.deserialize_without_witness(bytes.fromhex(v["tx"]))
    prevouts = [ref.TxOut.deserialize(ref.Reader(bytes.fromhex(p))) for p in v["prevouts"]]
    assert len(prevouts) == len(tx.vin)
    idx = v["index"]
    tx.vin[idx].script_sig = bytes.fromhex(v[which]["scriptSig"])
    tx.vin[idx].witness = [bytes.fromhex(e) for e in v[which]["witness"]]
    return tx, prevouts, idx


def run(tx, prevouts, idx, flags):
    """Return (error code or None, SpendInfo)."""
    info = ref.SpendInfo()
    try:
        ref.verify_input(tx, prevouts, idx, flags, info)
        return None, info
    except ref.ScriptError as e:
        return e.code, info


def check_vector(v):
    """Return a list of problems (empty if the vector is correct) and a summary of the run."""
    problems = []
    notes = []
    test_flags = frozenset(v["flags"].split(","))
    assert test_flags <= set(ref.CONSENSUS_FLAGS), v["flags"]
    final = v.get("final", False)
    m = re.search(r"\[failure: (\w+)\]$", v["comment"])
    expected = m.group(1) if m else None
    if ("failure" in v) != (expected is not None):
        problems.append("failure witness and [failure: ...] tag do not match")

    if "success" in v:
        tx, prevouts, idx = build_tx(v, "success")
        for flags in ALL_COMBINATIONS:
            if final or flags <= test_flags:
                err, info = run(tx, prevouts, idx, flags)
                if err is not None:
                    problems.append("success witness fails with %s under %s" % (err, ",".join(sorted(flags))))
                    break
                if flags == test_flags:
                    notes.append("success path=%s" % info.path)
                    if info.ctx is not None:
                        notes.append("slh_checks=%d slh_verifications=%d budget_left=%d" % (
                            info.ctx.slh_checks, info.ctx.slh_verifications, info.ctx.budget))

    if "failure" in v:
        tx, prevouts, idx = build_tx(v, "failure")
        for flags in ALL_COMBINATIONS:
            if flags >= test_flags:
                err, info = run(tx, prevouts, idx, flags)
                if err is None:
                    problems.append("failure witness passes under %s" % ",".join(sorted(flags)))
                    break
                if err != expected:
                    problems.append("failure witness fails with %s, expected %s, under %s" % (
                        err, expected, ",".join(sorted(flags))))
                    break
        # Soft fork check: a failure caused by this BIP must not be a failure
        # before activation (PQSIG unset), because opcode 202 is then OP_SUCCESS202.
        if "PQSIG" in test_flags and expected not in P2MR_ERRORS:
            flags = test_flags - {"PQSIG"}
            err, _ = run(tx, prevouts, idx, flags)
            if err is not None:
                problems.append("failure witness also fails without PQSIG (%s)" % err)
    return problems, notes


def main():
    args = [a for a in sys.argv[1:] if a != "-v"]
    verbose = "-v" in sys.argv
    path = args[0] if args else os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
    with open(path) as f:
        vectors = json.load(f)
    print("%d vectors, %d flag combinations" % (len(vectors), len(ALL_COMBINATIONS)))
    failed = 0
    groups = Counter()
    kinds = Counter()
    errors = Counter()
    for v in vectors:
        problems, notes = check_vector(v)
        group = "/".join(v["comment"].split()[0].split("/")[:2])
        groups[group] += 1
        if "success" in v:
            kinds["success"] += 1
        if "failure" in v:
            kinds["failure"] += 1
            errors[re.search(r"\[failure: (\w+)\]$", v["comment"]).group(1)] += 1
        status = "FAIL" if problems else "ok"
        if problems or verbose:
            print("%-4s %s %s" % (status, v["comment"], " ".join(notes)))
            for p in problems:
                print("     " + p)
        failed += bool(problems)
    print()
    print("Vectors by group:")
    for g, n in sorted(groups.items()):
        print("  %-22s %d" % (g, n))
    print("Witnesses: %d success, %d failure" % (kinds["success"], kinds["failure"]))
    print("Failure witnesses by expected error:")
    for e, n in sorted(errors.items()):
        print("  %-30s %d" % (e, n))
    print()
    print("%d of %d vectors passed" % (len(vectors) - failed, len(vectors)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

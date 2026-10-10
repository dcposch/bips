#!/usr/bin/env python3
"""Test slhdsa.py against the NIST ACVP vectors for SLH-DSA-SHA2-128s.

The vector files are large, so they are not stored in this directory. They are
downloaded from a pinned commit of https://github.com/usnistgov/ACVP-Server
into a cache directory. The cache directory is the first command line
argument, or the ACVP_CACHE environment variable, or <tmpdir>/acvp-cache.

Groups that use the pre-hash interface (HashSLH-DSA) are skipped, because
this BIP only uses the pure interface.

Usage: python3 test_slhdsa_acvp.py [cache_dir]
"""

import json
import os
import sys
import tempfile
import urllib.request
from concurrent.futures import ProcessPoolExecutor

import slhdsa

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{}/gen-val/json-files/{}/{}"
PARAMETER_SET = "SLH-DSA-SHA2-128s"
DIRS = ["SLH-DSA-keyGen-FIPS205", "SLH-DSA-sigGen-FIPS205", "SLH-DSA-sigVer-FIPS205"]


def load(cache, name):
    """Return internalProjection.json, which holds the prompts and the results."""
    path = os.path.join(cache, name, "internalProjection.json")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        url = URL.format(ACVP_COMMIT, name, "internalProjection.json")
        print("downloading", url)
        urllib.request.urlretrieve(url, path)
    with open(path) as f:
        return json.load(f)


def b(x):
    return bytes.fromhex(x)


def run_keygen(t):
    sk, pk = slhdsa.slh_keygen_internal(b(t["skSeed"]), b(t["skPrf"]), b(t["pkSeed"]))
    return sk == b(t["sk"]) and pk == b(t["pk"])


def run_siggen(args):
    g, t = args
    addrnd = None if g["deterministic"] else b(t["additionalRandomness"])
    if g["signatureInterface"] == "internal":
        sig = slhdsa.slh_sign_internal(b(t["message"]), b(t["sk"]), addrnd)
    else:
        sig = slhdsa.slh_sign(b(t["message"]), b(t["context"]), b(t["sk"]),
                              addrnd=addrnd, deterministic=g["deterministic"])
    return sig == b(t["signature"])


def run_sigver(args):
    g, t = args
    if g["signatureInterface"] == "internal":
        ok = slhdsa.slh_verify_internal(b(t["message"]), b(t["signature"]), b(t["pk"]))
    else:
        ok = slhdsa.slh_verify(b(t["message"]), b(t["signature"]), b(t["context"]), b(t["pk"]))
    return ok == t["testPassed"]


def groups(data):
    for g in data["testGroups"]:
        if g["parameterSet"] != PARAMETER_SET:
            continue
        if g.get("preHash") == "preHash":
            yield g, False
        else:
            yield g, True


def main():
    cache = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        "ACVP_CACHE", os.path.join(tempfile.gettempdir(), "acvp-cache"))
    print("ACVP-Server commit", ACVP_COMMIT)
    runners = {"keyGen": run_keygen, "sigGen": run_siggen, "sigVer": run_sigver}
    total_fail = 0
    with ProcessPoolExecutor() as pool:
        for name in DIRS:
            kind = name.split("-")[2]
            data = load(cache, name)
            passed = failed = skipped = 0
            for g, supported in groups(data):
                if not supported:
                    skipped += len(g["tests"])
                    continue
                label = "{}/{}".format(g.get("signatureInterface", "-"), g.get("preHash", "-"))
                if kind == "sigGen":
                    label += "/" + ("deterministic" if g["deterministic"] else "randomized")
                if kind == "keyGen":
                    jobs = g["tests"]
                else:
                    jobs = [(g, t) for t in g["tests"]]
                results = list(pool.map(runners[kind], jobs))
                for t, ok in zip(g["tests"], results):
                    if not ok:
                        print("  FAIL tcId", t["tcId"], t.get("reason", ""))
                p = sum(results)
                passed += p
                failed += len(results) - p
                print("  {} tgId {} {}: {}/{} passed".format(kind, g["tgId"], label, p, len(results)))
            print("{}: {} passed, {} failed, {} skipped (pre-hash)".format(kind, passed, failed, skipped))
            total_fail += failed
    print("ALL PASSED" if total_fail == 0 else "{} FAILURES".format(total_fail))
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())

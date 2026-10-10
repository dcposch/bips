"""Reference implementation of SLH-DSA-SHA2-128s (FIPS 205).

This module follows the pseudocode of FIPS 205 closely. Function names and
algorithm numbers match the standard. It is written for clarity, not speed,
and it is not constant time. Do not use it to protect real secrets.

Only the parameter set SLH-DSA-SHA2-128s is implemented. Only the pure
(non-prehash) external interface is provided, together with the internal
functions that it uses.

    https://csrc.nist.gov/pubs/fips/205/final
"""

import hashlib
import hmac
import os

# Table 2: parameter set SLH-DSA-SHA2-128s.
N = 16          # security parameter, bytes
H = 63          # total hypertree height
D = 7           # hypertree layers
HP = 9          # height of each XMSS tree (h')
A = 12          # FORS tree height
K = 14          # number of FORS trees
LG_W = 4
W = 1 << LG_W   # Winternitz parameter
M = 30          # length of H_msg output, bytes

# Section 5: WOTS+ lengths.
LEN1 = (8 * N + LG_W - 1) // LG_W                    # 32
LEN2 = 3                                             # floor(log2(LEN1 * (W - 1)) / LG_W) + 1
LEN = LEN1 + LEN2                                    # 35

PK_BYTES = 2 * N
SK_BYTES = 4 * N
SIG_BYTES = (1 + K * (1 + A) + H + D * LEN) * N      # 7856

assert LEN2 == 3 and LEN == 35 and SIG_BYTES == 7856


# Section 4.2: address types.
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6


def to_int(x):
    """Algorithm 1: toInt (big-endian)."""
    return int.from_bytes(x, "big")


def to_byte(x, n):
    """Algorithm 2: toByte (big-endian)."""
    return (x % (1 << (8 * n))).to_bytes(n, "big")


def base_2b(x, b, out_len):
    """Algorithm 4: base_2b. Split x into out_len integers of b bits each."""
    i = 0
    bits = 0
    total = 0
    out = []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + x[i]
            i += 1
            bits += 8
        bits -= b
        out.append((total >> bits) % (1 << b))
    return out


class ADRS:
    """Section 4.2: the 32-byte hash address.

    Layout: layer (4) | tree (12) | type (4) | word1 (4) | word2 (4) | word3 (4).
    word1 is the key pair address. word2 is the chain address or tree height.
    word3 is the hash address or tree index.
    """

    def __init__(self, data=None):
        self.a = bytearray(32) if data is None else bytearray(data)

    def copy(self):
        return ADRS(self.a)

    def _set(self, offset, size, value):
        self.a[offset:offset + size] = to_byte(value, size)

    def _get(self, offset, size):
        return to_int(self.a[offset:offset + size])

    def set_layer_address(self, l):
        self._set(0, 4, l)

    def set_tree_address(self, t):
        self._set(4, 12, t)

    def set_type_and_clear(self, y):
        self._set(16, 4, y)
        self.a[20:32] = bytes(12)

    def set_key_pair_address(self, i):
        self._set(20, 4, i)

    def get_key_pair_address(self):
        return self._get(20, 4)

    def set_chain_address(self, i):
        self._set(24, 4, i)

    def set_tree_height(self, z):
        self._set(24, 4, z)

    def set_hash_address(self, i):
        self._set(28, 4, i)

    def set_tree_index(self, i):
        self._set(28, 4, i)

    def get_tree_index(self):
        return self._get(28, 4)

    def compressed(self):
        """Section 11.2: the 22-byte compressed address ADRSc."""
        a = self.a
        return bytes(a[3:4] + a[8:16] + a[19:20] + a[20:32])


# Section 11.2.1: hash functions for SHA2 at security category 1.
# F, H and T_l are all SHA-256 over PK.seed || toByte(0, 64-n) || ADRSc || M.
# The first block only depends on PK.seed, so its hash state is cached.

_seeded_state_cache = {}


def _seeded_sha256(pk_seed):
    state = _seeded_state_cache.get(pk_seed)
    if state is None:
        state = hashlib.sha256(pk_seed + bytes(64 - N))
        if len(_seeded_state_cache) > 64:
            _seeded_state_cache.clear()
        _seeded_state_cache[pk_seed] = state
    return state.copy()


def _tweakable_hash(pk_seed, adrs, m):
    h = _seeded_sha256(pk_seed)
    h.update(adrs.compressed())
    h.update(m)
    return h.digest()[:N]


def F(pk_seed, adrs, m1):
    return _tweakable_hash(pk_seed, adrs, m1)


def Hf(pk_seed, adrs, m2):
    # Named Hf to avoid a clash with the parameter H.
    return _tweakable_hash(pk_seed, adrs, m2)


def T_l(pk_seed, adrs, m):
    return _tweakable_hash(pk_seed, adrs, m)


def PRF(pk_seed, sk_seed, adrs):
    return _tweakable_hash(pk_seed, adrs, sk_seed)


def PRF_msg(sk_prf, opt_rand, m):
    return hmac.new(sk_prf, opt_rand + m, hashlib.sha256).digest()[:N]


def mgf1_sha256(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def H_msg(r, pk_seed, pk_root, m):
    inner = hashlib.sha256(r + pk_seed + pk_root + m).digest()
    return mgf1_sha256(r + pk_seed + inner, M)


# Section 5: WOTS+.

def chain(x, i, s, pk_seed, adrs):
    """Algorithm 5: chain."""
    tmp = x
    for j in range(i, i + s):
        adrs.set_hash_address(j)
        tmp = F(pk_seed, adrs, tmp)
    return tmp


def _wots_digits(m):
    """Message digits plus checksum digits (shared by Algorithms 7 and 8)."""
    msg = base_2b(m, LG_W, LEN1)
    csum = sum(W - 1 - v for v in msg)
    csum <<= (8 - ((LEN2 * LG_W) % 8)) % 8
    msg += base_2b(to_byte(csum, (LEN2 * LG_W + 7) // 8), LG_W, LEN2)
    return msg


def _wots_sk_adrs(adrs):
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    return sk_adrs


def _wots_pk_adrs(adrs):
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(WOTS_PK)
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    return pk_adrs


def wots_pkgen(sk_seed, pk_seed, adrs):
    """Algorithm 6: wots_pkGen."""
    sk_adrs = _wots_sk_adrs(adrs)
    tmp = []
    for i in range(LEN):
        sk_adrs.set_chain_address(i)
        sk = PRF(pk_seed, sk_seed, sk_adrs)
        adrs.set_chain_address(i)
        tmp.append(chain(sk, 0, W - 1, pk_seed, adrs))
    return T_l(pk_seed, _wots_pk_adrs(adrs), b"".join(tmp))


def wots_sign(m, sk_seed, pk_seed, adrs):
    """Algorithm 7: wots_sign."""
    msg = _wots_digits(m)
    sk_adrs = _wots_sk_adrs(adrs)
    sig = []
    for i in range(LEN):
        sk_adrs.set_chain_address(i)
        sk = PRF(pk_seed, sk_seed, sk_adrs)
        adrs.set_chain_address(i)
        sig.append(chain(sk, 0, msg[i], pk_seed, adrs))
    return b"".join(sig)


def wots_pk_from_sig(sig, m, pk_seed, adrs):
    """Algorithm 8: wots_pkFromSig."""
    msg = _wots_digits(m)
    tmp = []
    for i in range(LEN):
        adrs.set_chain_address(i)
        tmp.append(chain(sig[i * N:(i + 1) * N], msg[i], W - 1 - msg[i], pk_seed, adrs))
    return T_l(pk_seed, _wots_pk_adrs(adrs), b"".join(tmp))


# Section 6: XMSS.

def xmss_node(sk_seed, i, z, pk_seed, adrs):
    """Algorithm 9: xmss_node."""
    if z == 0:
        adrs.set_type_and_clear(WOTS_HASH)
        adrs.set_key_pair_address(i)
        return wots_pkgen(sk_seed, pk_seed, adrs)
    lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
    rnode = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return Hf(pk_seed, adrs, lnode + rnode)


def xmss_sign(m, sk_seed, idx, pk_seed, adrs):
    """Algorithm 10: xmss_sign."""
    auth = []
    for j in range(HP):
        k = (idx >> j) ^ 1
        auth.append(xmss_node(sk_seed, k, j, pk_seed, adrs))
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = wots_sign(m, sk_seed, pk_seed, adrs)
    return sig + b"".join(auth)


def xmss_pk_from_sig(idx, sig_xmss, m, pk_seed, adrs):
    """Algorithm 11: xmss_pkFromSig."""
    adrs.set_type_and_clear(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = sig_xmss[:LEN * N]
    auth = sig_xmss[LEN * N:]
    node = wots_pk_from_sig(sig, m, pk_seed, adrs)
    adrs.set_type_and_clear(TREE)
    adrs.set_tree_index(idx)
    for k in range(HP):
        adrs.set_tree_height(k + 1)
        auth_k = auth[k * N:(k + 1) * N]
        if (idx >> k) % 2 == 0:
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            node = Hf(pk_seed, adrs, node + auth_k)
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node = Hf(pk_seed, adrs, auth_k + node)
    return node


# Section 7: the hypertree.

XMSS_SIG_BYTES = (HP + LEN) * N


def ht_sign(m, sk_seed, pk_seed, idx_tree, idx_leaf):
    """Algorithm 12: ht_sign."""
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    sig_tmp = xmss_sign(m, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, m, pk_seed, adrs)
    for j in range(1, D):
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht += sig_tmp
        if j < D - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, pk_seed, adrs)
    return sig_ht


def ht_verify(m, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root):
    """Algorithm 13: ht_verify."""
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    sig_tmp = sig_ht[:XMSS_SIG_BYTES]
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, m, pk_seed, adrs)
    for j in range(1, D):
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)
        sig_tmp = sig_ht[j * XMSS_SIG_BYTES:(j + 1) * XMSS_SIG_BYTES]
        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, pk_seed, adrs)
    return node == pk_root


# Section 8: FORS.

FORS_SIG_BYTES = K * (1 + A) * N


def fors_skgen(sk_seed, pk_seed, adrs, idx):
    """Algorithm 14: fors_skGen."""
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(FORS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    sk_adrs.set_tree_index(idx)
    return PRF(pk_seed, sk_seed, sk_adrs)


def fors_node(sk_seed, i, z, pk_seed, adrs):
    """Algorithm 15: fors_node."""
    if z == 0:
        sk = fors_skgen(sk_seed, pk_seed, adrs, i)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i)
        return F(pk_seed, adrs, sk)
    lnode = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
    rnode = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
    adrs.set_tree_height(z)
    adrs.set_tree_index(i)
    return Hf(pk_seed, adrs, lnode + rnode)


def fors_sign(md, sk_seed, pk_seed, adrs):
    """Algorithm 16: fors_sign."""
    indices = base_2b(md, A, K)
    sig = b""
    for i in range(K):
        sig += fors_skgen(sk_seed, pk_seed, adrs, (i << A) + indices[i])
        for j in range(A):
            s = (indices[i] >> j) ^ 1
            sig += fors_node(sk_seed, (i << (A - j)) + s, j, pk_seed, adrs)
    return sig


def fors_pk_from_sig(sig_fors, md, pk_seed, adrs):
    """Algorithm 17: fors_pkFromSig."""
    indices = base_2b(md, A, K)
    roots = []
    for i in range(K):
        part = sig_fors[i * (A + 1) * N:(i + 1) * (A + 1) * N]
        sk = part[:N]
        auth = part[N:]
        adrs.set_tree_height(0)
        adrs.set_tree_index((i << A) + indices[i])
        node = F(pk_seed, adrs, sk)
        for j in range(A):
            adrs.set_tree_height(j + 1)
            auth_j = auth[j * N:(j + 1) * N]
            if (indices[i] >> j) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node = Hf(pk_seed, adrs, node + auth_j)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = Hf(pk_seed, adrs, auth_j + node)
        roots.append(node)
    pk_adrs = adrs.copy()
    pk_adrs.set_type_and_clear(FORS_ROOTS)
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    return T_l(pk_seed, pk_adrs, b"".join(roots))


# Section 9: SLH-DSA internal functions.

MD_BYTES = (K * A + 7) // 8                  # 21
TREE_BYTES = (H - H // D + 7) // 8           # 7
LEAF_BYTES = (H // D + 7) // 8               # 2


def _split_digest(digest):
    md = digest[:MD_BYTES]
    tmp_idx_tree = digest[MD_BYTES:MD_BYTES + TREE_BYTES]
    tmp_idx_leaf = digest[MD_BYTES + TREE_BYTES:MD_BYTES + TREE_BYTES + LEAF_BYTES]
    idx_tree = to_int(tmp_idx_tree) % (1 << (H - H // D))
    idx_leaf = to_int(tmp_idx_leaf) % (1 << (H // D))
    return md, idx_tree, idx_leaf


def slh_keygen_internal(sk_seed, sk_prf, pk_seed):
    """Algorithm 18: slh_keygen_internal. Returns (sk, pk)."""
    assert len(sk_seed) == len(sk_prf) == len(pk_seed) == N
    adrs = ADRS()
    adrs.set_layer_address(D - 1)
    pk_root = xmss_node(sk_seed, 0, HP, pk_seed, adrs)
    return sk_seed + sk_prf + pk_seed + pk_root, pk_seed + pk_root


def slh_sign_internal(m, sk, addrnd):
    """Algorithm 19: slh_sign_internal. addrnd=None gives the deterministic variant."""
    assert len(sk) == SK_BYTES
    sk_seed, sk_prf, pk_seed, pk_root = (sk[i * N:(i + 1) * N] for i in range(4))
    adrs = ADRS()
    opt_rand = pk_seed if addrnd is None else addrnd
    r = PRF_msg(sk_prf, opt_rand, m)
    digest = H_msg(r, pk_seed, pk_root, m)
    md, idx_tree, idx_leaf = _split_digest(digest)
    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs)
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
    sig_ht = ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)
    return r + sig_fors + sig_ht


def slh_verify_internal(m, sig, pk):
    """Algorithm 20: slh_verify_internal."""
    if len(pk) != PK_BYTES or len(sig) != SIG_BYTES:
        return False
    pk_seed, pk_root = pk[:N], pk[N:]
    r = sig[:N]
    sig_fors = sig[N:N + FORS_SIG_BYTES]
    sig_ht = sig[N + FORS_SIG_BYTES:]
    digest = H_msg(r, pk_seed, pk_root, m)
    md, idx_tree, idx_leaf = _split_digest(digest)
    adrs = ADRS()
    adrs.set_tree_address(idx_tree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)
    pk_fors = fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
    return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)


# Section 10.1 and 10.2: the pure external interface.

def slh_keygen(sk_seed=None, sk_prf=None, pk_seed=None):
    """Algorithm 21: slh_keygen. Missing seeds are drawn from os.urandom."""
    sk_seed = os.urandom(N) if sk_seed is None else sk_seed
    sk_prf = os.urandom(N) if sk_prf is None else sk_prf
    pk_seed = os.urandom(N) if pk_seed is None else pk_seed
    return slh_keygen_internal(sk_seed, sk_prf, pk_seed)


def _pure_message(m, ctx):
    return to_byte(0, 1) + to_byte(len(ctx), 1) + ctx + m


def slh_sign(m, ctx, sk, addrnd=None, deterministic=False):
    """Algorithm 22: slh_sign.

    By default a fresh addrnd is drawn from os.urandom (hedged variant).
    With deterministic=True, PK.seed is used instead (deterministic variant).
    """
    if len(ctx) > 255:
        raise ValueError("context string too long")
    if addrnd is None and not deterministic:
        addrnd = os.urandom(N)
    return slh_sign_internal(_pure_message(m, ctx), sk, addrnd)


def slh_verify(m, sig, ctx, pk):
    """Algorithm 24: slh_verify."""
    if len(ctx) > 255:
        return False
    return slh_verify_internal(_pure_message(m, ctx), sig, pk)

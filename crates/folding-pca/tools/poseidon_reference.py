#!/usr/bin/env python3
"""Independent, unoptimised Poseidon (HADES) reference used to cross-check the chain hash.

Written from the Poseidon paper and the IAIK `generate_parameters_grain.sage` reference script
(Grain LFSR round constants, x^5 S-box, plain HADES round structure: no sparse-matrix or
round-constant folding optimisations). Standard library only.

Step 1 (self-validation): with the reference script's own parameter generation (Grain constants and
Grain-drawn Cauchy MDS), reproduce the published IAIK test vectors poseidonperm_x5_255_3 and
poseidonperm_x5_254_3 from fixtures/hadeshash_test_vectors.txt.
Step 2: with the parameter choices of the Nova/neptune Poseidon instance (Cauchy MDS with
x_i = i, y_i = t + i; round numbers from the paper's inequalities with the +2 / x1.075 margin;
sponge tag from the IO pattern), compute H(left, right) for a set of inputs over the Pallas scalar
field and write fixtures/poseidon_crosscheck.json, which the Rust tests compare against.

Usage: python3 poseidon_reference.py selftest | generate
"""
import hashlib, json, math, os, random, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
FX = os.path.join(HERE, "..", "fixtures")

P_BLS12_381_FR = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
P_BN254_FR = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
P_PALLAS_SCALAR = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001


# The Nova/neptune instance seeds the Grain LFSR with the S-box field set to 1 for x^5 (the IAIK script
# uses 0 for x^alpha and 1 for x^-1). Round constants are therefore a different, equally valid draw.
NEPTUNE_SBOX_TAG = 1


class Grain:
    def __init__(self, field_size, t, rf, rp, field=1, sbox=0):
        bits = []
        for width, val in ((2, field), (4, sbox), (12, field_size), (12, t), (10, rf), (10, rp), (30, (1 << 30) - 1)):
            bits += [(val >> i) & 1 for i in range(width - 1, -1, -1)]
        assert len(bits) == 80
        self.s = bits
        for _ in range(160):
            self._step()

    def _step(self):
        s = self.s
        b = s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
        s.pop(0)
        s.append(b)
        return b

    def bit(self):
        b = self._step()
        while b == 0:
            self._step()  # discard the paired bit
            b = self._step()
        return self._step()

    def rand(self, nbits):
        v = 0
        for _ in range(nbits):
            v = (v << 1) | self.bit()
        return v


def grain_constants(g, p, n, count):
    out = []
    for _ in range(count):
        v = g.rand(n)
        while v >= p:
            v = g.rand(n)
        out.append(v)
    return out


def mds_from_grain(g, p, n, t):
    while True:
        r = [g.rand(n) % p for _ in range(2 * t)]
        while len(set(r)) != len(r):
            r = [g.rand(n) % p for _ in range(2 * t)]
        xs, ys = r[:t], r[t:]
        if any((x + y) % p == 0 for x in xs for y in ys):
            continue
        return [[pow(x + y, -1, p) for y in ys] for x in xs]


def mds_sequential(p, t):
    xs = list(range(t))
    ys = list(range(t, 2 * t))
    return [[pow(x + y, -1, p) for y in ys] for x in xs]


def permute(state, p, mds, rcs, rf, rp):
    t = len(state)
    st = list(state)
    r = 0
    for rnd in range(rf + rp):
        st = [(st[i] + rcs[rnd * t + i]) % p for i in range(t)]
        if rnd < rf // 2 or rnd >= rf // 2 + rp:
            st = [pow(x, 5, p) for x in st]
        else:
            st[0] = pow(st[0], 5, p)
        st = [sum(mds[i][j] * st[j] for j in range(t)) % p for i in range(t)]
    return st


def round_numbers(t, n_bits=256, m=128, margin=True):
    """Port of the paper's security inequalities (calc_round_numbers.py), float64."""
    def secure(rf, rp):
        rf_stat = 6.0 if m <= (n_bits - 3) * (t + 1) else 10.0
        rf_interp = 0.43 * m + math.log2(t) - rp
        g1 = 0.21 * n_bits - rp
        g2 = (0.14 * n_bits - 1 - rp) / (t - 1)
        return rf >= max(math.ceil(x) for x in (rf_stat, rf_interp, g1, g2))
    best, rf_b, rp_b = None, 0, 0
    for rf in range(2, 1001, 2):
        for rp in range(4, 200):
            if secure(rf, rp):
                a, b = rf, rp
                if margin:
                    a += 2
                    b = math.ceil(1.075 * b)
                cost = t * a + b
                if best is None or cost < best or (cost == best and a < rf_b):
                    best, rf_b, rp_b = cost, a, b
    return rf_b, rp_b


def selftest_vectors():
    txt = open(os.path.join(FX, "hadeshash_test_vectors.txt")).read()
    blocks = {}
    cur = None
    for line in txt.splitlines():
        if line.startswith("# "):
            cur = line[2:].strip()
            blocks[cur] = {}
        elif line.startswith("Input:"):
            mode = "in"
        elif line.startswith("Output:"):
            mode = "out"
        elif line.startswith("["):
            blocks[cur][mode] = [int(x.strip().strip("'"), 16) for x in line.strip("[]").split(",")]
    results = {}
    for name, p, n, t, rf, rp in (
        ("poseidonperm_x5_255_3", P_BLS12_381_FR, 255, 3, 8, 57),
        ("poseidonperm_x5_254_3", P_BN254_FR, 254, 3, 8, 57),
    ):
        g = Grain(n, t, rf, rp)
        rcs = grain_constants(g, p, n, (rf + rp) * t)
        mds = mds_from_grain(g, p, n, t)
        got = permute(blocks[name]["in"], p, mds, rcs, rf, rp)
        ok = got == blocks[name]["out"]
        results[name] = ok
        print(name, "MATCH" if ok else "MISMATCH")
    return results


def sponge_tag():
    """IO pattern [Absorb(2), Squeeze(1)], domain separator 0 (SpongeAPI tag hashing)."""
    M = (1 << 128) - 1
    base = (-159) & M
    st, xi = 0, 1
    for a in ((1 << 31) + 2, 1, 0):
        xi = (xi * base) & M
        st = (st + xi * a) & M
    return st


def pallas_hash2(left, right, params=None):
    p = P_PALLAS_SCALAR
    t = 3
    rf, rp = round_numbers(t)
    n = p.bit_length()  # 255
    g = Grain(n, t, rf, rp, sbox=NEPTUNE_SBOX_TAG)
    rcs = grain_constants(g, p, n, (rf + rp) * t)
    mds = mds_sequential(p, t)
    out = permute([sponge_tag(), left % p, right % p], p, mds, rcs, rf, rp)
    return out[1], (rf, rp)


def generate():
    rf, rp = round_numbers(3)
    p = P_PALLAS_SCALAR
    n = p.bit_length()
    g = Grain(n, 3, rf, rp, sbox=NEPTUNE_SBOX_TAG)
    rcs = grain_constants(g, p, n, (rf + rp) * 3)
    mds = mds_sequential(p, 3)
    tag = sponge_tag()
    rng = random.Random(0x5043412d504f534549444f4e)  # fixed seed, deterministic
    pairs = [(0, 0), (0, 1), (1, 0), (1, 1), (p - 1, p - 1), (p - 1, 0), (0, p - 1), (1 << 128, 1 << 64)]
    pairs += [(rng.randrange(p), rng.randrange(p)) for _ in range(24)]
    vecs = []
    for l, r in pairs:
        out = permute([tag, l, r], p, mds, rcs, rf, rp)[1]
        vecs.append({"left": hex(l), "right": hex(r), "hash": hex(out)})
    tvpath = os.path.join(FX, "hadeshash_test_vectors.txt")
    doc = {
        "what": "Independent Poseidon (HADES) reference for the chain hash H(left,right)",
        "field_modulus_hex": hex(p),
        "t": 3, "alpha": 5, "full_rounds": rf, "partial_rounds": rp,
        "mds": "Cauchy, x_i = i, y_i = t + i", "round_constants": "Grain LFSR (IAIK reference algorithm), n = 255, S-box field bits = 1 (neptune encoding of x^5)",
        "sponge_tag_hex": hex(tag),
        "reference_self_validation": {
            "source": "https://extgit.iaik.tugraz.at/krypto/hadeshash/-/raw/master/code/test_vectors.txt",
            "retrieved": "2026-10-08",
            "sha256": hashlib.sha256(open(tvpath, "rb").read()).hexdigest(),
            "vectors_reproduced": ["poseidonperm_x5_255_3", "poseidonperm_x5_254_3"],
        },
        "vectors": vecs,
    }
    json.dump(doc, open(os.path.join(FX, "poseidon_crosscheck.json"), "w"), indent=2)
    print("wrote", len(vecs), "vectors; rounds", (rf, rp))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if cmd == "selftest":
        r = selftest_vectors()
        sys.exit(0 if all(r.values()) else 1)
    elif cmd == "generate":
        if not all(selftest_vectors().values()):
            sys.exit("reference does not reproduce the published vectors; refusing to generate")
        generate()

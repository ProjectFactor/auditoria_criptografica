#!/usr/bin/env python3
"""Weak-SEED CTR_DRBG reconstruction (SP 800-90A) against boot-aligned outputs.

Hypothesis under test: the chip's DRBG is instantiated at power-up from a
LOW-ENTROPY seed with a standard construction. If so, a GET CHALLENGE right
after a cold reset == CTR_DRBG_Generate(Instantiate(seed))[:16] for some small,
guessable seed. We sweep seeds across constructions and intersect the computed
first-16-byte outputs with the real boot outputs collected over many resets.

Validation note: the NO-DF path reduces to AES-CTR where Key and V are XORs of
AES-of-zero constants (printed in --selftest), so it is correct from the AES
primitive alone. The DF path is implemented per SP 800-90A (spec-faithful).
"""
import os, sys, time, json, itertools
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MASK = (1 << 128) - 1

def aes(key, blk):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor(); return e.update(blk) + e.finalize()
def aes_many(key, buf):   # buf is k*16 bytes; ECB encrypt all blocks at C speed
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor(); return e.update(buf) + e.finalize()
def incr(Vint): return (Vint + 1) & MASK

def drbg_update(provided, Key, Vint, keylen):
    seedlen = keylen + 16; temp = b""
    while len(temp) < seedlen:
        Vint = incr(Vint); temp += aes(Key, Vint.to_bytes(16, "big"))
    temp = temp[:seedlen]
    temp = bytes(a ^ b for a, b in zip(temp, provided))
    return temp[:keylen], int.from_bytes(temp[keylen:], "big")

def block_cipher_df(inp, nbytes, keylen):
    S = len(inp).to_bytes(4, "big") + nbytes.to_bytes(4, "big") + inp + b"\x80"
    while len(S) % 16: S += b"\x00"
    K = bytes(range(keylen))
    def bcc(key, data):
        chain = b"\x00" * 16
        for i in range(0, len(data), 16):
            chain = aes(key, bytes(a ^ b for a, b in zip(chain, data[i:i+16])))
        return chain
    temp = b""; i = 0
    while len(temp) < keylen + 16:
        temp += bcc(K, i.to_bytes(4, "big") + b"\x00" * 12 + S); i += 1
    K2 = temp[:keylen]; X = temp[keylen:keylen+16]; out = b""
    while len(out) < nbytes:
        X = aes(K2, X); out += X
    return out[:nbytes]

def instantiate_first16(entropy, nonce, perso, keylen, use_df):
    seedlen = keylen + 16
    if use_df:
        sm = block_cipher_df(entropy + nonce + perso, seedlen, keylen)
    else:
        sm = (entropy + b"\x00" * seedlen)[:seedlen]
        if perso:
            p = (perso + b"\x00" * seedlen)[:seedlen]
            sm = bytes(a ^ b for a, b in zip(sm, p))
    Key, Vint = drbg_update(sm, b"\x00" * keylen, 0, keylen)
    return aes(Key, incr(Vint).to_bytes(16, "big"))   # first generate block


def selftest():
    # no-df AES-128, zero seed: update(0) -> Key=C1=AES(0,1), V=C2=AES(0,2); out=AES(C1, C2+1)
    C1 = aes(b"\x00"*16, (1).to_bytes(16,"big")); C2 = aes(b"\x00"*16, (2).to_bytes(16,"big"))
    want = aes(C1, (int.from_bytes(C2,"big")+1).to_bytes(16,"big"))
    got = instantiate_first16(b"\x00"*32, b"", b"", 16, False)
    assert got == want, "no-df reduction mismatch"
    # df determinism + length
    a = block_cipher_df(b"\x01\x02", 32, 16); b = block_cipher_df(b"\x01\x02", 32, 16)
    assert a == b and len(a) == 32
    print("selftest PASS: no-df reduces to AES-CTR(C1,C2) as expected; df deterministic")
    print("  C1=AES(0,1)=", C1.hex(), "\n  C2=AES(0,2)=", C2.hex())
    return 0


def load_targets(path):
    t = set()
    for line in open(path):
        line = line.strip()
        if line: t.add(bytes.fromhex(line)[:16])
    return t


def structured_seeds():
    seeds = []
    # timestamps 2019-01-01 .. 2027-01-01 (unix seconds, LE and BE, 4 and 8 byte)
    for ts in range(1546300800, 1798761600, 3600):   # hourly
        seeds.append(ts.to_bytes(4, "big")); seeds.append(ts.to_bytes(4, "little"))
    # UID / CAN-ish, zeros, counters already covered by int sweep.
    # Card UIDs are private and must be supplied by the caller, never hardcoded
    # (export CEDULA_SEED_UID_HEX=<hex> to add a candidate).
    uids = []
    extra = os.environ.get("CEDULA_SEED_UID_HEX")
    if extra:
        uids.append(bytes.fromhex(extra))
    for u in uids:
        seeds.append(u); seeds.append(u + b"\x00")
    return seeds


def search(targets, budget_per=45.0):
    hits = []; covered = {}
    constructions = [("AES128-nodf", 16, False), ("AES256-nodf", 32, False),
                     ("AES128-df", 16, True), ("AES256-df", 32, True)]
    # ---- fast no-df counter-region sweep (Key constant = C-family) ----
    for name, keylen, use_df in constructions:
        t0 = time.time(); n = 0
        if not use_df:
            # seed in the V-region (low 16 bytes): Key constant, only V varies.
            seedlen = keylen + 16
            Key, V0 = drbg_update(b"\x00"*seedlen, b"\x00"*keylen, 0, keylen)  # zero-seed state
            # with seed s (low 16 bytes), V = V0 ^ s ; out = AES(Key, (V0^s)+1)
            CH = 1 << 20
            while time.time() - t0 < budget_per:
                buf = bytearray(CH * 16)
                for j in range(CH):
                    s = n + j
                    v = (V0 ^ s)
                    buf[j*16:(j+1)*16] = ((v + 1) & MASK).to_bytes(16, "big")
                outs = aes_many(Key, bytes(buf))
                for j in range(CH):
                    o = outs[j*16:(j+1)*16]
                    if o in targets:
                        hits.append((name, "V-seed", n + j, o.hex()))
                n += CH
            covered[name + "/V-region"] = n
            # seed in the KEY region (high bytes): Key varies, V constant.
            t1 = time.time(); m = 0
            while time.time() - t1 < budget_per / 2:
                s = (m).to_bytes(keylen, "big") + b"\x00" * 16   # high-region small int
                Key2, Vi = drbg_update((s + b"\x00"*(keylen+16))[:keylen+16], b"\x00"*keylen, 0, keylen)
                o = aes(Key2, incr(Vi).to_bytes(16, "big"))
                if o in targets: hits.append((name, "K-seed", m, o.hex()))
                m += 1
            covered[name + "/K-region"] = m
        else:
            # df: sweep small-integer entropy of several byte-lengths
            while time.time() - t0 < budget_per:
                for L in (1, 2, 3, 4):
                    s = (n).to_bytes(max(L, (n.bit_length()+7)//8 or 1), "big")
                    o = instantiate_first16(s, b"", b"", keylen, True)
                    if o in targets: hits.append((name, f"df-int{L}", n, o.hex()))
                n += 1
            covered[name + "/df-int"] = n
    # ---- structured seeds across all constructions (df + no-df) ----
    ss = structured_seeds()
    for name, keylen, use_df in constructions:
        for s in ss:
            o = instantiate_first16(s, b"", b"", keylen, use_df)
            if o in targets: hits.append((name, "structured", s.hex(), o.hex()))
    covered["structured_seeds"] = len(ss) * len(constructions)
    return hits, covered


def main():
    if "--selftest" in sys.argv:
        return selftest()
    targets = load_targets(sys.argv[1])
    print(f"{len(targets)} boot-output targets loaded")
    budget = float(sys.argv[3]) if len(sys.argv) > 3 else 45.0
    t0 = time.time()
    hits, covered = search(targets, budget_per=budget)
    res = {"targets": len(targets), "budget_per_construction_s": budget,
           "seeds_covered": covered, "hits": hits, "elapsed_s": round(time.time()-t0, 1)}
    print(json.dumps(res, indent=2))
    if len(sys.argv) > 2:
        json.dump(res, open(sys.argv[2], "w"), indent=2)
    print("\n" + ("!!! HIT — weak seed found" if hits else "no weak seed found in the swept space"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Self-contained RNG test battery (NIST SP 800-22 core, FIPS 140-2, SP 800-90B
min-entropy estimators, classic stats) in numpy. No external test binaries.

Usage: python3 rng_battery.py <rng.bin> [out.json]
p-values use alpha=0.01 (SP 800-22 default). PASS = p >= 0.01.
"""
from __future__ import annotations
import sys, math, json, zlib, time
import numpy as np

ALPHA = 0.01


# ---- special functions ------------------------------------------------------
def erfc(x): return math.erfc(x)


def igamc(a, x):
    """Regularized upper incomplete gamma Q(a,x)."""
    if x <= 0 or a <= 0:
        return 1.0
    gln = math.lgamma(a)
    if x < a + 1.0:                       # series for P, return 1-P
        ap = a; s = 1.0 / a; d = s
        for _ in range(2000):
            ap += 1.0; d *= x / ap; s += d
            if abs(d) < abs(s) * 1e-16:
                break
        return 1.0 - s * math.exp(-x + a * math.log(x) - gln)
    b = x + 1.0 - a; c = 1e300; d = 1.0 / b; h = d   # continued fraction for Q
    for i in range(1, 2000):
        an = -i * (i - a); b += 2.0; d = an * d + b
        if abs(d) < 1e-300: d = 1e-300
        c = b + an / c
        if abs(c) < 1e-300: c = 1e-300
        d = 1.0 / d; dl = d * c; h *= dl
        if abs(dl - 1.0) < 1e-16:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def bits_from_bytes(b: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8))


# ---- NIST SP 800-22 tests ---------------------------------------------------
def t_frequency(bits):
    n = bits.size; s = int(bits.sum()) * 2 - n
    p = erfc(abs(s) / math.sqrt(2 * n))
    return "Frequency (monobit)", p


def t_block_frequency(bits, M=128):
    n = bits.size; N = n // M
    if N == 0: return "Block Frequency", None
    blk = bits[:N * M].reshape(N, M).mean(axis=1)
    chi = 4.0 * M * np.sum((blk - 0.5) ** 2)
    return "Block Frequency", igamc(N / 2.0, chi / 2.0)


def t_runs(bits):
    n = bits.size; pi = bits.mean()
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n): return "Runs", 0.0
    vobs = int(np.sum(bits[1:] != bits[:-1])) + 1
    num = abs(vobs - 2 * n * pi * (1 - pi))
    p = erfc(num / (2 * math.sqrt(2 * n) * pi * (1 - pi)))
    return "Runs", p


def t_longest_run(bits):
    n = bits.size
    if n < 6272: M = 8; K = 3; N = 16; pi = [0.2148,0.3672,0.2305,0.1875]; v0,vk=1,4
    elif n < 750000: M=128; K=5; N=49; pi=[0.1174,0.2430,0.2493,0.1752,0.1027,0.1124]; v0,vk=4,9
    else: M=10000; K=6; N=75; pi=[0.0882,0.2092,0.2483,0.1933,0.1208,0.0675,0.0727]; v0,vk=10,16
    nb = n // M
    if nb == 0: return "Longest Run of Ones", None
    v = np.zeros(K + 1)
    b = bits[:nb * M].reshape(nb, M)
    for row in b:
        # longest run of 1s
        mx = cur = 0
        for x in row:
            if x: cur += 1; mx = cur if cur > mx else mx
            else: cur = 0
        cls = min(max(mx, v0), vk) - v0
        v[cls] += 1
    chi = sum((v[i] - nb * pi[i]) ** 2 / (nb * pi[i]) for i in range(K + 1))
    return "Longest Run of Ones", igamc(K / 2.0, chi / 2.0)


def _gf2_rank(m):
    m = m.copy().astype(np.uint8); rows, cols = m.shape; r = 0
    for c in range(cols):
        piv = None
        for i in range(r, rows):
            if m[i, c]: piv = i; break
        if piv is None: continue
        m[[r, piv]] = m[[piv, r]]
        for i in range(rows):
            if i != r and m[i, c]: m[i] ^= m[r]
        r += 1
        if r == rows: break
    return r


def t_matrix_rank(bits, M=32, Q=32):
    n = bits.size; N = n // (M * Q)
    if N < 38: return "Binary Matrix Rank", None
    fm = ff = fr = 0
    data = bits[:N * M * Q].reshape(N, M, Q)
    for k in range(N):
        r = _gf2_rank(data[k])
        if r == M: fm += 1
        elif r == M - 1: ff += 1
        else: fr += 1
    p_m, p_f = 0.2888, 0.5776; p_r = 1 - p_m - p_f
    chi = (fm - p_m*N)**2/(p_m*N) + (ff - p_f*N)**2/(p_f*N) + (fr - p_r*N)**2/(p_r*N)
    return "Binary Matrix Rank", math.exp(-chi / 2.0)


def t_spectral(bits, cap=2_000_000):
    x = 2 * bits[:cap].astype(np.float64) - 1 if bits.size > cap else 2*bits.astype(np.float64)-1
    n = x.size
    S = np.abs(np.fft.rfft(x))[1:n // 2]
    T = math.sqrt(math.log(1/0.05) * n)
    N0 = 0.95 * n / 2.0; N1 = np.sum(S < T)
    d = (N1 - N0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    return f"Spectral DFT (n={n})", erfc(abs(d) / math.sqrt(2))


def t_approx_entropy(bits, m=10, cap=1_000_000):
    b = bits[:cap] if bits.size > cap else bits
    n = b.size
    def phi(mm):
        if mm == 0: return 0.0
        ext = np.concatenate([b, b[:mm-1]])
        # pack mm-bit windows into integers
        idx = np.zeros(n, dtype=np.int64)
        for j in range(mm):
            idx = (idx << 1) | ext[j:j+n]
        counts = np.bincount(idx, minlength=1 << mm)
        c = counts[counts > 0] / n
        return float(np.sum(c * np.log(c)))
    apen = phi(m) - phi(m + 1)
    chi = 2.0 * n * (math.log(2) - apen)
    return f"Approximate Entropy (m={m})", igamc(2 ** (m - 1), chi / 2.0)


def t_serial(bits, m=16, cap=2_000_000):
    b = bits[:cap] if bits.size > cap else bits
    n = b.size
    def psi2(mm):
        if mm == 0: return 0.0
        ext = np.concatenate([b, b[:mm-1]])
        idx = np.zeros(n, dtype=np.int64)
        for j in range(mm):
            idx = (idx << 1) | ext[j:j+n]
        counts = np.bincount(idx, minlength=1 << mm).astype(np.float64)
        return float(np.sum(counts**2) * (2**mm) / n - n)
    p0, p1, p2 = psi2(m), psi2(m-1), psi2(m-2)
    d1 = p0 - p1; d2 = p0 - 2*p1 + p2
    return f"Serial (m={m})", min(igamc(2**(m-2), d1/2.0), igamc(2**(m-3), d2/2.0))


def t_cusum(bits, cap=2_000_000):
    b = bits[:cap] if bits.size > cap else bits
    x = 2 * b.astype(np.int64) - 1; n = x.size
    def one(mode):
        S = np.cumsum(x if mode == 0 else x[::-1]); z = int(np.max(np.abs(S)))
        if z == 0: return 1.0
        s = 0.0
        k0 = (-n // z + 1) // 4
        for k in range(k0, n // z // 4 + 1):
            s += _Phi((4*k+1)*z/math.sqrt(n)) - _Phi((4*k-1)*z/math.sqrt(n))
        s2 = 0.0
        for k in range((-n//z - 3)//4, n//z//4 + 1):
            s2 += _Phi((4*k+3)*z/math.sqrt(n)) - _Phi((4*k+1)*z/math.sqrt(n))
        return 1.0 - s + s2
    return "Cumulative Sums (fwd)", one(0)


def _Phi(x): return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def t_maurer(bits):
    n = bits.size
    L = 6
    for LL, th in [(6,387840),(7,904960),(8,2068480),(9,4654080),(10,10342400),
                   (11,22753280),(12,49643520),(13,107560960),(14,231669760),(15,496435200),(16,1059061760)]:
        if n >= th: L = LL
    Q = 10 * (2 ** L); K = n // L - Q
    if K <= 0: return "Maurer Universal", None
    expected = {6:5.2177052,7:6.1962507,8:7.1836656,9:8.1764248,10:9.1723243,
                11:10.170032,12:11.168765,13:12.168070,14:13.167693,15:14.167488,16:15.167379}
    var = {6:2.954,7:3.125,8:3.238,9:3.311,10:3.356,11:3.384,12:3.401,13:3.410,14:3.416,15:3.419,16:3.421}
    blocks = bits[:(Q+K)*L].reshape(Q+K, L)
    pw = (1 << np.arange(L)[::-1])
    vals = blocks.dot(pw)
    last = np.zeros(1 << L, dtype=np.int64)
    s = 0.0
    for i, v in enumerate(vals, start=1):
        if i <= Q:
            last[v] = i
        else:
            s += math.log2(i - last[v]); last[v] = i
    fn = s / K
    c = 0.7 - 0.8/L + (4 + 32/L) * (K ** (-3/L)) / 15
    sigma = c * math.sqrt(var[L] / K)
    p = erfc(abs((fn - expected[L]) / (math.sqrt(2) * sigma)))
    return f"Maurer Universal (L={L})", p


# ---- FIPS 140-2 (single 20000-bit block) ------------------------------------
def fips_140_2(bits):
    b = bits[:20000]
    ones = int(b.sum())
    mono = 9725 < ones < 10275
    # poker
    m = b.reshape(5000, 4).dot(1 << np.arange(4)[::-1])
    f = np.bincount(m, minlength=16)
    X = (16/5000) * int(np.sum(f.astype(np.int64)**2)) - 5000
    poker = 2.16 < X < 46.17
    # runs + longruns
    change = np.flatnonzero(b[1:] != b[:-1])
    starts = np.concatenate([[0], change + 1]); ends = np.concatenate([change + 1, [20000]])
    lengths = ends - starts; vals = b[starts]
    ok_runs = True; longrun = True
    want = {1:(2315,3085),2:(1114,1386),3:(527,723),4:(240,384),5:(103,209),6:(103,209)}
    for bit in (0,1):
        L = lengths[vals == bit]
        for k,(lo,hi) in want.items():
            cnt = int(np.sum(L == k)) if k < 6 else int(np.sum(L >= 6))
            if not (lo <= cnt <= hi): ok_runs = False
        if L.size and int(L.max()) >= 26: longrun = False
    return {"monobit": mono, "poker": poker, "runs": ok_runs, "long_run(<26)": longrun,
            "ones_in_20000": ones}


# ---- SP 800-90B min-entropy (IID-track estimators) --------------------------
def sp90b(data: bytes, bits):
    n = len(data); out = {}
    # byte MCV
    cnt = np.bincount(np.frombuffer(data, np.uint8), minlength=256)
    pmax = cnt.max() / n
    ub = min(1.0, pmax + 2.576 * math.sqrt(pmax * (1 - pmax) / n))
    out["byte_MCV_minent_per_byte"] = -math.log2(ub)
    # bit-level estimators
    bb = bits; L = bb.size
    p1 = bb.mean(); pm = max(p1, 1 - p1)
    ubb = min(1.0, pm + 2.576 * math.sqrt(pm * (1 - pm) / L))
    out["bit_MCV_minent_per_bit"] = -math.log2(ubb)
    # collision estimate (bit)  -- mean time between collisions
    # Markov estimate (bit, 1st order)
    t00 = int(np.sum((bb[:-1]==0)&(bb[1:]==0))); t01=int(np.sum((bb[:-1]==0)&(bb[1:]==1)))
    t10 = int(np.sum((bb[:-1]==1)&(bb[1:]==0))); t11=int(np.sum((bb[:-1]==1)&(bb[1:]==1)))
    p0 = (t00+t01); p1c=(t10+t11)
    P00=t00/p0 if p0 else 0; P01=t01/p0 if p0 else 0
    P10=t10/p1c if p1c else 0; P11=t11/p1c if p1c else 0
    # highest-prob 128-step path (per SP800-90B Markov), min-entropy per bit
    import itertools
    best = 0.0
    for first in (0,1):
        logp = math.log2(max(1-p1,1e-12) if first==0 else max(p1,1e-12))
        # greedy max transition each step (128 steps) -> upper bound on prob
        cur = first
        for _ in range(127):
            if cur==0:
                step = max(P00,P01); nxt = 0 if P00>=P01 else 1
            else:
                step = max(P10,P11); nxt = 0 if P10>=P11 else 1
            logp += math.log2(max(step,1e-12)); cur = nxt
        best = min(best, logp) if best else logp
    out["bit_Markov_minent_per_128bit"] = -best
    out["bit_Markov_minent_per_bit"] = -best/128.0
    # compression ratio sanity
    out["zlib_ratio"] = len(zlib.compress(data,9))/n
    return out


# ---- classic ----------------------------------------------------------------
def classic(data, bits):
    n=len(data); cnt=np.bincount(np.frombuffer(data,np.uint8),minlength=256)
    p=cnt[cnt>0]/n; H=float(-np.sum(p*np.log2(p)))
    exp=n/256; chi=float(np.sum((cnt-exp)**2/exp)); z=(chi-255)/math.sqrt(510)
    arr=np.frombuffer(data,np.uint8).astype(np.float64); mean=arr.mean()
    scc=float(np.sum((arr[:-1]-mean)*(arr[1:]-mean))/np.sum((arr-mean)**2))
    return {"shannon_bits_per_byte":H,"chi2":chi,"chi2_z":z,
            "serial_corr_lag1":scc,"n_bytes":n}


def per_sequence(bits, M=1_000_000):
    """NIST STS-style: split into N sequences of M bits; for each quick test report
    proportion passing (p>=0.01) and uniformity of p-values (chi^2 over 10 bins)."""
    N = bits.size // M
    if N < 20:
        return {"note": f"only {N} sequences of {M} bits; skipped"}
    seqs = bits[:N * M].reshape(N, M)
    tests = [t_frequency, t_block_frequency, t_runs, t_longest_run,
             t_spectral, t_approx_entropy, t_serial, t_cusum]
    lo = 0.99 - 3 * math.sqrt(0.99 * 0.01 / N)
    out = {"sequences": N, "bits_per_seq": M, "proportion_floor": round(lo, 4), "results": []}
    for fn in tests:
        ps = []
        for k in range(N):
            try:
                _, p = fn(seqs[k])
                if p is not None: ps.append(p)
            except Exception:
                pass
        if not ps:
            continue
        name = fn(seqs[0])[0]
        npass = sum(1 for p in ps if p >= ALPHA); prop = npass / len(ps)
        bins = [0] * 10
        for p in ps: bins[min(int(p * 10), 9)] += 1
        exp = len(ps) / 10.0
        chi = sum((b - exp) ** 2 / exp for b in bins)
        unif = igamc(4.5, chi / 2.0)
        out["results"].append({
            "test": name, "proportion_pass": round(prop, 4),
            "prop_ok": prop >= lo, "uniformity_p": round(unif, 5),
            "unif_ok": unif >= 1e-4})
    return out


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    bits = bits_from_bytes(data)
    print(f"loaded {len(data)} bytes ({bits.size} bits) from {path}\n")
    res = {"file": path, "n_bytes": len(data)}
    res["classic"] = classic(data, bits)
    print("CLASSIC:", json.dumps(res["classic"]))
    t0 = time.time()
    sp800_22 = []
    for fn in (t_frequency, t_block_frequency, t_runs, t_longest_run, t_matrix_rank,
               t_spectral, t_maurer, t_approx_entropy, t_serial, t_cusum):
        try:
            name, p = fn(bits)
            verdict = "SKIP" if p is None else ("PASS" if p >= ALPHA else "FAIL")
            sp800_22.append({"test": name, "p_value": p, "verdict": verdict})
            print(f"  {name:32s} p={p if p is None else round(p,5)!s:>10}  {verdict}")
        except Exception as e:
            sp800_22.append({"test": fn.__name__, "error": str(e)})
            print(f"  {fn.__name__:32s} ERROR {e}")
    res["sp800_22"] = sp800_22
    res["fips_140_2"] = fips_140_2(bits)
    print("FIPS 140-2:", json.dumps(res["fips_140_2"]))
    res["sp800_90b"] = sp90b(data, bits)
    print("SP800-90B :", json.dumps({k: round(v,4) if isinstance(v,float) else v for k,v in res["sp800_90b"].items()}))
    res["per_sequence"] = per_sequence(bits)
    print("\nPER-SEQUENCE (NIST STS-style proportion + uniformity):")
    if "results" in res["per_sequence"]:
        print(f"  {res['per_sequence']['sequences']} sequences x {res['per_sequence']['bits_per_seq']} bits; "
              f"proportion floor {res['per_sequence']['proportion_floor']}")
        for r in res["per_sequence"]["results"]:
            print(f"  {r['test']:28s} prop={r['proportion_pass']:.4f} {'OK' if r['prop_ok'] else 'LOW'}"
                  f"  unif_p={r['uniformity_p']:.5f} {'OK' if r['unif_ok'] else 'LOW'}")
    else:
        print(" ", res["per_sequence"].get("note"))
    print(f"\nelapsed {time.time()-t0:.1f}s")
    if len(sys.argv) > 2:
        json.dump(res, open(sys.argv[2], "w"), indent=2)
        print("wrote", sys.argv[2])


if __name__ == "__main__":
    main()

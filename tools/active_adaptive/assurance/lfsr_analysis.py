#!/usr/bin/env python3
"""Can an LFSR predict this RNG? Two tests on the collected card bytes:
  (1) NIST SP 800-22 Linear Complexity test (Berlekamp-Massey over M-bit blocks).
  (2) Direct experiment: fit the shortest LFSR to a prefix, then predict the next
      bits using the TRUE history (open-loop, best case for the attacker).
An LFSR-weak source -> low linear complexity and >>50% prediction.
A good RNG          -> linear complexity ~ n/2 and ~50% prediction (chance).
"""
import sys, math
import numpy as np

def igamc(a, x):
    if x <= 0 or a <= 0: return 1.0
    gln = math.lgamma(a)
    if x < a + 1.0:
        ap=a; s=1.0/a; d=s
        for _ in range(2000):
            ap+=1; d*=x/ap; s+=d
            if abs(d) < abs(s)*1e-16: break
        return 1.0 - s*math.exp(-x+a*math.log(x)-gln)
    b=x+1-a; c=1e300; dd=1.0/b; h=dd
    for i in range(1,2000):
        an=-i*(i-a); b+=2; dd=an*dd+b
        if abs(dd)<1e-300: dd=1e-300
        c=b+an/c
        if abs(c)<1e-300: c=1e-300
        dd=1.0/dd; dl=dd*c; h*=dl
        if abs(dl-1)<1e-16: break
    return math.exp(-x+a*math.log(x)-gln)*h


def berlekamp_massey(s):
    """GF(2) Berlekamp-Massey. s: numpy uint8 0/1 array.
    Returns (L, C) with C an int: bit j = connection coeff c_j (C=1 means empty)."""
    n = len(s)
    C = 1; B = 1; L = 0; m = 1
    window = 0  # bit (j-1) = s[i-j]
    sl = s.tolist()
    for i in range(n):
        d = sl[i]
        if L:
            d ^= ((C >> 1) & window).bit_count() & 1
        if d:
            T = C
            C ^= (B << m)
            if 2*L <= i:
                L = i + 1 - L; B = T; m = 1
            else:
                m += 1
        else:
            m += 1
        window = (window << 1) | sl[i]
    return L, C


def predict_open_loop(s, T, P):
    """Fit LFSR on s[:T], then predict s[T:T+P] from the TRUE previous L bits."""
    L, C = berlekamp_massey(s[:T])
    cc = C >> 1
    sl = s.tolist()
    # window bit (j-1) = s[i-j]; initialize from s[T-1 .. T-L]
    window = 0
    for j in range(1, L+1):
        window |= (sl[T-j] << (j-1))
    correct = 0
    for i in range(T, T+P):
        pred = (cc & window).bit_count() & 1
        if pred == sl[i]:
            correct += 1
        window = ((window << 1) | sl[i])  # feed TRUE bit (best case for attacker)
    return L, correct / P


def nist_linear_complexity(bits, M=1000, N=1000):
    use = bits[:M*N]
    N = len(use)//M
    mu = M/2 + (9 + (-1)**(M+1))/36 - (M/3 + 2/9)/(2**M)
    v = [0]*7
    for k in range(N):
        L, _ = berlekamp_massey(use[k*M:(k+1)*M])
        Ti = (-1)**M * (L - mu) + 2/9
        if Ti <= -2.5: v[0]+=1
        elif Ti <= -1.5: v[1]+=1
        elif Ti <= -0.5: v[2]+=1
        elif Ti <= 0.5: v[3]+=1
        elif Ti <= 1.5: v[4]+=1
        elif Ti <= 2.5: v[5]+=1
        else: v[6]+=1
    pi = [0.010417,0.03125,0.125,0.5,0.25,0.0625,0.020833]
    chi = sum((v[i]-N*pi[i])**2/(N*pi[i]) for i in range(7))
    return N, M, chi, igamc(3.0, chi/2.0), v


def main():
    data = open(sys.argv[1],"rb").read()
    bits = np.unpackbits(np.frombuffer(data, np.uint8))
    print(f"{len(data)} bytes, {bits.size} bits\n")

    print("=== NIST SP 800-22 Linear Complexity test (M=1000 x N=1000 blocks) ===")
    N, M, chi, p, v = nist_linear_complexity(bits, M=1000, N=1000)
    print(f"  {N} blocks of {M} bits; chi2={chi:.2f} over 6 dof; p-value={p:.5f}  "
          f"{'PASS' if p>=0.01 else 'FAIL'}")
    print(f"  category counts v={v} (expected ~[10,31,125,500,250,63,21])")

    print("\n=== Linear complexity of a prefix (should be ~ n/2) ===")
    for n in (1000, 5000, 20000):
        L, _ = berlekamp_massey(bits[:n])
        print(f"  first {n:6d} bits -> linear complexity L={L:6d}  (L/n={L/n:.3f}; ideal ~0.5)")

    print("\n=== Fit-then-predict (open-loop, true history fed back = best case) ===")
    print("    train T bits -> fit shortest LFSR (degree L), predict next P bits:")
    for T in (2000, 8000, 32000):
        P = 5000
        L, acc = predict_open_loop(bits, T, P)
        print(f"  T={T:6d}  L={L:6d} (L/T={L/T:.3f})  predict next {P}: accuracy={acc*100:.2f}%  "
              f"(chance=50.00%)")

    # Control: a REAL LFSR stream should be predicted ~100%
    print("\n=== Control: a genuine 31-bit LFSR (x^31+x^28+1) ===")
    st = 0x1; seq = np.empty(60000, np.uint8)
    for i in range(60000):
        bit = st & 1; seq[i] = bit
        nb = ((st >> 0) ^ (st >> 3)) & 1   # taps for reversed rep
        st = (st >> 1) | (nb << 30)
    L, acc = predict_open_loop(seq, 2000, 5000)
    print(f"  LFSR control: fit T=2000 -> L={L}, predict next 5000 accuracy={acc*100:.2f}% (expect ~100%)")


if __name__ == "__main__":
    main()

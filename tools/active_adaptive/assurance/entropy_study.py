import sys, math, zlib, collections, time
from smartcard.scard import (SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
    SCardEstablishContext, SCardListReaders, SCardConnect, SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD)
hr,ctx=SCardEstablishContext(SCARD_SCOPE_USER); hr,rdrs=SCardListReaders(ctx,[])
picc=[r for r in rdrs if "PICC" in r][0]
hr,card,proto=SCardConnect(ctx,picc,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1)
N_CALLS=512            # 512 * 256 = 128 KiB
buf=bytearray(); t0=time.time()
for _ in range(N_CALLS):
    hr,r=SCardTransmit(card,proto,[0x00,0x84,0x00,0x00,0x00])
    if r[-2]==0x90: buf+=bytes(r[:-2])
SCardDisconnect(card,SCARD_LEAVE_CARD)
dt=time.time()-t0
open(f"{sys.argv[1]}/card_rng_128k.bin","wb").write(buf)
n=len(buf); print(f"collected {n} bytes in {dt:.1f}s ({N_CALLS} GET CHALLENGE calls)\n")

# byte-level stats
hist=collections.Counter(buf)
counts=[hist.get(i,0) for i in range(256)]
# Shannon entropy (bits/byte)
H=-sum((c/n)*math.log2(c/n) for c in counts if c)
# min-entropy (most-common-value)
pmax=max(counts)/n; Hmin=-math.log2(pmax)
# chi-square vs uniform (255 dof): mean 255, sd sqrt(2*255)=22.58
exp=n/256; chi=sum((c-exp)**2/exp for c in counts)
z=(chi-255)/math.sqrt(510)
# monobit
ones=sum(bin(b).count("1") for b in buf); bits=n*8
mono_z=(ones-bits/2)/math.sqrt(bits/4)
# serial correlation (lag-1, byte level)
mean=sum(buf)/n
num=sum((buf[i]-mean)*(buf[i+1]-mean) for i in range(n-1))
den=sum((b-mean)**2 for b in buf)
scc=num/den if den else 0
# compressibility
comp=len(zlib.compress(bytes(buf),9))/n
print(f"Shannon entropy : {H:.6f} bits/byte   (ideal 8.000000)")
print(f"Min-entropy(MCV): {Hmin:.4f} bits/byte   (ideal 8; pmax={pmax:.5f})")
print(f"Chi-square      : {chi:.1f} on 255 dof   (z={z:+.2f}; |z|<~3 good)")
print(f"Monobit bit-bias: ones={ones}/{bits} ({ones/bits:.5f})  z={mono_z:+.2f}")
print(f"Serial corr lag1: {scc:+.5f}   (ideal ~0)")
print(f"zlib ratio      : {comp:.4f}   (incompressible ~1.0)")
print(f"byte hist min/max counts: {min(counts)}/{max(counts)} (expected ~{exp:.0f})")

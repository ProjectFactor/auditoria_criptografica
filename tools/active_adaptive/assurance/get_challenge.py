import sys
from smartcard.scard import (SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
    SCardEstablishContext, SCardListReaders, SCardConnect, SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD)
hr, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
hr, rdrs = SCardListReaders(ctx, [])
picc = [r for r in rdrs if "PICC" in r][0]
hr, card, proto = SCardConnect(ctx, picc, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1)
def tx(apdu):
    hr, r = SCardTransmit(card, proto, apdu)
    return bytes(r[:-2]), r[-2], r[-1]
print("=== GET CHALLENGE (00 84 00 00 08), raw, no PACE, 5x ===")
samples=[]
for i in range(5):
    data,s1,s2 = tx([0x00,0x84,0x00,0x00,0x08])
    print(f"  SW={s1:02X}{s2:02X}  {data.hex()}")
    if (s1,s2)==(0x90,0x00): samples.append(data)
# try larger lengths
for le in (0x10,0x20,0x00):
    data,s1,s2 = tx([0x00,0x84,0x00,0x00,le])
    print(f"  Le={le:02X} -> SW={s1:02X}{s2:02X} len={len(data)}")
SCardDisconnect(card, SCARD_LEAVE_CARD)
if samples:
    allb=b"".join(samples)
    print(f"\ndistinct bytes across {len(allb)} sampled: {len(set(allb))}/256; all 5 differ: {len(set(map(bytes,samples)))==len(samples)}")

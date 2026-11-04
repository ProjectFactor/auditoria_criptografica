from smartcard.scard import (SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
    SCardEstablishContext, SCardListReaders, SCardConnect, SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD)
hr,ctx=SCardEstablishContext(SCARD_SCOPE_USER); hr,rdrs=SCardListReaders(ctx,[])
picc=[r for r in rdrs if "PICC" in r][0]
hr,card,proto=SCardConnect(ctx,picc,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1)
def tx(apdu,label):
    hr,r=SCardTransmit(card,proto,apdu)
    d=bytes(r[:-2]); sw=f"{r[-2]:02X}{r[-1]:02X}"
    print(f"{label:28s} {sw} len={len(d)}  {d.hex()}")
    return d,r[-2],r[-1]
print("ATR:", bytes(__import__('smartcard').scard.SCardStatus(card)[4]).hex() if False else "")
# CPLC via GET DATA 9F7F, both CLA 00 and 80
tx([0x00,0xCA,0x9F,0x7F,0x00],"GET DATA 9F7F (CLA00)")
tx([0x80,0xCA,0x9F,0x7F,0x00],"GET DATA 9F7F (CLA80)")
# GP card data / IIN / CIN
tx([0x00,0xCA,0x00,0x66,0x00],"GET DATA 0066 (card data)")
tx([0x80,0xCA,0x00,0x66,0x00],"GET DATA 0066 (CLA80)")
tx([0x00,0xCA,0x9F,0x68,0x00],"GET DATA 9F68 (CPLC v2?)")
SCardDisconnect(card,SCARD_LEAVE_CARD)

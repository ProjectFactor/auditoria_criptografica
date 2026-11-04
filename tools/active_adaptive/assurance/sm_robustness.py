#!/usr/bin/env python3
"""On-card assurance: SM replay/SSC-desync rejection and EAC (DG3) enforcement.
Read-only / rejected commands only; no PIN, no write. CAN on stdin."""
import sys, json, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pace_sm as ps
from smartcard.scard import (SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
    SCARD_UNPOWER_CARD, SCardEstablishContext, SCardListReaders, SCardConnect,
    SCardReconnect, SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD)

SELECT_MF=(0x00,0xA4,0x00,0x0C); MF=b"\x3f\x00"
SEL_CA=(0x00,0xA4,0x02,0x0C);  CA=b"\x01\x1c"
SEL_AID=(0x00,0xA4,0x04,0x0C); AID=bytes.fromhex("A0000002471001")
SEL_DG3=(0x00,0xA4,0x02,0x0C); DG3=b"\x01\x03"
READ=(0x00,0xB0,0x00,0x00)

hr,ctx=SCardEstablishContext(SCARD_SCOPE_USER); hr,rdrs=SCardListReaders(ctx,[])
picc=[r for r in rdrs if "PICC" in r][0]
hr,card,proto=SCardConnect(ctx,picc,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1)
def tx(apdu):
    hr,r=SCardTransmit(card,proto,list(apdu)); return bytes(r[:-2]),r[-2],r[-1]
def reset():
    global proto; hr,proto=SCardReconnect(card,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1,SCARD_UNPOWER_CARD)
can=bytearray(sys.stdin.buffer.readline().strip())
rep={}

# ---------- PACE session 1: positive control + EAC(DG3) enforcement ----------
reset()
pace=ps.establish_pace(lambda a: tx(a), bytes(can))
sm=ps.SecureMessaging(pace.k_enc,pace.k_mac)
# positive control: SM read EF.CardAccess
d,s1,s2=tx(sm.build(*SELECT_MF,data=MF)); sm.unwrap(d,s1,s2); d,s1,s2=tx(sm.build(*SEL_CA,data=CA)); sm.unwrap(d,s1,s2)
d,s1,s2=tx(sm.build(*READ,le=0x16)); plain,r1,r2=sm.unwrap(d,s1,s2)
rep["positive_control"]={"sm_read_sw":f"{r1:02X}{r2:02X}","bytes":len(plain),"ok":len(plain)==22}
# EAC: select eMRTD app, select DG3, read -> expect denied (TA not performed)
d,s1,s2=tx(sm.build(*SEL_AID,data=AID)); sm.unwrap(d,s1,s2)
try:
    d,s1,s2=tx(sm.build(*SEL_DG3,data=DG3)); _,rs1,rs2=sm.unwrap(d,s1,s2)
    sel_sw=f"{rs1:02X}{rs2:02X}"
except ps.CardError as e:
    sel_sw=f"select-error({e})"
denied=True; dg3_sw=sel_sw; dg3_bytes=0
if sel_sw=="9000":
    try:
        d,s1,s2=tx(sm.build(*READ,le=0x10)); plain,rs1,rs2=sm.unwrap(d,s1,s2)
        dg3_sw=f"{rs1:02X}{rs2:02X}"; dg3_bytes=len(plain); denied=(dg3_bytes==0 and dg3_sw!="9000")
    except ps.CardError as e:
        dg3_sw=f"read-error({e})"; denied=True
rep["eac_dg3"]={"dg3_status":dg3_sw,"data_bytes":dg3_bytes,"denied_without_TA":denied,
                "verdict":"OK (DG3 gated by EAC)" if denied else "FAIL (DG3 readable without TA!)"}

# ---------- PACE session 2: replay + SSC-desync rejection ----------
reset()
pace=ps.establish_pace(lambda a: tx(a), bytes(can))
sm=ps.SecureMessaging(pace.k_enc,pace.k_mac)
d,s1,s2=tx(sm.build(*SELECT_MF,data=MF)); sm.unwrap(d,s1,s2); d,s1,s2=tx(sm.build(*SEL_CA,data=CA)); sm.unwrap(d,s1,s2)
captured=sm.build(*READ,le=0x16)              # a VALID SM read at this SSC
d,s1,s2=tx(captured); plain,r1,r2=sm.unwrap(d,s1,s2)   # execute it (SSC advances on both sides)
# replay the exact captured bytes now that SSC has moved -> expect rejection
d,s1,s2=tx(captured)
rep["replay"]={"replayed_sw":f"{s1:02X}{s2:02X}","data_bytes":len(d),
               "rejected":(s1,s2)!=(0x90,0x00) and not d,
               "verdict":"OK (stale-SSC replay rejected)" if ((s1,s2)!=(0x90,0x00) and not d) else "FAIL (replay accepted!)"}
# SSC desync: deliberately skip the counter, build a read at the wrong SSC
reset(); pace=ps.establish_pace(lambda a: tx(a), bytes(can)); sm=ps.SecureMessaging(pace.k_enc,pace.k_mac)
d,s1,s2=tx(sm.build(*SELECT_MF,data=MF)); sm.unwrap(d,s1,s2); d,s1,s2=tx(sm.build(*SEL_CA,data=CA)); sm.unwrap(d,s1,s2)
sm.ssc += 3   # jump the send-sequence counter out of step with the card
d,s1,s2=tx(sm.build(*READ,le=0x16))
rep["ssc_desync"]={"sw":f"{s1:02X}{s2:02X}","data_bytes":len(d),
                   "rejected":(s1,s2)!=(0x90,0x00) and not d,
                   "verdict":"OK (wrong-SSC rejected)" if ((s1,s2)!=(0x90,0x00) and not d) else "FAIL (wrong SSC accepted!)"}
SCardDisconnect(card,SCARD_LEAVE_CARD)
for i in range(len(can)): can[i]=0
print(json.dumps(rep,indent=2))

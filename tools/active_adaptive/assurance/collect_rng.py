import sys, time
from smartcard.scard import (SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
    SCARD_UNPOWER_CARD, SCardEstablishContext, SCardListReaders, SCardConnect,
    SCardReconnect, SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD, SCARD_S_SUCCESS)
outdir = sys.argv[1]
TARGET_CALLS = 40960          # 40960 * 256 = 10,485,760 bytes = 10 MiB
GET_CHALLENGE = [0x00,0x84,0x00,0x00,0x00]  # Le=0 -> 256 bytes
hr,ctx = SCardEstablishContext(SCARD_SCOPE_USER)
hr,rdrs = SCardListReaders(ctx,[])
picc = [r for r in rdrs if "PICC" in r][0]
hr,card,proto = SCardConnect(ctx,picc,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1)
hexf=open(outdir+"/rng_calls.txt","w"); binf=open(outdir+"/rng.bin","wb"); logf=open(outdir+"/collect.log","w",buffering=1)
def log(m): logf.write(f"[{time.strftime('%H:%M:%S')}] {m}\n")
calls=got=fails=consec=0; t0=time.time()
log(f"start: target {TARGET_CALLS} calls (10 MiB), reader={picc}")
while calls < TARGET_CALLS:
    try:
        hr,r = SCardTransmit(card,proto,GET_CHALLENGE)
    except Exception as e:
        fails+=1; consec+=1; log(f"transmit error: {e}")
        try: hr,proto = SCardReconnect(card,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1,SCARD_UNPOWER_CARD)
        except Exception as e2: log(f"reconnect failed: {e2}")
        if consec>50: log("ABORT: >50 consecutive failures"); break
        time.sleep(0.2); continue
    if len(r)>=258 and r[-2]==0x90 and r[-1]==0x00:
        data=bytes(r[:-2])
        hexf.write(data.hex()+"\n"); binf.write(data)
        calls+=1; got+=len(data); consec=0
        if calls % 2000 == 0:
            hexf.flush(); binf.flush()
            rate=calls/(time.time()-t0)
            log(f"progress: {calls}/{TARGET_CALLS} calls, {got} bytes, {rate:.0f} calls/s, fails={fails}")
    else:
        fails+=1; consec+=1; log(f"bad resp SW={r[-2]:02X}{r[-1]:02X} len={len(r)}")
        if consec>50: log("ABORT: >50 consecutive failures"); break
hexf.flush(); binf.flush()
SCardDisconnect(card,SCARD_LEAVE_CARD)
dt=time.time()-t0
log(f"DONE: {calls} calls, {got} bytes, {fails} failures, {dt:.1f}s")
open(outdir+"/collect_done.flag","w").write(f"{calls} {got} {fails} {dt:.1f}\n")

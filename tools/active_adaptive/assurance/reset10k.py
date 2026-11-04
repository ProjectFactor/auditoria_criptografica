import sys, time, math, json, collections
from smartcard.scard import (SCARD_SCOPE_USER, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
    SCARD_UNPOWER_CARD, SCardEstablishContext, SCardListReaders, SCardConnect,
    SCardReconnect, SCardTransmit, SCardDisconnect, SCARD_LEAVE_CARD, SCARD_S_SUCCESS)
outdir=sys.argv[1]; K=10000
hr,ctx=SCardEstablishContext(SCARD_SCOPE_USER); hr,rdrs=SCardListReaders(ctx,[])
picc=[r for r in rdrs if "PICC" in r][0]
hr,card,proto=SCardConnect(ctx,picc,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1)
GC=[0x00,0x84,0x00,0x00,0x20]
hexf=open(outdir+"/reset_first32.txt","w"); log=open(outdir+"/reset.log","w",buffering=1)
first=[]; fails=0; consec=0; t0=time.time()
for i in range(K):
    try:
        hr,proto=SCardReconnect(card,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1,SCARD_UNPOWER_CARD)
        if hr!=SCARD_S_SUCCESS:
            fails+=1; consec+=1
            if consec>100: log.write("ABORT reconnect\n"); break
            continue
        hr,r=SCardTransmit(card,proto,GC)
        if len(r)>=34 and r[-2]==0x90:
            d=bytes(r[:-2]); first.append(d); hexf.write(d.hex()+"\n"); consec=0
        else:
            fails+=1; consec+=1
    except Exception as e:
        fails+=1; consec+=1; log.write(f"{i} {e}\n")
        try: hr,proto=SCardReconnect(card,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1,SCARD_UNPOWER_CARD)
        except Exception: pass
        if consec>100: log.write("ABORT\n"); break
    if i%500==0:
        hexf.flush(); log.write(f"[{time.strftime('%H:%M:%S')}] {i}/{K} ok={len(first)} fails={fails} rate={len(first)/(time.time()-t0+1e-9):.1f}/s\n")
hexf.flush(); SCardDisconnect(card,SCARD_LEAVE_CARD); dt=time.time()-t0
def minent(samples,L):
    out=[]
    for p in range(L):
        c=collections.Counter(s[p] for s in samples); pmax=max(c.values())/len(samples)
        out.append(round(-math.log2(pmax),3))
    return out
res={"resets":K,"ok":len(first),"fails":fails,"seconds":round(dt,1)}
res["unique_full32"]=len(set(first)); res["unique_first16"]=len({s[:16] for s in first})
res["any_collision_full32"]=res["unique_full32"]!=len(first)
res["any_collision_first16"]=res["unique_first16"]!=len(first)
res["min_entropy_per_byte"]=minent(first,32) if first else []
# chi-square on pooled bytes of boot outputs
allb=b"".join(first); import numpy as np
cnt=np.bincount(np.frombuffer(allb,np.uint8),minlength=256); exp=len(allb)/256
res["pooled_chi2_255dof"]=float(np.sum((cnt-exp)**2/exp)); res["pooled_chi2_z"]=(res["pooled_chi2_255dof"]-255)/math.sqrt(510)
res["pooled_bytes"]=len(allb)
json.dump(res,open(outdir+"/reset10k.json","w"),indent=2)
log.write("DONE "+json.dumps(res)+"\n"); open(outdir+"/done.flag","w").write("done\n")

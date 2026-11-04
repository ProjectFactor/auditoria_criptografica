#!/usr/bin/env python3
"""Offline crypto assurance checks: ROCA fingerprint on the RSA-1024 dev signer,
EC public-key validity (DS brainpoolP256r1, chip-auth P-384), SOD CMS signature."""
import sys, subprocess, re, json, os, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pace_sm as ps   # P-384 constants + ec helpers

def run(cmd, inp=None):
    return subprocess.run(cmd, input=inp, capture_output=True).stdout

# ---------- ROCA fingerprint (Nemec et al., CVE-2017-15361) ----------
def roca_vulnerable(N):
    primes = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,
              97,101,103,107,109,113,127,131,137,139,149,151,157,163,167]
    g = 65537
    for p in primes:
        gp = g % p
        subgroup = set()
        x = 1
        for _ in range(p):
            subgroup.add(x); x = (x * gp) % p
            if x == 1: break
        if (N % p) not in subgroup:
            return False, p   # a prime where N mod p escapes <65537> -> NOT ROCA
    return True, None

# ---------- generic EC point validity ----------
def ec_valid(p, a, b, n, X, Y, label):
    on = (Y*Y - (X*X*X + a*X + b)) % p == 0
    # order check via a minimal double-and-add using these params
    def add(P,Q):
        if P is None: return Q
        if Q is None: return P
        x1,y1=P; x2,y2=Q
        if x1==x2 and (y1+y2)%p==0: return None
        if P==Q: l=(3*x1*x1+a)*pow(2*y1,p-2,p)%p
        else: l=(y2-y1)*pow(x2-x1,p-2,p)%p
        x3=(l*l-x1-x2)%p; return (x3,(l*(x1-x3)-y1)%p)
    def mul(k,P):
        R=None
        while k:
            if k&1: R=add(R,P)
            P=add(P,P); k>>=1
        return R
    order_ok = mul(n,(X,Y)) is None
    return {"curve":label,"on_curve":on,"n_times_P_is_identity":order_ok,
            "not_identity": not (X==0 and Y==0)}

def get_ec_point(pem_cmd):
    txt = run(pem_cmd).decode(errors="ignore")
    m = re.search(r"pub:\s*((?:[0-9a-f:\s]+))ASN1 OID:\s*(\S+)", txt)
    if not m: m = re.search(r"pub:\s*((?:[0-9a-f:\s]+))(?:Field|$)", txt)
    hexs = re.sub(r"[^0-9a-f]","", m.group(1))
    oid = m.group(2) if m.lastindex and m.lastindex>=2 else "?"
    pt = bytes.fromhex(hexs)
    assert pt[0]==0x04, "not uncompressed point"
    L=(len(pt)-1)//2
    return int.from_bytes(pt[1:1+L],"big"), int.from_bytes(pt[1+L:],"big"), oid

out={}
# ROCA
mod_line = run(["openssl","x509","-in",str(ROOT/"exports/certificates/cardsecurity-development-ds.pem"),"-noout","-modulus"]).decode()
N = int(mod_line.strip().split("=")[1],16)
vuln, esc = roca_vulnerable(N)
out["roca"]={"modulus_bits":N.bit_length(),"roca_vulnerable":vuln,"escaped_at_prime":esc,
             "verdict":"VULNERABLE (ROCA)" if vuln else "not ROCA-fingerprinted"}

# brainpoolP256r1 params
bp_p=int("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",16)
bp_a=int("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",16)
bp_b=int("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",16)
bp_n=int("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",16)
try:
    X,Y,oid = get_ec_point(["bash","-c",
        f"openssl x509 -in {ROOT}/exports/certificates/jce-ds-02.pem -pubkey -noout | openssl ec -pubin -text -noout 2>/dev/null"])
    out["ds_ec"]={**ec_valid(bp_p,bp_a,bp_b,bp_n,X,Y,"brainpoolP256r1"),"openssl_oid":oid}
except Exception as e:
    out["ds_ec"]={"error":str(e)}
# P-384 chip auth
try:
    X,Y,oid = get_ec_point(["openssl","ec","-pubin","-in",
        str(ROOT/"exports/cedula-p384-chip-auth-public-key.pem"),"-text","-noout"])
    out["chipauth_ec"]={**ec_valid(ps._P,ps._A,ps._B,ps._N,X,Y,"NIST P-384"),"openssl_oid":oid}
except Exception as e:
    out["chipauth_ec"]={"error":str(e)}

# SOD CMS signature verify (embedded DS cert; chain not checked = -noverify)
import tempfile
# Supply a locally captured EF.SOD via CEDULA_SOD_DER=/path/to/sod.der (not shipped in this repo).
_sod_path=os.environ.get("CEDULA_SOD_DER")
if not _sod_path:
    out["sod_cms"]={"skipped": "set CEDULA_SOD_DER to a captured EF.SOD (DER) to run this check"}
else:
    _sd=pathlib.Path(_sod_path).read_bytes()
    _inner=_sd[2+( _sd[1]&0x7f if _sd[1]&0x80 else 0):] if _sd[1]&0x80 else _sd[2:]
    sod=tempfile.NamedTemporaryFile(suffix=".der",delete=False).name; open(sod,"wb").write(_inner)
    r = subprocess.run(["openssl","cms","-verify","-in",sod,"-inform","DER","-noverify","-out","/dev/null"],
                       capture_output=True)
    out["sod_cms"]={"signature_valid": r.returncode==0, "stderr": r.stderr.decode().strip()[:120]}

print(json.dumps(out, indent=2))

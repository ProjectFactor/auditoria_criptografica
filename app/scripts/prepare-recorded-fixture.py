#!/usr/bin/env python3
"""Copy already acquired card payloads into an ignored local app fixture; no reader or CAN access."""
from pathlib import Path
import json, shutil, hashlib
root=Path(__file__).resolve().parents[2]
out=root/'app/private-fixtures/recorded'
out.mkdir(parents=True, exist_ok=True)
entries=[]
def add(app,name,fid,session,artifact='assembled_der_001.bin'):
    path=root/'logs/sessions'/session/'artifacts'/artifact
    if not path.exists() and name=='EF.COM':
        path=path.parent/'decrypted_response_002.bin'
    if not path.exists():
        print('Missing artifact for',name)
        return
    dest=f'{app}-{name}.bin'
    shutil.copyfile(path,out/dest)
    entries.append(dict(Application=app,Name=name,Fid=fid,File=dest))
for name,fid,session in [
('DG1','0101','session_TEST-01_DG1_FULL'),
('DG2','0102','session_TEST-01_DG2_FULL'),
('DG7','0107','session_TEST-01_DG7_FULL'),
('DG11','010B','session_TEST-01_DG11_FULL'),
('DG12','010C','session_TEST-01_DG12_FULL'),
('DG13','010D','session_TEST-01_DG13_FULL'),
('DG14','010E','session_TEST-01_DG14_FULL'),
('EF.SOD','011D','session_TEST-01_EF_SOD_FULL'),
('EF.COM','011E','session_TEST-01_EF_COM_FULL')]:
    add('eMRTD',name,fid,session)
add('MF','EF.CardSecurity','011D','session_TEST-01_CARDSECURITY_FULL')
entries.append(dict(Application='eMRTD',Name='DG3',Fid='0103',File='',Status='Protected',Detail='Prior recorded access denial; not acquired'))
(out/'recorded.json').write_text(json.dumps(entries,indent=2))
print(f'Prepared {len(entries)} object descriptors; private fixture excluded from Git.')

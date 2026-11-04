#!/usr/bin/env python3
"""Produce the portable distribution; never include recorded card data or build/test output."""
from pathlib import Path
import hashlib,tarfile,zipfile,gzip,io
EPOCH=(1980,1,1,0,0,0)  # fixed timestamps: archives carry no build date
def zadd(z,path,name):
    zi=zipfile.ZipInfo(name,date_time=EPOCH);zi.compress_type=zipfile.ZIP_DEFLATED;zi.external_attr=0o755<<16 if name.endswith('.exe') else 0o644<<16
    z.writestr(zi,Path(path).read_bytes())
def tfilter(ti):
    ti.mtime=0;ti.uid=ti.gid=0;ti.uname=ti.gname='';return ti
app=Path(__file__).resolve().parents[1]
exe=app/'artifacts/win-x64/CedulaReader.exe'
output=app/'artifacts/CedulaReader-0.1.0-win-x64.zip'
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
    zadd(archive,exe,'CedulaReader.exe')
    for name in ['README.md','WINDOWS_TEST_CHECKLIST.md']:
        zadd(archive,app/name,name)
    for f in sorted((app/'licenses').glob('*')):
        zadd(archive,f,'licenses/'+f.name)
sha=hashlib.sha256(output.read_bytes()).hexdigest()
output.with_suffix('.zip.sha256').write_text(sha+'  '+output.name+'\n')
print(f'{output.name}: {output.stat().st_size} bytes; SHA-256 {sha}')

lexe=app/'artifacts/linux-x64/cedula-reader'
ltar=app/'artifacts/cedula-reader-0.1.0-linux-x64.tar.gz'
with gzip.GzipFile(ltar,'wb',mtime=0) as gz, tarfile.open(fileobj=gz,mode='w') as archive:
    archive.add(lexe,'cedula-reader',filter=tfilter)
    archive.add(app/'README.md','README.md',filter=tfilter)
    for f in sorted((app/'licenses').glob('*')):
        archive.add(f,'licenses/'+f.name,filter=tfilter)
sha=hashlib.sha256(ltar.read_bytes()).hexdigest()
ltar.with_suffix('.gz.sha256').write_text(sha+'  '+ltar.name+'\n')
print(f'{ltar.name}: {ltar.stat().st_size} bytes; SHA-256 {sha}')

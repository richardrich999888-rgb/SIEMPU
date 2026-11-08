"""Assemble a dedicated, secret-free ClamAV runtime from a verified engine package."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

lab=Path(sys.argv[1]).resolve()
native=lab/'engine/usr/local'
root=lab/'runtime'
root.mkdir(mode=0o755)
for name in ['bin','lib','lib64','etc/certs','proc','dev','tmp','signatures']:
    (root/name).mkdir(parents=True,exist_ok=True,mode=0o755)

def copy(source,destination):
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    shutil.copyfile(source,destination)
    destination.chmod(0o755 if os.access(source,os.X_OK) else 0o644)

copy(native/'bin/clamscan',root/'bin/clamscan')
env={'PATH':'/usr/bin:/bin','LD_LIBRARY_PATH':str(native/'lib')}
# Only the already hash-verified upstream package is inspected with the system loader tool.
linked=subprocess.check_output(['/usr/bin/ldd',str(native/'bin/clamscan')],env=env,text=True)
if 'not found' in linked:
    raise RuntimeError('unresolved native library')
for line in linked.splitlines():
    match=re.search(r'(/[^\s()]+)',line)
    if not match:
        continue
    source=Path(match[1])
    relative='lib/'+source.name if source.is_relative_to(native) else str(source).lstrip('/')
    copy(source,root/relative)
for source in (native/'etc/certs').iterdir():
    if source.is_file():copy(source,root/'etc/certs'/source.name)
for directory,_,_ in os.walk(root):Path(directory).chmod(0o755)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
config=json.loads((lab/'config.json').read_text())
config['executable']=str(root/'bin/clamscan')
config['executableSha256']=sha(config['executable'])
config['sandbox']={'bwrap':'/usr/bin/bwrap','bwrapSha256':sha('/usr/bin/bwrap'),
 'prlimit':'/usr/bin/prlimit','prlimitSha256':sha('/usr/bin/prlimit'),'runtimeRoot':str(root),
 'files':{str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file()}}
(lab/'isolated-config.json').write_text(json.dumps(config))
Path('artifacts/clamav-host/isolation-inventory.json').write_text(json.dumps({
 'bubblewrapVersion':subprocess.check_output(['/usr/bin/bwrap','--version'],text=True).strip(),
 'bwrapSha256':config['sandbox']['bwrapSha256'],'prlimitSha256':config['sandbox']['prlimitSha256'],
 'runtimeFiles':config['sandbox']['files'],'scope':'Linux laboratory runtime; no host attestation or aggregate cgroup limits'},indent=2)+'\n')

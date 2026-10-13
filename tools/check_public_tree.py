"""Basic tracked-tree privacy checks; not a substitute for human review."""
from pathlib import Path
import re
import subprocess

root=Path(__file__).resolve().parents[1]
tracked=subprocess.check_output(['git','-C',str(root),'ls-files','-z']).decode().split('\0')
forbidden_parts={'.env','state','private','data','profile','.browser-runtime','.browser-venv','handoff','.test-tmp'}
forbidden_suffixes={'.sqlite','.sqlite3','.db','.json','.jsonl','.csv','.log','.png','.jpg','.zip','.pem','.key'}
patterns=[('private_key',re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
          ('github_token',re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}')),
          ('jwt',re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}')),
          ('telegram_token',re.compile(r'\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}'))]
issues=[]
for name in filter(None,tracked):
    relative=Path(name);path=root/relative
    if any(p in forbidden_parts for p in relative.parts) or relative.name=='RUN.md' or relative.suffix.lower() in forbidden_suffixes:
        issues.append((name,'private_or_runtime_path'));continue
    if path.is_symlink():issues.append((name,'symlink'));continue
    if not path.is_file():issues.append((name,'missing_file'));continue
    data=path.read_bytes()
    if len(data)>1024*1024:issues.append((name,'unexpected_large_file'));continue
    if b'\x00' in data:issues.append((name,'binary_file'));continue
    text=data.decode('utf-8')
    for label,pattern in patterns:
        if pattern.search(text):issues.append((name,label))
for name,label in issues:print(name+': '+label)
if issues:raise SystemExit(1)
print('Public tracked-tree checks passed ('+str(len([x for x in tracked if x]))+' files).')

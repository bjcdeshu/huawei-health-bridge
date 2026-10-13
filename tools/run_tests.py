"""Run synthetic tests with process-wide production/network guards."""
import os
from pathlib import Path
import sys
import unittest

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
if not os.environ.get('TMPDIR'):
    raise SystemExit('Set TMPDIR to an explicit private test directory first.')
tmp=Path(os.environ['TMPDIR']).resolve()
if not tmp.is_dir():raise SystemExit('TMPDIR must exist.')

def audit(event,args):
    if event in ('socket.connect','socket.getaddrinfo','subprocess.Popen'):
        raise AssertionError('real_network_or_browser_forbidden_in_synthetic_suite')
    if event in ('open','sqlite3.connect') and args and isinstance(args[0],(str,bytes,os.PathLike)):
        name=os.fsdecode(args[0])
        if name.startswith('file:'):name=name[5:].split('?',1)[0]
        absolute=str(Path(name).absolute())
        if absolute.startswith(('/var/lib/huawei-training-camp','/srv/agent-workspace/huawei-training-camp/')):
            raise AssertionError('production_path_forbidden_in_synthetic_suite')
sys.addaudithook(audit)
suite=unittest.defaultTestLoader.discover(str(root),pattern='test_*.py')
result=unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)

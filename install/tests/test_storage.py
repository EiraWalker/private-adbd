import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from test_local import SCRATCH
import installer as m


class StorageTests(unittest.TestCase):
    def test_parent_component_cannot_hide_output_inside_checkout(self):
        from unittest.mock import patch
        import private_output
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix='fictional-checkout-') as temp:
            root = Path(temp)
            checkout = root/'checkout'
            (checkout/'install').mkdir(parents=True)
            outside = root/'outside'
            outside.mkdir()
            alias = outside/'..'/'checkout'/'evidence'
            with patch.object(private_output, '__file__', str(checkout/'install'/'private_output.py')):
                with self.assertRaises(m.Refusal):
                    private_output.PrivateOutput(alias, create=True)
            self.assertFalse((checkout/'evidence').exists())

    def test_cross_process_host_session_lock_rejects_parallel_resume(self):
        import subprocess,sys
        self.assertTrue(hasattr(m.PrivateOutput,'session'),'host session exclusion missing')
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-session-') as temp:
            out=m.PrivateOutput(Path(temp)/'out',create=True)
            code="import sys;sys.path.insert(0,sys.argv[1]);from private_output import PrivateOutput;from common import Refusal;out=PrivateOutput(sys.argv[2],False)\ntry:\n with out.session(): pass\nexcept Refusal: raise SystemExit(2)\n"
            cmd=[sys.executable,'-S','-B','-c',code,str(Path(m.__file__).parent),str(out.path)]
            with out.session():
                result=subprocess.run(cmd,capture_output=True)
                self.assertEqual(result.returncode,2,result.stderr)
            result=subprocess.run(cmd,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)

    @unittest.skipUnless(os.name=='nt','Windows file DACL fixture')
    def test_reopening_output_rejects_broad_child_file_acl(self):
        import subprocess
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-acl-file-') as temp:
            path=Path(temp)/'out';out=m.PrivateOutput(path,True)
            out.raw('private.bin',b'FICTIONAL private backup')
            result=subprocess.run(['icacls',str(path/'private.bin'),'/grant','*S-1-1-0:(R)'],capture_output=True)
            self.assertEqual(result.returncode,0)
            with self.assertRaises(m.Refusal):m.PrivateOutput(path,False)

    def test_private_durable_output_and_safe_events(self):
        self.assertTrue(hasattr(m, 'PrivateOutput'), 'private durable output missing')
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix='fictional-out-') as temp:
            path=Path(temp)/'out'
            out=m.PrivateOutput(path, create=True)
            out.write('checkpoint.json', {'phase':'preflight'})
            self.assertEqual(json.loads((path/'checkpoint.json').read_text()),{'phase':'preflight'})
            out.write('checkpoint.json', {'phase':'complete'})
            self.assertEqual(json.loads((path/'checkpoint.json').read_text())['phase'],'complete')
            out.raw('backup-000.bin',b'FICTIONAL private bytes')
            out.event('package', 0, b'FICTIONAL secret stdout', b'FICTIONAL private stderr')
            obj=json.loads((path/'events.jsonl').read_text())
            self.assertEqual(set(obj),{'time','label','exit','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'})
            self.assertNotIn('FICTIONAL', (path/'events.jsonl').read_text())
            with self.assertRaises(m.Refusal): out.event('private raw command',0,b'',b'')
            with self.assertRaises(m.Refusal): out.raw('../escape',b'no')
            with self.assertRaises(m.Refusal): out.raw('backup-000.bin',b'overwrite')
            m.PrivateOutput(path, create=False)
            with self.assertRaises(m.Refusal): m.PrivateOutput(path, create=True)
            if os.name=='posix':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700)
                for p in path.iterdir(): self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
                path.chmod(0o755)
                with self.assertRaises(m.Refusal): m.PrivateOutput(path,create=False)


if __name__ == '__main__': unittest.main()

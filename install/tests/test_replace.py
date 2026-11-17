import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_local import SCRATCH, digest
import installer as m
import android as a


class ReplaceTests(unittest.TestCase):
    def test_checked_replace_contract_has_inline_flock_and_exclusive_temp(self):
        self.assertTrue(hasattr(a,'replace_script'), 'checked replacement missing')
        script=a.replace_script(m.MANAGER,'0'*64,'1'*64,'700',10123,'a'*32,
                                m.APP,m.STATE+'session.lock',m.BIN+'flock')
        self.assertIn('} 9<',script)
        self.assertNotIn('exec 9',script)
        self.assertIn('set -C',script)
        self.assertGreaterEqual(script.count('0'*64),2)
        self.assertNotIn('rm -rf',script)
        cleanup=script.split('cleanup()')[1].split('trap cleanup')[0]
        self.assertIn('sha256sum',cleanup)
        for args in [(m.MANAGER,'bad','1'*64,'700',10123,'a'*32),
                     (m.MANAGER,'0'*64,'1'*64,'777',10123,'a'*32),
                     (m.MANAGER,'0'*64,'1'*64,'700',10123,'bad')]:
            with self.assertRaises(m.Refusal): a.replace_script(*args,m.APP,m.STATE+'session.lock',m.BIN+'flock')

    @unittest.skipUnless(os.name=='posix' and shutil.which('flock'), 'requires real POSIX filesystem and flock')
    def test_real_posix_checked_replace_collision_symlink_and_pre_rename_drift(self):
        self.assertTrue(hasattr(a,'replace_script'), 'checked replacement missing')
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-cas-') as temp:
            root=Path(temp); root.chmod(0o700)
            old=b'FICTIONAL before'; new=b'FICTIONAL after'; path=root/'code'; lock=root/'lock'
            lock.write_bytes(b'FICTIONAL lock'); lock.chmod(0o600)
            def script():
                return a.replace_script(str(path),digest(old),digest(new),'700',os.getuid(),'a'*32,
                                        str(root),str(lock),shutil.which('flock'))
            def run(code,env=None):
                return subprocess.run([getattr(self,'fixture_shell','sh'),'-c',code],input=base64.b64encode(new)+b'\n',capture_output=True,env=env)
            path.write_bytes(old);path.chmod(0o700)
            self.assertEqual(run(script()).returncode,0)
            self.assertEqual(path.read_bytes(),new)
            self.assertNotEqual(run(script()).returncode,0)
            path.write_bytes(old);path.chmod(0o700)
            for unsafe_mode in (0o720, 0o702, 0o777):
                root.chmod(unsafe_mode)
                try:
                    self.assertNotEqual(run(script()).returncode, 0)
                finally:
                    root.chmod(0o700)
                self.assertEqual(path.read_bytes(), old)
            candidate=Path(str(path)+'.upgrade-'+'a'*32)
            candidate.write_bytes(b'FICTIONAL unrelated collision')
            self.assertNotEqual(run(script()).returncode,0)
            self.assertEqual(candidate.read_bytes(),b'FICTIONAL unrelated collision'); candidate.unlink()
            path.unlink(); path.symlink_to(lock)
            self.assertNotEqual(run(script()).returncode,0)
            path.unlink();path.write_bytes(old);path.chmod(0o700)
            tools=root/'tools';tools.mkdir(); shim=tools/'base64'
            shim.write_text('#!/bin/sh\n/usr/bin/base64 "$@"\nprintf drift > '+a.q(str(path))+'\n');shim.chmod(0o700)
            env=dict(os.environ);env['PATH']=str(tools)+':'+env['PATH']
            self.assertNotEqual(run(script(),env).returncode,0)
            self.assertEqual(path.read_bytes(),b'drift')
            self.assertFalse(candidate.exists())

    @unittest.skipUnless(os.name=='posix' and shutil.which('mksh') and shutil.which('flock'), 'requires installed real mksh and POSIX flock')
    def test_real_mksh_inline_fd9_fixture(self):
        self.fixture_shell=shutil.which('mksh')
        self.test_real_posix_checked_replace_collision_symlink_and_pre_rename_drift()


if __name__=='__main__': unittest.main()

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_local import SCRATCH, release
from test_installer import profile
import installer as m


class OfflineSDK:
    """Model injection boundary; real SDK subprocess validation has separate tests."""
    def verify(self,path,expected):
        return {k:expected[k] for k in ('sha256','version','package','signer_sha256','debuggable')}


class CLITests(unittest.TestCase):
    def test_plan_and_default_apply_never_construct_remote(self):
        self.assertTrue(hasattr(m,'run'),'CLI dispatch missing')
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-cli-') as temp:
            root=Path(temp); (root/'fixture.apk').write_bytes(b'FICTIONAL APK')
            (root/'profile.json').write_text(json.dumps(profile()))
            (root/'release.json').write_text(json.dumps(release()))
            def bomb(*args,**kwargs): self.fail('dry-run constructed a remote')
            for command in ['plan','apply','resume']:
                args=argparse.Namespace(command=command,profile=root/'profile.json',release=root/'release.json',
                    output=root/('out-'+command),execute=False,maintenance=None,checkpoint_sha256=None,
                    apksigner_argv='["FICTIONAL-signer"]',aapt_argv='["FICTIONAL-aapt"]')
                result=m.run(args,remote_factory=bomb,sdk=OfflineSDK())
                self.assertEqual(result['device_calls'],0)
                self.assertEqual(result['result'],'dry-run')
            args.command='plan';args.execute=True
            with self.assertRaises(m.Refusal):m.run(args,remote_factory=bomb,sdk=OfflineSDK())

    def test_inspect_verifies_identity_first_and_can_observe_missing_native(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-inspect-') as temp:
            root=Path(temp);(root/'fixture.apk').write_bytes(b'FICTIONAL APK')
            (root/'profile.json').write_text(json.dumps(profile()));(root/'release.json').write_text(json.dumps(release()))
            sequence=[]
            class Inspector:
                calls=2
                def package(self):sequence.append('identity');return {'FICTIONAL':'package'}
                def snapshot(self,allow_missing_native=False):
                    self_test.assertEqual(sequence,['identity'])
                    self_test.assertTrue(allow_missing_native)
                    sequence.append('snapshot');return {'native':None}
            self_test=self
            def factory(inputs,out,execute):self.assertFalse(execute);return Inspector()
            args=argparse.Namespace(command='inspect',profile=root/'profile.json',release=root/'release.json',output=root/'out',
                execute=False,maintenance=None,checkpoint_sha256=None,apksigner_argv='[]',aapt_argv='[]')
            self.assertEqual(m.run(args,remote_factory=factory,sdk=OfflineSDK())['result'],'inspected')

    def test_real_cli_dry_run_uses_only_offline_fixture_tools(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-cli-process-') as temp:
            root=Path(temp);(root/'fixture.apk').write_bytes(b'FICTIONAL APK')
            controller=root/'controller.py';marker=root/'DEVICE-CALL-FORBIDDEN'
            controller.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("FICTIONAL unexpected call")\n')
            p=profile();p['transport']['argv']=[sys.executable,'-S',str(controller)]
            (root/'profile.json').write_text(json.dumps(p));(root/'release.json').write_text(json.dumps(release()))
            tool=root/'sdk.py'
            tool.write_text("import sys\nif sys.argv[1]=='sign':print('Signer #1 certificate SHA-256 digest: '+'0'*64)\nelse:\n print(\"package: name='com.termux' versionCode='2' versionName='fictional'\")\n print('application-debuggable')\n")
            base=[sys.executable,'-S','-B',str(Path(m.__file__)),'apply','--profile',str(root/'profile.json'),
                  '--release',str(root/'release.json'),'--apksigner-argv',json.dumps([sys.executable,'-S',str(tool),'sign']),
                  '--aapt-argv',json.dumps([sys.executable,'-S',str(tool),'meta'])]
            result=subprocess.run(base+['--output',str(root/'dry')],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['device_calls'],0)
            self.assertFalse(marker.exists())
            result=subprocess.run(base+['--execute','--output',str(root/'no-owner')],capture_output=True)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertFalse(marker.exists())

    def test_help_and_site_disabled_import_are_inert(self):
        result=subprocess.run([sys.executable,'-S','-B',str(Path(m.__file__)),'--help'],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'--execute',result.stdout)
        code="import sys,subprocess;sys.path.insert(0,sys.argv[1]);subprocess.run=lambda *a,**k:(_ for _ in ()).throw(AssertionError('import subprocess'));import installer"
        result=subprocess.run([sys.executable,'-S','-B','-c',code,str(Path(m.__file__).parent)],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()

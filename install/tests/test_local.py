import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

from test_installer import profile
import installer as m

SCRATCH = Path(os.environ.get('TMPDIR') or tempfile.gettempdir())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def release():
    return {'schema': 1, 'apk': 'fixture.apk', 'sha256': digest(b'FICTIONAL APK'),
            'version': 2, 'package': 'com.termux', 'signer_sha256': '0' * 64,
            'debuggable': True, 'baselines': [{'version': 1, 'sha256': digest(b'FICTIONAL old APK')}],
            'payloads': [], 'remove_legacy': [], 'source_revision': 'FICTIONAL-not-verified'}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='fictional-install-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'fixture.apk').write_bytes(b'FICTIONAL APK')

    @unittest.skipUnless(os.name=='nt','Windows junction fixture')
    def test_windows_source_directory_junction_is_not_a_relative_artifact(self):
        target=self.root/'target';target.mkdir();(target/'fixture.apk').write_bytes(b'FICTIONAL APK')
        manifest=self.root/'manifest';manifest.mkdir();junction=manifest/'assets'
        result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(junction),str(target)],capture_output=True)
        if result.returncode:self.skipTest('junction creation unavailable on this filesystem')
        r=release();r['apk']='assets/fixture.apk'
        with self.assertRaises(m.Refusal):m.validate_release(r,manifest)

    def test_release_local_integrity_and_strict_destinations(self):
        self.assertTrue(hasattr(m, 'validate_release'), 'release validation missing')
        self.assertEqual(m.validate_release(release(), self.root), release())
        for key, value in [('sha256', 'a'*63), ('sha256', 'F'*64), ('apk', '../escape'),
                           ('apk', '/absolute.apk'), ('unknown', 1), ('debuggable', False),
                           ('version', 1), ('package', 'other'), ('sha256', '1'*64),
                           ('baselines', []), ('baselines', [{'version': 3, 'sha256': '0'*64}])]:
            with self.subTest(key=key, value=value):
                r = release(); r[key] = value
                with self.assertRaises(m.Refusal): m.validate_release(r, self.root)
        (self.root / 'code').write_bytes(b'FICTIONAL CODE')
        payload = {'path': m.MANAGER, 'source': 'code', 'sha256': digest(b'FICTIONAL CODE'),
                   'before_sha256': None, 'mode': '700', 'phase': 'before_apk'}
        r = release(); r['payloads'] = [payload]
        self.assertEqual(m.validate_release(r, self.root), r)
        for path in [m.STATE+'adbkey', m.APP+'/shared_prefs/private.xml', '/system/bin/sh',
                     m.BIN+'../bin/private-adbd', m.STATE+'health.json', m.BIN+'arbitrary',
                     m.MANAGER+';id']:
            with self.subTest(path=path):
                bad=copy.deepcopy(r); bad['payloads'][0]['path']=path
                with self.assertRaises(m.Refusal): m.validate_release(bad, self.root)
        for key,value in [('mode','777'), ('phase','anything'), ('before_sha256','x'), ('source','../code')]:
            with self.subTest(key=key):
                bad=copy.deepcopy(r); bad['payloads'][0][key]=value
                with self.assertRaises(m.Refusal): m.validate_release(bad, self.root)
        r['payloads'].append(copy.deepcopy(payload))
        with self.assertRaises(m.Refusal): m.validate_release(r, self.root)
        r=release(); r['remove_legacy']=[{'path':m.MANAGER,'sha256':'0'*64,'mode':'700'}]
        with self.assertRaises(m.Refusal): m.validate_release(r, self.root)


if __name__ == '__main__': unittest.main()

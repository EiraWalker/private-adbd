import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_local import SCRATCH, release
import installer as m


class SDKTests(unittest.TestCase):
    def test_actual_offline_tool_subprocess_and_strict_metadata(self):
        self.assertTrue(hasattr(m, 'SDK'), 'SDK verifier missing')
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix='fictional-sdk-') as temp:
            root=Path(temp); apk=root/'fixture.apk'; apk.write_bytes(b'FICTIONAL APK')
            tool=root/'tool.py'
            tool.write_text("import sys\nkind=sys.argv[1]\nif kind=='sign':\n print('Signer #1 certificate SHA-256 digest: '+ '0'*64)\nelse:\n print(\"package: name='com.termux' versionCode='2' versionName='fictional'\")\n print('application-debuggable')\n", encoding='utf-8')
            sdk=m.SDK([sys.executable,'-S',str(tool),'sign'],[sys.executable,'-S',str(tool),'meta'])
            self.assertEqual(sdk.verify(apk,release())['version'],2)
            self.assertEqual(sdk.calls,2)
            for old,new in [('versionCode=\'2\'','versionCode=\'3\''),('com.termux','other.package'),
                            ('application-debuggable','not-debuggable'),("'0'*64","'1'*64")]:
                with self.subTest(new=new):
                    original=tool.read_text(); tool.write_text(original.replace(old,new))
                    try:
                        with self.assertRaises(m.Refusal): sdk.verify(apk,release())
                    finally: tool.write_text(original)
            tool.write_text("raise SystemExit(1)\n")
            with self.assertRaises(m.Refusal): sdk.verify(apk,release())
            with self.assertRaises(m.Refusal): m.SDK('shell string', ['aapt'])


if __name__ == '__main__': unittest.main()

import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_installer import profile
import installer as m
from test_local import SCRATCH


class AndroidTests(unittest.TestCase):
    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('android'), 'Android execution primitives missing')
        import android
        return android

    def test_fixed_transport_argv_with_real_fixture_subprocess(self):
        a=self.api()
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-transport-') as temp:
            tool=Path(temp)/'transport.py'
            tool.write_text('import sys,json\nprint(json.dumps(sys.argv[1:]))\n')
            p=profile(); p['transport']['argv']=[sys.executable,'-S',str(tool)]
            events=[]
            t=a.Transport(p,lambda *x:events.append(x),execute=False)
            self.assertEqual(json.loads(t.shell('getprop ro.serialno','identity')),['shell','getprop ro.serialno'])
            with self.assertRaises(m.Refusal): t.shell('mutation','payload',mutating=True)
            self.assertEqual(len(events),1)
            p['transport']={'kind':'adb','argv':['FICTIONAL-adb'],'serial':'FICTIONAL-explicit'}
            self.assertEqual(a.Transport(p,lambda *x:None).command(['shell','id']),
                             ['FICTIONAL-adb','-s','FICTIONAL-explicit','shell','-T','id'])

    def test_transport_requires_late_gate_before_each_mutation_dispatch(self):
        a=self.api()
        t=a.Transport(profile(),lambda *x:None,execute=True)
        self.assertTrue(hasattr(t,'before_mutation'),'transport late gate missing')
        with self.assertRaises(m.Refusal):t.shell('mutation','payload',mutating=True)
        seen=[]
        def refuse():seen.append('checked');raise m.Refusal('FICTIONAL maintenance expired')
        t.before_mutation=refuse
        with self.assertRaises(m.Refusal):t.shell('mutation','payload',mutating=True)
        self.assertEqual(seen,['checked']);self.assertEqual(t.calls,0)

    def test_package_identity_duplicates_and_splits(self):
        a=self.api()
        self.assertTrue(hasattr(a,'parse_package'),'package identity parser missing')
        good='FICTIONAL-SERIAL-001\n2000\nu:r:shell:s0\nEnforcing\n10123\nversionCode=1 minSdk=28\n userId=10123\n appId=10123\n userId=10123\npackage:/data/app/FICTIONAL/base.apk\n'
        self.assertEqual(a.parse_package(good.encode(),profile())['version'],1)
        for old,new in [('2000\n','0\n'),('u:r:shell:s0','u:r:su:s0'),('Enforcing','Permissive'),
                        ('appId=10123','appId=10124'),('FICTIONAL-SERIAL-001','FICTIONAL-other'),
                        ('package:/data/app/FICTIONAL/base.apk','package:/data/app/FICTIONAL/base.apk\npackage:/data/app/FICTIONAL/split.apk')]:
            with self.subTest(new=new):
                with self.assertRaises(m.Refusal): a.parse_package(good.replace(old,new).encode(),profile())

    def test_control_and_fresh_heartbeat_gate(self):
        a=self.api()
        self.assertTrue(hasattr(a,'validate_control'),'control gates missing')
        prefs=b'<map><boolean name="userStopped" value="false"/><boolean name="safetyPaused" value="false"/><string name="phase">healthy</string></map>'
        lease=b'<map><boolean name="ownedFlag" value="false"/></map>'
        health={'state':'healthy','boot_id':'FICTIONAL-boot','uptime_ms':100000,'watch_pid':101,'child_pid':102}
        a.validate_control(prefs,lease,health,['FICTIONAL-boot','110.0 1.0','0','Enforcing'],False)
        for args in [(prefs.replace(b'false',b'true',1),lease,health,['FICTIONAL-boot','110.0 1.0','0','Enforcing'],False),
                     (prefs,lease.replace(b'false',b'true'),health,['FICTIONAL-boot','110.0 1.0','0','Enforcing'],False),
                     (prefs,lease,health,['FICTIONAL-boot','140.0 1.0','0','Enforcing'],False),
                     (prefs,lease,health,['FICTIONAL-boot','110.0 1.0','1','Enforcing'],False),
                     (prefs,lease,health,['FICTIONAL-boot','110.0 1.0','0','Enforcing'],True)]:
            with self.subTest(args=args):
                with self.assertRaises(m.Refusal): a.validate_control(*args)


if __name__=='__main__': unittest.main()

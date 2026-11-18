import base64
import importlib.util
import json
import os
import shutil
import shlex
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

    def ancestor_fixture(self,path,metadata,anchor=m.APP,symlink=None):
        """Execute the real generated policy with fictional remote stat/type data."""
        a=self.api()
        shell=shutil.which('sh')
        if not shell:self.skipTest('requires host sh for fictional shell-policy fixture')
        cases=[]
        for parent,(mode,uid,gid) in metadata.items():
            cases.append(shlex.quote(parent)+') mode='+mode+'; uid='+str(uid)+'; gid='+str(gid)+' ;;')
        shim='''stat() {
case "$3" in
'''+ '\n'.join(cases)+'''
*) mode=700; uid=10123; gid=10123 ;;
esac
case "$2" in %a) printf '%s' "$mode" ;; %u) printf '%s' "$uid" ;; %g) printf '%s' "$gid" ;; *) return 99 ;; esac
}
fixture_test() {
case "$1" in
-d) return 0 ;;
!) if test "$2" = -L; then test "$3" != '''+shlex.quote(symlink or 'FICTIONAL-no-symlink')+''' ; return; fi ;;
esac
test "$@"
}
'''
        code=a.checked_ancestors(path,anchor,10123).replace('[ ','fixture_test ').replace(' ]','')
        return subprocess.run([shell,'-c',shim+code],capture_output=True)

    def test_android_managed_771_directories_accept_exact_app_owner_and_group(self):
        for parent in (m.APP+'/files',m.APP+'/shared_prefs'):
            with self.subTest(parent=parent):
                result=self.ancestor_fixture(parent+'/FICTIONAL-file',{parent:('771',10123,10123)})
                self.assertEqual(result.returncode,0,result.stderr)

    def test_android_771_exception_rejects_unsafe_identity_mode_scope_and_symlink(self):
        for parent in (m.APP+'/files',m.APP+'/shared_prefs'):
            for meta in [('771',10124,10123),('771',10123,10124),
                         ('773',10123,10123),('777',10123,10123),
                         ('770',10123,10123),('2771',10123,10123)]:
                with self.subTest(parent=parent,meta=meta):
                    self.assertEqual(self.ancestor_fixture(parent+'/FICTIONAL-file',{parent:meta}).returncode,70)
            self.assertEqual(self.ancestor_fixture(parent+'/FICTIONAL-file',
                             {parent:('771',10123,10123)},symlink=parent).returncode,70)
        for parent in (m.APP,m.APP+'/FICTIONAL-unknown',m.APP+'/files/home',
                       m.APP+'/files/home/.android',m.STATE.rstrip('/')):
            with self.subTest(parent=parent):
                self.assertEqual(self.ancestor_fixture(parent+'/FICTIONAL-file',
                                 {parent:('771',10123,10123)}).returncode,70)
        # A caller cannot turn a different anchor into an Android-managed path.
        parent=m.APP+'/files'
        self.assertEqual(self.ancestor_fixture(parent+'/FICTIONAL-file',
                         {parent:('771',10123,10123)},anchor=parent).returncode,70)
        parent='/data/local/tmp/FICTIONAL-base'
        self.assertEqual(self.ancestor_fixture(parent+'/FICTIONAL-file',
                         {parent:('771',10123,10123)},anchor=parent).returncode,70)

    @unittest.skipUnless(os.name=='posix','requires real POSIX modes')
    def test_real_posix_android_managed_directory_modes(self):
        a=self.api()
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-managed-') as temp:
            root=Path(temp);root.chmod(0o700)
            for name in ('files','shared_prefs','FICTIONAL-unknown'):
                (root/name).mkdir(mode=0o771);(root/name).chmod(0o771)
            def run(parent):
                code=a.checked_ancestors(m.APP+'/'+parent+'/FICTIONAL-file',m.APP,os.getuid())
                code=code.replace(m.APP,str(root)).replace('/data/data',str(root.parent)).replace('/data',str(root.parent.parent))
                return subprocess.run([getattr(self,'fixture_shell','sh'),'-c',code],capture_output=True)
            for name in ('files','shared_prefs'):
                self.assertEqual(run(name).returncode,0)
                for mode in (0o773,0o777,0o770):
                    (root/name).chmod(mode)
                    self.assertEqual(run(name).returncode,70)
                (root/name).chmod(0o771)
            self.assertEqual(run('FICTIONAL-unknown').returncode,70)
            (root/'files').rmdir();(root/'files').symlink_to(root/'shared_prefs',target_is_directory=True)
            self.assertEqual(run('files').returncode,70)

    @unittest.skipUnless(os.name=='posix' and shutil.which('mksh'),'requires real mksh and POSIX modes')
    def test_real_mksh_android_managed_directory_modes(self):
        self.fixture_shell=shutil.which('mksh')
        self.test_real_posix_android_managed_directory_modes()

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

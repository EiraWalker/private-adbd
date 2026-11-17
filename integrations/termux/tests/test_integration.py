#!/usr/bin/env python3
"""Linux host fixtures only. No adb, Android device, UID or SELinux acceptance."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
MKSH = os.environ['MKSH']
TOYBOX = os.environ['TOYBOX']
BOOT = '12345678-1234-1234-1234-123456789abc'

class PublisherFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['INTEGRATION_WORK'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app = self.root/'app'
        self.dest = self.app/'files/home/.config/tablet-daemon'
        self.dest.mkdir(parents=True)
        for d in [self.app, *self.dest.parents]:
            if d == self.root: break
            d.chmod(0o700)
        self.dest.chmod(0o700)
        self.clock = self.root/'uptime'
        self.clock.write_text('1000.25 0.00\n')
        self.calls = self.root/'calls'
        runas = self.root/'run-as'
        runas.write_text('#!/bin/sh\nprintf x >>"'+str(self.calls)+'"\n[ ! -e "'+str(self.root/'deny')+'" ] || exit 1\n[ "$1" = com.termux ] || exit 1\nshift\nexec "$@"\n')
        runas.chmod(0o700)
        self.text = ''
        if (SOURCE/'health-publisher.sh').exists():
            self.text = (SOURCE/'health-publisher.sh').read_text().split('# CLI entry.')[0]
            self.text = self.text.replace('/system/bin/run-as',str(runas)).replace('/system/bin/sh',MKSH).replace('/system/bin/toybox',TOYBOX)
            self.text = self.text.replace('/data/data/com.termux',str(self.app)).replace('/proc/uptime',str(self.clock))
        self.tools=self.root/'tools'; self.tools.mkdir(); (self.tools/'toybox').symlink_to(TOYBOX); (self.tools/'cat').symlink_to(TOYBOX)
        self.prefix = self.text.replace('/system/bin/cat',str(self.tools/'cat'))+'\nPATH='+str(self.tools)+':/usr/bin:/bin\nBOOT='+BOOT+'\n'

    def run_shell(self, body):
        r = subprocess.run([MKSH,'-c',self.prefix+body],text=True,capture_output=True,timeout=30)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        return r

class Publisher(PublisherFixture):
    def test_blocked_writer_is_bounded_and_advisory(self):
        runas=self.root/'run-as'
        runas.write_text(runas.read_text().replace('shift\nexec', 'printf "%s\\n" "$@" >"'+str(self.root/'runas.args')+'"\nshift\nexec'))
        blocked=self.root/'blocked-cat'
        completed=self.root/'transfer-completed'
        blocked.write_text('#!/bin/sh\nsleep 6\nprintf finished >"'+str(completed)+'"\n'); blocked.chmod(0o700)
        self.prefix=self.prefix.replace(str(self.tools/'cat'),str(blocked))
        self.run_shell('publish healthy 321 654; printf survived')
        # The transfer must be cancelled before its self-expiring completion,
        # without falsely asserting a deadline for stat/path/exec operations.
        self.assertFalse(completed.exists())
        self.assertEqual(list(self.dest.glob('.health.json.new.*')),[], 'the app shell must survive timeout to clean its owned temp')
        args=(self.root/'runas.args').read_text().splitlines()
        self.assertEqual(args[1:3],[MKSH,'-c'])
        self.assertFalse((self.dest/'health.json').exists())

    def test_protected_writer_publishes_json(self):
        self.run_shell('publish healthy 321 654\n')
        self.assertTrue((self.dest/'health.json').exists(), 'publisher must create health.json')
        self.assertEqual(json.loads((self.dest/'health.json').read_text()),dict(version=1,boot_id=BOOT,uptime_ms=1000250,watch_pid=321,child_pid=654,state='healthy'))
        self.assertEqual((self.dest/'health.json').stat().st_mode & 0o777,0o600)

    def test_long_uptime_throttle_failures_and_validation(self):
        (self.root/'deny').touch()
        self.clock.write_text('30000000.25 0.00\n')
        self.run_shell('''publish healthy 321 654
printf '30000015.24 0.00\\n' >"'''+str(self.clock)+'''"
publish failure 0 0
printf '30000015.25 0.00\\n' >"'''+str(self.clock)+'''"
publish failure 0 0
publish stopped 0 0
''')
        self.assertEqual(self.calls.read_text(),'xx')
        (self.root/'deny').unlink()
        self.run_shell('publish healthy 321 654')
        self.assertEqual(json.loads((self.dest/'health.json').read_text())['uptime_ms'],30000015250)
        self.calls.unlink()
        self.run_shell('publish invalid 1 2; publish healthy "1;sh" 2; BOOT=bad; publish healthy 1 2')
        self.assertFalse(self.calls.exists())

    def test_writer_rejects_unsafe_paths_and_cleans_owned_temp(self):
        sentinel=self.root/'sentinel'; sentinel.write_text('keep')
        target=self.dest/'health.json'
        for kind in ('symlink','hardlink','mode','directory','owner'):
            with self.subTest(kind=kind):
                if kind=='symlink': target.symlink_to(sentinel)
                if kind=='hardlink': os.link(sentinel,target)
                if kind=='mode': target.write_text('old'); target.chmod(0o644)
                if kind=='directory': target.mkdir()
                if kind=='owner': target.write_text('old'); target.chmod(0o600); os.chown(target,12345,12345)
                self.run_shell('publish healthy 321 654')
                self.assertEqual(sentinel.read_text(),'keep')
                if target.is_dir(): target.rmdir()
                else: target.unlink()
        self.dest.chmod(0o755)
        self.run_shell('publish healthy 321 654')
        self.assertFalse(target.exists())
        self.dest.chmod(0o700)
        original=self.prefix
        self.prefix=self.prefix.replace('tmp=.health.json.new.$$', 'tmp=.health.json.new.collision')
        temp=self.dest/'.health.json.new.collision'; temp.write_text('keep')
        self.run_shell('publish healthy 321 654')
        self.assertEqual(temp.read_text(),'keep')
        self.assertFalse(target.exists())
        temp.unlink()
        self.prefix=self.prefix.replace(str(self.tools/'cat')+' >&3 || exit 1','/bin/false >&3 || exit 1')
        self.run_shell('publish healthy 321 654')
        self.assertFalse(temp.exists())
        self.prefix=original
        actual=self.dest.with_name('real'); self.dest.rename(actual); self.dest.symlink_to(actual)
        self.run_shell('publish healthy 321 654')
        self.assertFalse((actual/'health.json').exists())

    def test_manager_status_is_only_source_of_healthy_pids(self):
        status=self.root/'manager.status'; code=self.root/'manager.code'
        manager=self.root/'service.sh'
        manager.write_text('[ "$1" = status ] || exit 99\ncat "'+str(status)+'"\nexit "$(cat "'+str(code)+'")"\n')
        self.prefix+='SERVICE='+str(manager)+'\n'
        bindir=self.root/'bin'; bindir.mkdir(); (bindir/'toybox').symlink_to(TOYBOX)
        self.prefix+='PATH='+str(bindir)+':/usr/bin:/bin\n'
        good=f'watch=exact watch_pid=321 watch_start=12 child=exact child_pid=654 child_start=34 lock=yes failure=no boot={BOOT} uid=2000 context=u:r:shell:s0\n'
        for row,rc,expected in [(good,0,'healthy'),(good,1,'failure'),(good,3,'stopped'),(good.replace('child=exact','child=gate'),0,'failure'),(good.replace(BOOT,'00000000-0000-0000-0000-000000000000'),0,'failure'),(good+'extra\n',0,'failure'),(good.replace('watch_pid=321','watch_pid=03'),0,'failure'),(good.replace('lock=yes','lock=no'),0,'failure'),(good.replace('failure=no','failure=yes'),0,'failure'),(good.replace('uid=2000','uid=0'),0,'failure')]:
            with self.subTest(row=row,rc=rc):
                status.write_text(row); code.write_text(str(rc))
                self.run_shell('sample')
                data=json.loads((self.dest/'health.json').read_text())
                self.assertEqual(data['state'],expected)
                self.assertEqual((data['watch_pid'],data['child_pid']),(321,654) if expected=='healthy' else (0,0))


class PublisherProcess(PublisherFixture):

    def setUp(self):
        super().setUp()
        import shlex
        self.base=self.root/'base'; self.base.mkdir(mode=0o700)
        self.script=self.base/'health-publisher.sh'
        self.bindir=self.root/'bin'; self.bindir.mkdir()
        (self.bindir/'toybox').symlink_to(TOYBOX)
        enforce=self.bindir/'getenforce'; enforce.write_text('#!/bin/sh\necho Enforcing\n'); enforce.chmod(0o700)
        self.hostboot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.context='host-fixture-context'
        context_file=self.root/'context'; context_file.write_text(self.context+'\n')
        text=(SOURCE/'health-publisher.sh').read_text()
        text=text.replace('/system/bin/run-as',str(self.root/'run-as')).replace('/system/bin/sh',MKSH).replace('/system/bin/toybox',TOYBOX).replace('/system/bin/cat',str(self.tools/'cat'))
        text=text.replace('/data/data/com.termux',str(self.app)).replace('/data/local/tmp/private-adbd',str(self.base))
        text=text.replace('PATH=/system/bin:/system/xbin','PATH='+str(self.bindir)+':/usr/bin:/bin')
        text=text.replace('EXPECT_UID=2000','EXPECT_UID='+str(os.getuid())).replace('EXPECT_CONTEXT=u:r:shell:s0','EXPECT_CONTEXT='+shlex.quote(self.context))
        # Test clock only; real /proc identity, argv, starttime and locks remain.
        text=text.replace('/proc/$$/attr/current',str(context_file)).replace('/proc/$p/attr/current',str(context_file))
        text=text.replace('/proc/uptime',str(self.clock))
        self.script.write_text(text); self.script.chmod(0o700)
        self.manager=self.base/'service.sh'
        self.manager.write_text('[ "$1" = status ] || exit 99\ncat "'+str(self.root/'manager.status')+'"\nexit "$(cat "'+str(self.root/'manager.code')+'")"\n'); self.manager.chmod(0o700)
        (self.root/'manager.status').write_text(f'watch=exact watch_pid=321 watch_start=12 child=exact child_pid=654 child_start=34 lock=yes failure=no boot={self.hostboot} uid={os.getuid()} context={self.context}\n')
        (self.root/'manager.code').write_text('0')
        self.pidfd=None
        self.addCleanup(self.cleanup_watch)

    def call(self,cmd):
        return subprocess.run([MKSH,str(self.script),cmd],capture_output=True,text=True,timeout=12)

    def cleanup_watch(self):
        import signal
        if self.pidfd is not None:
            try: signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
            except ProcessLookupError: pass
            os.close(self.pidfd); self.pidfd=None
        # An owned, newly created fixture dir: verify no live argv points into it.
        import time
        for _ in range(30):
            live=[]
            for proc in Path('/proc').glob('[0-9]*'):
                try:
                    argv=(proc/'cmdline').read_bytes().split(b'\0')
                    state=(proc/'stat').read_text().rsplit(') ',1)[1].split()[0]
                    if state!='Z' and str(self.script).encode() in argv: live.append(proc.name)
                except OSError: pass
            if not live: return
            time.sleep(.1)
        self.fail('live fixture processes: '+','.join(live))

    def capture_handle(self):
        # Open the pidfd before tests can kill or corrupt any state; no raw kills.
        record=(self.base/'health.watch').read_text().split()
        pid=int(record[0]); self.pidfd=os.pidfd_open(pid)
        self.assertIn(str(self.script).encode(),Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0'))
        return pid

    def await_health(self,predicate):
        import time
        until=time.monotonic()+8
        while time.monotonic()<until:
            try:
                data=json.loads((self.dest/'health.json').read_text())
                if predicate(data): return data
            except (OSError,ValueError): pass
            time.sleep(.05)
        self.fail('health predicate timed out')

    def test_invalid_boot_record_is_not_reconciled_as_dead(self):
        record=self.base/'health.watch'; original='999999 1 bad-boot\n'
        record.write_text(original); record.chmod(0o600)
        r=self.call('ensure')
        if r.returncode==0 and record.exists(): self.capture_handle()
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertEqual(record.read_text(),original)

    def test_concurrent_ensure_keeps_one_exact_publisher(self):
        calls=[subprocess.Popen([MKSH,str(self.script),'ensure'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(4)]
        results=[(p.communicate(timeout=12),p.returncode) for p in calls]
        self.capture_handle()
        self.assertTrue(any(code==0 for _,code in results),results)
        self.assertTrue(all(code in (0,2) for _,code in results),results)
        live=[]
        for p in Path('/proc').glob('[0-9]*'):
            try:
                argv=(p/'cmdline').read_bytes().split(b'\0')
                fields=(p/'stat').read_text().rsplit(') ',1)[1].split()
                # mksh command-substitution forks temporarily inherit argv.
                # Detached publishers, unlike these helpers, are SID leaders.
                if argv==[MKSH.encode(),str(self.script).encode(),b'watch',b''] and fields[3]==p.name and fields[0]!='Z': live.append(p.name)
            except OSError: pass
        self.assertEqual(len(live),1)
        self.assertEqual(self.call('status').returncode,0)

    def test_stop_only_terminates_exact_publisher(self):
        r=self.call('ensure'); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.capture_handle()
        self.await_health(lambda h:h['state']=='healthy')
        r=self.call('stop'); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(self.call('status').returncode,1)
        self.assertFalse((self.base/'health.watch').exists())
        self.assertEqual((self.root/'manager.code').read_text(),'0')
        self.assertEqual(self.call('stop').returncode,0)

    def test_live_mismatched_record_never_signalled_or_overwritten(self):
        sleeper=subprocess.Popen(['/bin/sleep','30'])
        self.addCleanup(sleeper.wait)
        self.addCleanup(lambda: sleeper.poll() is None and sleeper.kill())
        stamp=Path(f'/proc/{sleeper.pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
        record=self.base/'health.watch'; original=f'{sleeper.pid} {stamp} {self.hostboot}\n'
        record.write_text(original); record.chmod(0o600)
        self.assertEqual(self.call('ensure').returncode,2)
        self.assertEqual(self.call('stop').returncode,2)
        self.assertIsNone(sleeper.poll())
        self.assertEqual(record.read_text(),original)

    def test_real_core_watch_death_cannot_refresh_healthy(self):
        # Reuse the frozen lifecycle's real /proc/ELF/lock fixture; no core edits.
        import importlib.util
        import signal
        path=SOURCE.parents[1]/'lifecycle/tests/test_service.py'
        spec=importlib.util.spec_from_file_location('integration_core_fixture',path)
        fixture=importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        fixture.SHELL=MKSH; fixture.TOYBOX=TOYBOX
        previous=os.environ.get('FIXTURE_WORK'); os.environ['FIXTURE_WORK']=os.environ['INTEGRATION_WORK']
        def restore():
            if previous is None: os.environ.pop('FIXTURE_WORK',None)
            else: os.environ['FIXTURE_WORK']=previous
        self.addCleanup(restore)
        core=fixture.ServiceTests()
        def cleanup_core():
            import shutil
            core.doCleanups()
            if hasattr(core,'root'): shutil.rmtree(core.root,ignore_errors=True)
        self.addCleanup(cleanup_core)
        core.setUp()
        source=core.script.read_text().replace('ps -A -o PID,NAME','ps -A -o pid=,comm=')
        core.script.write_text(source)
        self.script.write_text(self.script.read_text().replace('SERVICE=$BASE/service.sh','SERVICE='+str(core.script)).replace('EXPECT_CONTEXT=host-fixture-context','EXPECT_CONTEXT=fixture-context'))
        (self.root/'context').write_text('fixture-context\n')
        r=core.call('start'); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        core.await_running()
        r=self.call('ensure'); self.assertEqual(r.returncode,0,r.stdout+r.stderr); self.capture_handle()
        data=self.await_health(lambda h:h['state']=='healthy')
        self.assertEqual(data['watch_pid'],int((core.base/'v2.watch').read_text().split()[0]))
        self.assertEqual(data['child_pid'],int((core.base/'v2.child').read_text().split()[0]))
        core.signal_record('watch',signal.SIGKILL)
        self.clock.write_text('1015.25 0.00\n')
        self.await_health(lambda h:h['state']=='failure')
        self.assertEqual(len((core.base/'launches').read_text().splitlines()),1)
        self.assertTrue(core.is_alive(data['child_pid']))
        self.assertEqual(core.call('stop').returncode,0)
        self.clock.write_text('1030.25 0.00\n')
        self.await_health(lambda h:h['state']=='stopped')

    def test_detached_singleton_restart_and_staleness(self):
        import signal
        import time
        r=self.call('ensure'); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertTrue((self.base/'health.watch').exists(),'ensure must detach a recorded publisher')
        first=self.capture_handle()
        self.await_health(lambda h:h['state']=='healthy')
        r=self.call('ensure'); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(int((self.base/'health.watch').read_text().split()[0]),first)
        self.assertEqual(self.call('status').returncode,0)
        self.clock.write_text('1015.25 0.00\n')
        self.await_health(lambda h:h['uptime_ms']==1015250)
        (self.root/'manager.code').write_text('1')
        self.clock.write_text('1030.25 0.00\n')
        self.await_health(lambda h:h['state']=='failure')
        signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
        os.close(self.pidfd); self.pidfd=None
        time.sleep(.3)
        before=(self.dest/'health.json').read_bytes()
        self.clock.write_text('1060.25 0.00\n'); time.sleep(1.2)
        self.assertEqual((self.dest/'health.json').read_bytes(),before)
        self.assertNotEqual(self.call('status').returncode,0)
        r=self.call('ensure'); self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.capture_handle()
        self.await_health(lambda h:h['uptime_ms']==1060250)


class Wrapper(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ['INTEGRATION_WORK']); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.app=self.root/'app'
        self.home=self.app/'files/home'; self.prefix=self.app/'files/usr'
        self.state=self.home/'.config/tablet-daemon'
        (self.prefix/'bin').mkdir(parents=True); self.state.mkdir(parents=True)
        for d in [self.app,self.app/'files',self.home,self.home/'.config',self.state,self.prefix,self.prefix/'bin']: d.chmod(0o700)
        (self.state/'device.serial').write_text('test-serial\n'); (self.state/'device.serial').chmod(0o600)
        self.adblog=self.root/'adb.jsonl'
        shim=self.prefix/'bin/adb'
        shim.write_text('''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
root=Path(__file__).resolve().parents[4]
args=sys.argv[1:]
try: os.fstat(9); fd9=True
except OSError: fd9=False
with (root/'adb.jsonl').open('a') as f: f.write(json.dumps(dict(args=args,fd9=fd9,home=os.environ.get('HOME'),keys=os.environ.get('ADB_VENDOR_KEYS'),mdns=os.environ.get('ADB_MDNS_AUTO_CONNECT')))+'\\n')
if 'keygen' in args:
 p=Path(args[-1]); p.write_text('fixture-key-not-cryptographic'); p.chmod(0o600); p.with_suffix('.pub').write_text('fixture-public'); p.with_suffix('.pub').chmod(0o600)
elif 'get-state' in args: print('device')
elif 'shell' in args:
 command=args[-1]
 if command=='ro.serialno' or command=='getprop ro.serialno': print((root/'actual.serial').read_text().strip())
 elif command=='-u' or command=='id -u': print((root/'actual.uid').read_text().strip())
 elif 'start' in command: sys.exit(int((root/'remote.code').read_text()))
'''); shim.chmod(0o700)
        (self.root/'actual.serial').write_text('test-serial\n')
        (self.root/'actual.uid').write_text('2000\n')
        (self.root/'remote.code').write_text('0')
        self.script=self.root/'private-adbd'
        text=(SOURCE/'private-adbd').read_text() if (SOURCE/'private-adbd').exists() else 'echo missing-wrapper >&2; exit 127\n'
        text=text.replace('/data/data/com.termux',str(self.app))
        text=text.replace('export PATH="$PREFIX/bin:/system/bin"','export PATH="$PREFIX/bin:/usr/bin:/bin"')
        self.script.write_text(text)

    def call(self,*args,extra=None):
        env=dict(os.environ)
        env.pop('TABLET_DAEMON_EXPECTED_SERIAL',None)
        if extra: env.update(extra)
        return subprocess.run(['/bin/bash',str(self.script),*args],capture_output=True,text=True,env=env,timeout=10)

    def rows(self):
        return [json.loads(line) for line in self.adblog.read_text().splitlines()] if self.adblog.exists() else []

    def test_pair_and_status_never_dispatch_start(self):
        self.assertEqual(self.call('pair','37002').returncode,0)
        rows=self.rows(); pair=[row['args'] for row in rows if 'pair' in row['args']]
        self.assertEqual(len(pair),1); self.assertEqual(pair[0][-1],'127.0.0.1:37002')
        self.assertFalse((self.state/'port').exists())
        self.adblog.unlink()
        self.assertEqual(self.call('status','37001').returncode,0)
        self.assertFalse(any('service.sh start' in a for row in self.rows() for a in row['args']))
        self.assertTrue(all(not row['fd9'] for row in self.rows()))
        for port in ('0','65536','-1','37001;id','127.0.0.1:37001'):
            self.assertEqual(self.call('start',port).returncode,2)

    def test_start_verifies_identity_then_single_fixed_mutation(self):
        r=self.call('start','37001',extra={'TABLET_DAEMON_EXPECTED_SERIAL':'test-serial'})
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        rows=self.rows(); commands=[row['args'] for row in rows]
        self.assertTrue(any('ro.serialno' in a or 'getprop ro.serialno' in a for a in commands))
        self.assertTrue(any('id -u' in a or '-u' in a for a in commands))
        mutations=[a for a in commands if any('service.sh start' in v for v in a)]
        self.assertEqual(len(mutations),1)
        self.assertEqual(mutations[0][-1],'/system/bin/sh /data/local/tmp/private-adbd/service.sh start && /system/bin/sh /data/local/tmp/private-adbd/health-publisher.sh ensure')
        self.assertTrue(all(not row['fd9'] for row in rows))
        for row in rows:
            self.assertEqual(row['mdns'],'0')
            self.assertTrue(row['keys'].startswith(str(self.state)+'/'))
        self.assertTrue(any('tcp:localhost:5038' in a for a in commands))
        self.assertTrue(all(not any('27184' in v or '5555' in v for v in a) for a in commands))

    def test_environment_cannot_reenable_auto_scan_or_move_key_home(self):
        shim=self.prefix/'bin/adb'
        text=shim.read_text().replace("mdns=os.environ.get('ADB_MDNS_AUTO_CONNECT')", "mdns=os.environ.get('ADB_MDNS_AUTO_CONNECT'),maxport=os.environ.get('ADB_LOCAL_TRANSPORT_MAX_PORT'),android_home=os.environ.get('ANDROID_USER_HOME'),sdk_home=os.environ.get('ANDROID_SDK_HOME')")
        shim.write_text(text)
        r=self.call('start','37001',extra={'ADB_LOCAL_TRANSPORT_MAX_PORT':'65535','ANDROID_USER_HOME':'/hostile','ANDROID_SDK_HOME':'/hostile'})
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        for row in self.rows():
            self.assertEqual(row['maxport'],'0')
            self.assertNotEqual(row['android_home'],'/hostile')
            self.assertNotEqual(row['sdk_home'],'/hostile')

    def test_noncanonical_serial_and_identity_mismatch_never_mutate(self):
        path=self.state/'device.serial'
        for raw in [b'',b'test-serial',b'test-serial\nextra',b'test-serial\nextra\n',b'test-serial\0\n',b'test-serial\r\n',b'bad;cmd\n',b'a'*129+b'\n']:
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                self.assertEqual(self.call('start','37001').returncode,2)
                self.assertEqual(self.rows(),[])
        path.write_text('test-serial\n')
        for field,value in [('actual.serial','wrong-device'),('actual.uid','0')]:
            original=(self.root/field).read_text(); (self.root/field).write_text(value+'\n')
            self.assertEqual(self.call('start','37001').returncode,2)
            self.assertFalse(any('service.sh start' in a for row in self.rows() for a in row['args']))
            (self.root/field).write_text(original); self.adblog.unlink()
        self.assertEqual(self.call('start','37001',extra={'TABLET_DAEMON_EXPECTED_SERIAL':'other-device'}).returncode,2)
        self.assertEqual(self.rows(),[])

    def test_ambiguous_dispatch_survives_wrapper_death_without_replay(self):
        import time
        shim=self.prefix/'bin/adb'
        shim.write_text(shim.read_text().replace("elif 'start' in command: sys.exit", "elif 'start' in command:\n  import time; time.sleep(1.5)\n  sys.exit"))
        p=subprocess.Popen(['/bin/bash',str(self.script),'start','37001'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: p.poll() is None and p.kill())
        end=time.monotonic()+5
        while time.monotonic()<end and not any('service.sh start' in a for row in self.rows() for a in row['args']): time.sleep(.02)
        self.assertIsNone(p.poll(),'wrapper should be awaiting mutating dispatch')
        p.kill(); p.wait(timeout=3)
        time.sleep(1.7)  # the bounded native shim exits itself, never killed by PID
        r=self.call('start','37001')
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertEqual(sum('service.sh start' in a for row in self.rows() for a in row['args']),1)
        self.assertTrue((self.state/'start.pending').exists())
        self.assertEqual(self.call('reconcile','37001').returncode,0)
        self.assertFalse((self.state/'start.pending').exists())

    def test_mutating_failure_is_safety_pause_not_replay(self):
        for code in (1,2,4,124,255):
            with self.subTest(code=code):
                (self.root/'remote.code').write_text(str(code))
                r=self.call('start','37001'); self.assertEqual(r.returncode,2,r.stdout+r.stderr)
                self.assertEqual(sum('service.sh start' in a for row in self.rows() for a in row['args']),1)
                self.assertEqual(self.call('start','37001').returncode,2)
                self.assertEqual(sum('service.sh start' in a for row in self.rows() for a in row['args']),1)
                self.assertEqual(self.call('reconcile','37001').returncode,0)
                self.adblog.unlink()

if __name__ == '__main__': unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Linux fixture only: no adb/device/network; production source is transformed in a private fixture."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1]
SHELL = os.environ.get('FIXTURE_SHELL', '/bin/dash')
TOYBOX = os.environ.get('FIXTURE_TOYBOX')

class ServiceTests(unittest.TestCase):
    def setUp(self):
        # The runner supplies an isolated Linux-permission fixture directory.
        self.root = Path(tempfile.mkdtemp(prefix='case-', dir=os.environ['FIXTURE_WORK']))
        self.base = self.root / 'service'
        self.base.mkdir(mode=0o700)
        self.addCleanup(self.cleanup)
        self.assertTrue((SOURCE / 'service.sh').is_file(), 'public lifecycle/service.sh is missing')
        source = (SOURCE / 'service.sh').read_text()
        self.script = self.base / 'service.sh'
        source = source.replace('/data/local/tmp/private-adbd', str(self.base))
        source = source.replace('SH=/system/bin/sh', 'SH=' + SHELL)
        source = source.replace('PATH=/system/bin:/system/xbin', f'PATH={self.root}/bin:/usr/bin:/bin')
        source = source.replace('EXPECT_UID=2000', f'EXPECT_UID={os.getuid()}')
        source = source.replace('EXPECT_CONTEXT=u:r:shell:s0', 'EXPECT_CONTEXT=fixture-context')
        source = source.replace('cat /proc/$$/attr/current', 'printf fixture-context')
        source = source.replace('cat "/proc/$p/attr/current"', 'printf fixture-context')
        self.script.write_text(source)
        self.script.chmod(0o700)
        bindir = self.root / 'bin'
        bindir.mkdir()
        for name, body in {
            'getprop': 'cat "' + str(self.root / 'serial') + '"',
            'getenforce': 'echo Enforcing',
            'toybox': ('exec "' + TOYBOX + '" "$@"') if TOYBOX else 'exec "$@"',
        }.items():
            target = bindir / name
            target.write_text('#!/bin/sh\n' + body + '\n')
            target.chmod(0o700)
        if TOYBOX:
            applets = subprocess.check_output([TOYBOX], text=True).split()
            for name in ('stat', 'readlink', 'od', 'tr', 'wc', 'cat', 'date', 'mv', 'rm', 'grep', 'sleep', 'id', 'awk'):
                if name in applets:
                    target = bindir / name
                    target.write_text('#!/bin/sh\nexec "' + TOYBOX + '" ' + name + ' "$@"\n')
                    target.chmod(0o700)
        (self.root / 'serial').write_text('FIXTURE-SERIAL-001\n')
        (self.base / 'service.serial').write_text('FIXTURE-SERIAL-001\n')
        (self.base / 'service.serial').chmod(0o600)
        (self.base / 'authorized_keys').write_text('fixture public key placeholder, not device keys\n')
        (self.base / 'authorized_keys').chmod(0o600)
        # Real copied ELF, not a shell PID masquerading as /proc/exe.
        shutil.copyfile('/usr/bin/python3', self.base / 'private-adbd')
        (self.base / 'private-adbd').chmod(0o700)
        # Python argv recognizes --keys as an invalid option; replace fixture daemon
        # command only, keeping original source identity/proc/lock logic intact.
        daemon = self.base / 'fixture.py'
        daemon.write_text('import os,time,sys\np=os.path.dirname(__file__)\nopen(p+"/launches","a").write(str(os.getpid())+"\\n")\nmode=open(p+"/mode").read().strip()\nif mode.startswith("exit"):\n time.sleep(.3); sys.exit(int(mode[4:]))\nend=time.monotonic()+180\nwhile time.monotonic()<end: time.sleep(.2)\n')
        source = self.script.read_text().replace('"$DAEMON" --keys "$KEYS" --serial "$SERIAL"', '"$DAEMON" "$BASE/fixture.py" --keys "$KEYS" --serial "$SERIAL"')

        self.script.write_text(source.replace('watch 7>&- </dev/null >/dev/null 2>&1 &', 'watch 7>&- </dev/null >>"$BASE/watch-debug.log" 2>&1 &'))
        (self.base / 'mode').write_text('run')

    def tearDown(self):
        snapshot = {'test': self.id(), 'files': {}}
        for f in self.base.iterdir():
            if f.is_file() and not f.is_symlink() and (f.name.startswith('v2.') or f.name in ('launches', 'watch-debug.log')):
                snapshot['files'][f.name] = f.read_text()
        with (Path(os.environ['FIXTURE_EVIDENCE']) / 'diagnostics.jsonl').open('a') as out:
            out.write(json.dumps(snapshot) + '\n')

    def call(self, verb, timeout=20):
        return subprocess.run([SHELL, str(self.script), verb], capture_output=True, text=True, timeout=timeout)

    def cleanup(self):
        if not getattr(self, 'script', None):
            return
        if self.script.exists():
            self.call('stop')
        # Acquire a stable pidfd before inspecting argv; never signal a reused PID.
        for proc in Path('/proc').glob('[0-9]*'):
            try:
                fd = os.pidfd_open(int(proc.name))
                try:
                    cmd = (proc / 'cmdline').read_bytes().split(b'\0')
                    if str(self.script).encode() in cmd or str(self.base / 'fixture.py').encode() in cmd:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                finally:
                    os.close(fd)
            except (OSError, ProcessLookupError):
                pass

    def signal_record(self, role, signum):
        fields = (self.base / ('v2.' + role)).read_text().split()
        pid = int(fields[0])
        fd = os.pidfd_open(pid)
        try:
            proc = Path('/proc', str(pid))
            self.assertEqual(proc.joinpath('stat').read_text().rsplit(') ', 1)[1].split()[19], fields[1])
            self.assertEqual(proc.joinpath('cmdline').read_bytes().hex(), fields[4])
            self.assertEqual(os.readlink(proc / 'exe').encode().hex(), fields[3])
            signal.pidfd_send_signal(fd, signum)
        finally:
            os.close(fd)

    def await_running(self):
        end = time.monotonic() + 15
        while time.monotonic() < end:
            r = self.call('status')
            if r.returncode == 0:
                return r.stdout
            time.sleep(.1)
        self.fail('no running status: ' + r.stdout + r.stderr)

    def test_start_is_idempotent_and_stop_releases_lock(self):
        r = self.call('start')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        first = self.await_running()
        self.assertEqual(self.call('start').returncode, 0)
        self.assertEqual(first, self.call('status').stdout)
        self.assertEqual(self.call('stop').returncode, 0)
        self.assertEqual(self.call('status').returncode, 3)

    def test_concurrent_start_has_one_watch_and_child(self):
        calls = [subprocess.Popen([SHELL, str(self.script), 'start'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
        results = [(p.communicate(timeout=30), p.returncode) for p in calls]
        self.assertTrue(all(code == 0 for _, code in results), results)
        self.await_running()
        self.assertEqual(len((self.base / 'launches').read_text().splitlines()), 1)

    def test_wrong_uid_serial_context_and_enforcement_fail_before_write(self):
        original = self.script.read_text()
        for before, after in [('EXPECT_UID=' + str(os.getuid()), 'EXPECT_UID=42424'),
                              ('EXPECT_CONTEXT=fixture-context', 'EXPECT_CONTEXT=wrong-context')]:
            self.script.write_text(original.replace(before, after))
            self.assertEqual(self.call('start').returncode, 2)
            self.assertEqual(list(self.base.glob('v2.*')), [])
        self.script.write_text(original)
        (self.root / 'serial').write_text('wrong-device\n')
        self.assertEqual(self.call('start').returncode, 2)
        self.assertEqual(list(self.base.glob('v2.*')), [])
        (self.root / 'serial').write_text('FIXTURE-SERIAL-001\n')
        (self.root / 'bin/getenforce').write_text('#!/bin/sh\necho Permissive\n')
        self.assertEqual(self.call('start').returncode, 2)
        self.assertEqual(list(self.base.glob('v2.*')), [])

    def test_symlink_hardlink_and_unsafe_mode_are_rejected(self):
        victim = self.root / 'untouched'
        victim.write_text('sentinel')
        for name in ['v2.watch.lock', 'v2.child', 'v2.current.log', 'v2.go.tmp', 'authorized_keys', 'service.serial']:
            target = self.base / name
            original = target.read_bytes() if target.exists() else None
            if target.exists(): target.unlink()
            target.symlink_to(victim)
            self.assertEqual(self.call('start').returncode, 2, name)
            self.assertEqual(victim.read_text(), 'sentinel')
            target.unlink()
            if original is not None:
                target.write_bytes(original); target.chmod(0o600)
        os.link(victim, self.base / 'v2.child')
        self.assertEqual(self.call('start').returncode, 2)
        (self.base / 'v2.child').unlink()
        self.base.chmod(0o777)
        self.assertEqual(self.call('start').returncode, 2)
        self.base.chmod(0o700)

    def test_killed_watch_reclaims_exact_surviving_child(self):
        self.assertEqual(self.call('start').returncode, 0)
        self.await_running()
        watch = (self.base / 'v2.watch').read_text().split()
        old = (self.base / 'v2.child').read_text().split()
        self.signal_record('watch', signal.SIGKILL)
        self.assertTrue(Path('/proc', old[0]).exists())
        r = self.call('start')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.await_running()
        new = (self.base / 'v2.child').read_text().split()
        self.assertNotEqual(new[:2], old[:2])
        self.assertEqual(len((self.base / 'launches').read_text().splitlines()), 2)
        self.assertFalse(self.is_alive(int(old[0])))
        self.assertEqual(self.call('stop').returncode, 0)

    @staticmethod
    def is_alive(pid):
        try:
            return Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()[0] != 'Z'
        except FileNotFoundError:
            return False

    def test_killed_child_restarts_with_bounded_backoff(self):
        self.assertEqual(self.call('start').returncode, 0)
        self.await_running()
        old = (self.base / 'v2.child').read_text().split()
        wp = (self.base / 'v2.watch').read_text()
        self.signal_record('child', signal.SIGKILL)
        end = time.monotonic() + 12
        while time.monotonic() < end:
            if (self.base / 'launches').exists() and len((self.base / 'launches').read_text().splitlines()) == 2:
                break
            time.sleep(.1)
        self.await_running()
        self.assertNotEqual((self.base / 'v2.child').read_text().split()[:2], old[:2])
        self.assertEqual((self.base / 'v2.watch').read_text(), wp)
        self.assertIn('backoff seconds=1 retry=1', (self.base / 'v2.current.log').read_text())

    def test_exit2_latches_without_retry_and_restart_is_explicit(self):
        (self.base / 'mode').write_text('exit2')
        r = self.call('start')
        end = time.monotonic() + 10
        while time.monotonic() < end and not (self.base / 'v2.failure').exists(): time.sleep(.1)
        self.assertTrue((self.base / 'v2.failure').exists(), r.stdout + r.stderr)
        time.sleep(2)
        self.assertEqual(len((self.base / 'launches').read_text().splitlines()), 1)
        self.assertEqual(self.call('start').returncode, 2)
        self.assertEqual(self.call('status').returncode, 2)
        (self.base / 'mode').write_text('run')
        self.assertEqual(self.call('restart').returncode, 0)
        self.await_running()

    def test_retry_budget_stops_after_six_launches(self):
        (self.base / 'mode').write_text('exit1')
        self.call('start')
        end = time.monotonic() + 80
        while time.monotonic() < end and not (self.base / 'v2.failure').exists(): time.sleep(.2)
        self.assertTrue((self.base / 'v2.failure').exists())
        self.assertEqual(len((self.base / 'launches').read_text().splitlines()), 6)
        self.assertEqual((self.base / 'v2.failure').read_text(), 'exit=1 retries=5\n')

    def test_live_stale_pid_is_never_signalled(self):
        sleeper = subprocess.Popen(['/bin/sleep', '120'])
        self.addCleanup(sleeper.kill)

        # Obtain valid policy fields from an owned running instance, then stop it.
        self.assertEqual(self.call('start').returncode, 0)
        self.await_running()
        fields = (self.base / 'v2.child').read_text().split()
        self.assertEqual(self.call('stop').returncode, 0)
        fields[0] = str(sleeper.pid)
        fields[1] = Path('/proc', str(sleeper.pid), 'stat').read_text().rsplit(') ', 1)[1].split()[19]
        (self.base / 'v2.child').write_text(' '.join(fields) + '\n')
        (self.base / 'v2.child').chmod(0o600)
        self.assertEqual(self.call('status').returncode, 4)
        self.assertNotEqual(self.call('start').returncode, 0)
        self.assertEqual(self.call('stop').returncode, 2)
        self.assertIsNone(sleeper.poll())
        (self.base / 'v2.child').unlink()
        sleeper.kill(); sleeper.wait()


    def test_old_run_lock_is_untouched(self):
        old = self.base / 'run.lock'
        old.mkdir()
        (old / 'supervisor.pid').write_text('unknown-sentinel\n')
        (old / 'child.pid').symlink_to(self.root / 'missing')
        self.assertEqual(self.call('start').returncode, 0)
        self.await_running()
        self.assertEqual(self.call('stop').returncode, 0)
        self.assertEqual((old / 'supervisor.pid').read_text(), 'unknown-sentinel\n')
        self.assertTrue((old / 'child.pid').is_symlink())

    def kill_watch_during_gate(self, phase):
        text = self.script.read_text()
        if phase == 'before-publication':
            anchor = 'mine=$(stamp "$$") || fail \'child starttime unavailable\''
        else:
            anchor = 'exec 8>&-\n n=0\n while [ "$n" -lt 15 ]; do'
        replacement = 'printf ready >"$BASE/gate-window"\n sleep 2\n ' + anchor
        self.assertIn(anchor, text)
        self.script.write_text(text.replace(anchor, replacement, 1))
        pending = subprocess.Popen([SHELL, str(self.script), 'start'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: pending.kill() if pending.poll() is None else None)
        end = time.monotonic() + 10
        while time.monotonic() < end and not (self.base / 'gate-window').exists(): time.sleep(.02)
        self.assertTrue((self.base / 'gate-window').exists())
        wp = int((self.base / 'v2.watch').read_text().split()[0])
        self.signal_record('watch', signal.SIGKILL)
        out, err = pending.communicate(timeout=30)
        self.assertEqual(pending.returncode, 0, out + err)
        self.await_running()
        self.assertEqual(len((self.base / 'launches').read_text().splitlines()), 1)

    def test_kill_during_birth_before_state_publication(self):
        self.kill_watch_during_gate('before-publication')

    def test_kill_during_birth_after_state_publication(self):
        self.kill_watch_during_gate('after-publication')

    def test_child_does_not_inherit_any_lock_fd(self):
        self.assertEqual(self.call('start').returncode, 0)
        self.await_running()
        pid = (self.base / 'v2.child').read_text().split()[0]
        links = []
        for f in Path('/proc', pid, 'fd').iterdir():
            try: links.append(os.readlink(f))
            except OSError: pass
        self.assertFalse(any(x.endswith('.lock') for x in links), links)

    def test_dead_pid_and_old_boot_are_recoverable_without_signal(self):
        self.assertEqual(self.call('start').returncode, 0)
        self.await_running()
        fields = (self.base / 'v2.child').read_text().split()
        self.assertEqual(self.call('stop').returncode, 0)
        for old_boot in (False, True):
            sleeper = subprocess.Popen(['/bin/sleep', '30'])
            try:
                fields[0] = str(sleeper.pid) if old_boot else '2147483647'
                fields[2] = '00000000-0000-0000-0000-000000000000' if old_boot else Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                (self.base / 'v2.child').write_text(' '.join(fields) + '\n')
                (self.base / 'v2.child').chmod(0o600)
                self.assertEqual(self.call('start').returncode, 0)
                self.await_running()
                self.assertIsNone(sleeper.poll())
                self.assertEqual(self.call('stop').returncode, 0)
            finally:
                sleeper.kill(); sleeper.wait()

    def test_untracked_daemon_is_refused_not_killed(self):
        proc = subprocess.Popen([str(self.base / 'private-adbd'), str(self.base / 'fixture.py'), '--keys', str(self.base / 'authorized_keys'), '--serial', 'FIXTURE-SERIAL-001'])
        try:
            time.sleep(.2)
            r = self.call('watch')
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn('untracked daemon', r.stderr)
            self.assertIsNone(proc.poll())
        finally:
            proc.kill(); proc.wait()

    def test_logs_are_bounded_and_keys_unchanged(self):
        before = (self.base / 'authorized_keys').read_bytes()
        for name, data in [('v2.current.log', 'A' * 32600), ('v2.previous.log', 'old')]:
            (self.base / name).write_text(data)
            (self.base / name).chmod(0o600)
        self.assertEqual(self.call('start').returncode, 0)
        self.await_running()
        self.assertEqual(self.call('stop').returncode, 0)
        self.assertLessEqual((self.base / 'v2.current.log').stat().st_size, 32768)
        self.assertEqual((self.base / 'v2.previous.log').stat().st_size, 32600)
        self.assertEqual((self.base / 'authorized_keys').read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.base.glob('*.log')), ['v2.current.log', 'v2.previous.log', 'watch-debug.log'])

if __name__ == '__main__':
    unittest.main(verbosity=2)

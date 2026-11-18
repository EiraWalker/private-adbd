import copy
import datetime as dt
import unittest
from test_installer import profile
import installer as m

NOW = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)


def maintenance():
    return {'schema': 1, 'profile_sha256': '0'*64, 'release_sha256': '1'*64,
            'serial': 'FICTIONAL-SERIAL-001', 'owner': 'FICTIONAL-owner-session',
            'ready': True, 'released': True, 'no_parallel': True,
            'issued_at': NOW.isoformat(), 'expires_at': (NOW+dt.timedelta(minutes=10)).isoformat()}


class MaintenanceTests(unittest.TestCase):
    def test_maintenance_binds_actual_owner_and_short_window(self):
        self.assertTrue(hasattr(m,'validate_maintenance'), 'maintenance gate missing')
        m.validate_maintenance(maintenance(), '0'*64, '1'*64, profile()['serial'], now=NOW)
        for key, value in [('ready',False),('released',False),('no_parallel',False),('owner',''),
                           ('profile_sha256','2'*64),('release_sha256','3'*64),('serial','FICTIONAL-other'),
                           ('issued_at','2030-01-01T00:00:00'),('expires_at','2030-01-01T01:00:00+00:00'),
                           ('expires_at',NOW.isoformat()),('unknown',True)]:
            with self.subTest(key=key):
                obj=maintenance(); obj[key]=value
                with self.assertRaises(m.Refusal):
                    m.validate_maintenance(obj, '0'*64, '1'*64, profile()['serial'], now=NOW)


# Fictional host subprocess/transport coverage, NOT Android acceptance.
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from types import SimpleNamespace
from test_local import SCRATCH, release, digest
from test_cli import OfflineSDK
from android import AndroidRemote, Transport
from common import Refusal
from installer import Inputs
from upgrade import Authorization

BOOT = '00000000-0000-0000-0000-000000000001'
APK = '/data/app/FICTIONAL/base.apk'
PRODUCER = r'''
import json, re, shlex, sys, os
mode, operation, command = sys.argv[1:]
assert operation == 'shell'
outer = shlex.split(command)
assert outer[:4] == ['run-as', 'com.termux', '/system/bin/sh', '-c']
assert len(outer) == 5
code = outer[4]
verb = re.search(r'com.termux.app.privateadb.MaintenanceCli (request|status|release)', code).group(1)
raw = sys.stdin.buffer.read()
if mode == 'timeout': __import__('time').sleep(1)
assert len(raw) <= 2048
p = json.loads(raw)
assert p['token'] not in command
if verb == 'request':
    assert len(p) == 8
    request = p
else:
    assert set(p) == {'version', 'token'}
    request = json.loads(os.environ['FICTIONAL_MAINTENANCE_REQUEST'])
result = dict(request, ownerUid=10123,
              phase='released' if verb == 'release' else ('pending' if mode == 'pending' else 'active'))
if mode == 'released': result['phase'] = 'released'
sys.stdout.buffer.write((json.dumps(result) + '\n').encode('ascii'))
'''


class HostTransport(Transport):
    """Actual Transport.call child stdin/argv; no ADB/Android process."""
    def __init__(self, p):
        super().__init__(p, lambda *args: None, execute=True)
        self.mode = 'active'
        self.response = None
        self.timeout_override = None
        self.ipcs = []
        self.clock = (BOOT+'\n100.00 100.00\n'+BOOT+'\n').encode()
        self.before_mutation = lambda: (_ for _ in ()).throw(AssertionError('recursive guard'))

    def command(self, args):
        return [sys.executable, '-c', PRODUCER, self.mode, *args]

    def shell(self, code, label, data=None, mutating=False, timeout=45):
        if label == 'clock': return self.clock
        return super().shell(code, label, data, mutating, timeout)

    def app(self, code, label, data=None, mutating=False, timeout=45):
        self.ipcs.append((code, label, data, mutating, timeout))
        if self.response is not None: return self.response
        if self.timeout_override is not None: timeout = min(timeout, self.timeout_override)
        return super().app(code, label, data, mutating, timeout)


class HostMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('maintenance'), 'maintenance client missing')
        import maintenance
        self.m = maintenance
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix='fictional-maintenance-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'fixture.apk').write_bytes(b'FICTIONAL APK')
        (self.root/'profile.json').write_text(json.dumps(profile()))
        (self.root/'release.json').write_text(json.dumps(release()))
        self.i = Inputs(self.root/'profile.json', self.root/'release.json', OfflineSDK())
        now = dt.datetime.now(dt.timezone.utc)
        handoff = {'schema': 1, **self.i.bindings, 'serial': self.i.p['serial'],
                   'owner': 'FICTIONAL-owner', 'ready': True, 'released': True,
                   'no_parallel': True, 'issued_at': now.isoformat(),
                   'expires_at': (now+dt.timedelta(minutes=10)).isoformat()}
        self.auth_path = self.root/'handoff.json'
        self.auth_path.write_text(json.dumps(handoff))
        self.auth = Authorization(self.auth_path, self.i)
        self.t = HostTransport(self.i.p)
        self.r = AndroidRemote(self.i, None, transport=self.t)
        self.pkg = {'version': 1, 'uid': 10123, 'path': APK,
                    'sha256': digest(b'FICTIONAL old APK')}
        self.control = {'flags': {'userStopped': 'false', 'safetyPaused': 'false'},
                        'lease_sha256': 'a'*64, 'boot': BOOT}
        self.r.package = lambda **kwargs: copy.deepcopy(self.pkg)
        self.r.late_control = lambda: copy.deepcopy(self.control)
        self.client = self.m.MaintenanceClient(self.r, self.auth)
        previous = os.environ.get('FICTIONAL_MAINTENANCE_REQUEST')
        def restore_environment():
            if previous is None: os.environ.pop('FICTIONAL_MAINTENANCE_REQUEST', None)
            else: os.environ['FICTIONAL_MAINTENANCE_REQUEST'] = previous
        self.addCleanup(restore_environment)

    def prepare(self, **kwargs):
        record = self.client.prepare(**kwargs)
        os.environ['FICTIONAL_MAINTENANCE_REQUEST'] = json.dumps(record['request'])
        return record

    def terminal_resume(self):
        record = self.prepare(ttl_ms=60000)
        self.pkg.update(version=self.i.r['version'], sha256=self.i.r['sha256'])
        self.i.out = m.PrivateOutput(self.root/'terminal-out', True)
        self.i.out.write('checkpoint.json', {'phase': 'maintenance-release',
                         'intent': 'maintenance-release', 'maintenance': record})
        checkpoint_hash = m.sha((self.i.out.path/'checkpoint.json').read_bytes())
        handoff = json.loads(self.auth.data)
        handoff['checkpoint_sha256'] = checkpoint_hash
        self.auth_path.write_text(json.dumps(handoff))
        self.auth = Authorization(self.auth_path, self.i, checkpoint_hash)
        client = self.m.MaintenanceClient(self.r, self.auth, checkpoint=record)
        self.t.clock = (BOOT+'\n800.00 800.00\n'+BOOT+'\n').encode()
        return record, checkpoint_hash, client

    def test_terminal_released_after_expiry_is_one_status_not_an_active_lease(self):
        record, checkpoint_hash, client = self.terminal_resume()
        before = (self.i.out.path/'checkpoint.json').read_bytes()
        for operation in (client.status, client.assert_active, client.wait_active,
                          client.request_once, client.release_once):
            with self.subTest(operation=operation.__name__), self.assertRaises(Refusal): operation()
        self.assertEqual(self.t.ipcs, [])
        self.t.mode = 'released'
        self.assertEqual(client.reconcile_release(checkpoint_hash=checkpoint_hash)['phase'], 'released')
        self.assertEqual(len(self.t.ipcs), 1)
        code, label, data, mutating, timeout = self.t.ipcs[0]
        self.assertIn('MaintenanceCli status', code)
        self.assertEqual(json.loads(data), {'version': 1, 'token': record['request']['token']})
        self.assertEqual(label, 'control')
        self.assertFalse(mutating)
        self.assertEqual(timeout, 5)
        for operation in (client.status, client.assert_active, client.wait_active,
                          client.request_once, client.release_once,
                          lambda: client.reconcile_release(checkpoint_hash=checkpoint_hash)):
            with self.assertRaises(Refusal): operation()
        self.assertEqual(len(self.t.ipcs), 1)
        self.assertEqual(client.checkpoint(), record)
        self.assertEqual((self.i.out.path/'checkpoint.json').read_bytes(), before)

    def test_terminal_release_refuses_every_nonreleased_or_unbound_reply_without_poll(self):
        record, checkpoint_hash, _ = self.terminal_resume()
        original = (self.i.out.path/'checkpoint.json').read_bytes()
        good = dict(record['request'], ownerUid=10123, phase='released')
        bad = []
        for phase in ('active', 'pending', 'expired', 'revoked', 'busy', 'not_owner',
                      'cleanup_pending', 'blocked_unknown_dispatch', 'future_phase'):
            bad.append(dict(good, phase=phase))
        bad += [{'version': 1, 'phase': 'released'}, {'version': 1, 'error': 'unsupported'}]
        for key, value in (('token', 'f'*64), ('ownerUid', 10124), ('ownerUid', 10123.0),
                           ('boot', BOOT[:-1]+'2'), ('profileSha256', '0'*64),
                           ('releaseSha256', '1'*64), ('deadlineElapsedMs', 160001),
                           ('deadlineElapsedMs', 160000.0), ('baselineVersion', True),
                           ('targetVersion', 3), ('unknown', False)):
            bad.append(dict(good, **{key: value}))
        wire = json.dumps(good).encode()
        responses = [json.dumps(obj).encode() for obj in bad]
        responses += [wire[:-1]+b',"phase":"released"}', wire+b'{}', b'\xff', wire+b' '*2049]
        for raw in responses:
            client = self.m.MaintenanceClient(self.r, self.auth, checkpoint=record)
            self.t.response = raw
            before = len(self.t.ipcs)
            with self.subTest(shape=len(raw)), self.assertRaises(Refusal):
                client.reconcile_release(checkpoint_hash=checkpoint_hash)
            self.assertEqual(len(self.t.ipcs), before+1)
            with self.assertRaises(Refusal): client.reconcile_release(checkpoint_hash=checkpoint_hash)
            self.assertEqual(len(self.t.ipcs), before+1)
            self.assertEqual(client.checkpoint(), record)
            self.assertEqual((self.i.out.path/'checkpoint.json').read_bytes(), original)
        self.assertTrue(all('MaintenanceCli status' in call[0] for call in self.t.ipcs))

    def test_terminal_release_requires_real_fresh_checkpoint_authority_before_ipc(self):
        record, checkpoint_hash, _ = self.terminal_resume()
        out = self.i.out
        before = (out.path/'checkpoint.json').read_bytes()
        pkg = copy.deepcopy(self.pkg)
        control = copy.deepcopy(self.control)
        handoff = self.auth.data
        clock = self.t.clock
        changes = [
            (lambda: setattr(self.t, 'execute', False), lambda: setattr(self.t, 'execute', True)),
            (lambda: setattr(self.auth, 'checkpoint_hash', None), lambda: setattr(self.auth, 'checkpoint_hash', checkpoint_hash)),
            (lambda: self.auth_path.write_bytes(handoff+b' '), lambda: self.auth_path.write_bytes(handoff)),
            (lambda: self.i.profile_path.write_bytes(self.i.profile_bytes+b' '), lambda: self.i.profile_path.write_bytes(self.i.profile_bytes)),
            (lambda: self.i.release_path.write_bytes(self.i.release_bytes+b' '), lambda: self.i.release_path.write_bytes(self.i.release_bytes)),
            (lambda: out.target('checkpoint.json').write_bytes(before+b' '), lambda: out.target('checkpoint.json').write_bytes(before)),
            (lambda: delattr(self.i, 'out'), lambda: setattr(self.i, 'out', out)),
            (lambda: self.pkg.update(uid=10124), lambda: self.pkg.update(pkg)),
            (lambda: self.pkg.update(version=1, sha256=digest(b'FICTIONAL old APK')), lambda: self.pkg.update(pkg)),
            (lambda: self.pkg.update(sha256='f'*64), lambda: self.pkg.update(pkg)),
            (lambda: self.control['flags'].update(userStopped='true'), lambda: self.control.update(copy.deepcopy(control))),
            (lambda: self.control['flags'].update(safetyPaused='true'), lambda: self.control.update(copy.deepcopy(control))),
            (lambda: self.control.update(lease_sha256='f'*64), lambda: self.control.update(copy.deepcopy(control))),
            (lambda: setattr(self.t, 'clock', clock.replace(BOOT.encode(), (BOOT[:-1]+'2').encode())), lambda: setattr(self.t, 'clock', clock)),
        ]
        for index, (change, undo) in enumerate(changes):
            client = self.m.MaintenanceClient(self.r, self.auth, checkpoint=record)
            change()
            try:
                with self.subTest(case=index), self.assertRaises(Refusal):
                    client.reconcile_release(checkpoint_hash=checkpoint_hash)
            finally: undo()
            self.assertEqual(self.t.ipcs, [])
        for value in ('0'*64, checkpoint_hash.upper(), None, True):
            client = self.m.MaintenanceClient(self.r, self.auth, checkpoint=record)
            with self.assertRaises(Refusal): client.reconcile_release(checkpoint_hash=value)
        self.assertEqual(self.t.ipcs, [])

    def test_terminal_release_rechecks_target_control_clock_handoff_and_checkpoint_after_ipc(self):
        record, checkpoint_hash, _ = self.terminal_resume()
        before = (self.i.out.path/'checkpoint.json').read_bytes()
        pkg, control = copy.deepcopy(self.pkg), copy.deepcopy(self.control)
        handoff, clock = self.auth.data, self.t.clock
        self.t.response = json.dumps(dict(record['request'], ownerUid=10123, phase='released')).encode()
        original_app = self.t.app
        changes = [
            (lambda: self.pkg.update(version=1, sha256=digest(b'FICTIONAL old APK')), lambda: self.pkg.update(pkg)),
            (lambda: self.pkg.update(uid=10124), lambda: self.pkg.update(pkg)),
            (lambda: self.control['flags'].update(userStopped='true'), lambda: self.control.update(copy.deepcopy(control))),
            (lambda: self.control['flags'].update(safetyPaused='true'), lambda: self.control.update(copy.deepcopy(control))),
            (lambda: self.control.update(lease_sha256='f'*64), lambda: self.control.update(copy.deepcopy(control))),
            (lambda: setattr(self.t, 'clock', clock.replace(BOOT.encode(), (BOOT[:-1]+'2').encode())), lambda: setattr(self.t, 'clock', clock)),
            (lambda: self.auth_path.write_bytes(handoff+b' '), lambda: self.auth_path.write_bytes(handoff)),
            (lambda: self.i.out.target('checkpoint.json').write_bytes(before+b' '), lambda: self.i.out.target('checkpoint.json').write_bytes(before)),
        ]
        for index, (change, undo) in enumerate(changes):
            client = self.m.MaintenanceClient(self.r, self.auth, checkpoint=record)
            def changed_after_call(*args, **kwargs):
                raw = original_app(*args, **kwargs)
                change()
                return raw
            self.t.app = changed_after_call
            prior = len(self.t.ipcs)
            try:
                with self.subTest(case=index), self.assertRaises(Refusal):
                    client.reconcile_release(checkpoint_hash=checkpoint_hash)
            finally:
                undo()
                self.t.app = original_app
            self.assertEqual(len(self.t.ipcs), prior+1)
            self.assertEqual(client.checkpoint(), record)
            self.assertEqual((self.i.out.path/'checkpoint.json').read_bytes(), before)

    def test_terminal_release_requires_original_private_intent_and_record_not_fake_authority(self):
        from types import SimpleNamespace
        record, checkpoint_hash, _ = self.terminal_resume()
        fake = SimpleNamespace(inputs=self.i, checkpoint_hash=checkpoint_hash, check=lambda: True)
        client = self.m.MaintenanceClient(self.r, fake, checkpoint=record)
        with self.assertRaises(Refusal): client.reconcile_release(checkpoint_hash=checkpoint_hash)
        handoff = json.loads(self.auth.data)
        original = {'phase': 'maintenance-release', 'intent': 'maintenance-release', 'maintenance': record}
        changed_record = copy.deepcopy(record)
        changed_record['request']['token'] = 'f'*64
        for change in ({'phase': 'complete'}, {'intent': None}, {'intent': 'maintenance-acquire'},
                       {'maintenance': changed_record}):
            self.i.out.write('checkpoint.json', dict(original, **change))
            checkpoint_hash = m.sha((self.i.out.path/'checkpoint.json').read_bytes())
            handoff['checkpoint_sha256'] = checkpoint_hash
            self.auth_path.write_text(json.dumps(handoff))
            auth = Authorization(self.auth_path, self.i, checkpoint_hash)
            client = self.m.MaintenanceClient(self.r, auth, checkpoint=record)
            with self.assertRaises(Refusal): client.reconcile_release(checkpoint_hash=checkpoint_hash)
        now = dt.datetime.now(dt.timezone.utc)
        handoff.update(issued_at=(now-dt.timedelta(minutes=2)).isoformat(),
                       expires_at=(now-dt.timedelta(minutes=1)).isoformat())
        self.auth_path.write_text(json.dumps(handoff))
        with self.assertRaises(Refusal): Authorization(self.auth_path, self.i, checkpoint_hash)
        self.assertEqual(self.t.ipcs, [])

    def test_terminal_release_real_host_timeout_is_uncertain_without_retry_or_renewal(self):
        record, checkpoint_hash, client = self.terminal_resume()
        before = (self.i.out.path/'checkpoint.json').read_bytes()
        self.t.mode = 'timeout'
        self.t.timeout_override = .03
        with self.assertRaises(self.m.MaintenanceUncertain):
            client.reconcile_release(checkpoint_hash=checkpoint_hash)
        with self.assertRaises(Refusal): client.reconcile_release(checkpoint_hash=checkpoint_hash)
        with self.assertRaises(Refusal): client.release_once()
        self.assertEqual(len(self.t.ipcs), 1)
        self.assertIn('MaintenanceCli status', self.t.ipcs[0][0])
        self.assertEqual(client.checkpoint(), record)
        self.assertEqual((self.i.out.path/'checkpoint.json').read_bytes(), before)

    def test_terminal_release_rereads_handoff_after_final_private_checkpoint_verification(self):
        record, checkpoint_hash, client = self.terminal_resume()
        original_verify = self.i.out.verify
        reads = 0
        def changed_during_final_read():
            nonlocal reads
            original_verify()
            reads += 1
            if reads == 3:
                self.auth_path.write_bytes(self.auth.data+b' ')
        self.i.out.verify = changed_during_final_read
        self.t.mode = 'released'
        with self.assertRaises(Refusal): client.reconcile_release(checkpoint_hash=checkpoint_hash)
        self.assertEqual(len(self.t.ipcs), 0, 'handoff drift during final private read must prevent IPC')
        self.assertEqual(client.checkpoint(), record)

    def dispatch_deadline_fixture(self, *, authority_delay=0.0, script_delay=0.0, preflight_delay=0.0):
        # Run real Client -> inherited Transport.call -> fictional host child.
        # A controllable monotonic clock makes slow validation deterministic;
        # the child marker independently proves whether the transport ran.
        clock = [100.0]
        marker = self.root/'dispatch-children'
        original_command = self.t.command
        def command(args):
            argv = original_command(args)
            prefix = ('from pathlib import Path\n'
                      'with Path('+repr(str(marker))+').open("ab") as f: f.write(b"x")\n')
            argv[2] = prefix+argv[2]
            return argv
        self.t.command = command
        original_preflight = self.client._preflight
        original_authority = self.client._authority
        original_script = self.client._script
        ready = [False]
        def preflight(*args, **kwargs):
            result = original_preflight(*args, **kwargs)
            clock[0] += preflight_delay
            ready[0] = True
            return result
        def authority():
            original_authority()
            if ready[0]:
                ready[0] = False
                clock[0] += authority_delay
        def script(*args):
            result = original_script(*args)
            clock[0] += script_delay
            return result
        self.client._preflight = preflight
        self.client._authority = authority
        self.client._script = script
        return clock, marker

    def test_slow_final_authority_exhausts_poll_budget_before_any_lifecycle_ipc(self):
        record = self.prepare(ttl_ms=60000)
        clock, marker = self.dispatch_deadline_fixture(authority_delay=2)
        with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            with self.assertRaises(Refusal):
                self.client.wait_active(max_attempts=1, timeout_ms=1000)
        self.assertEqual((len(self.t.ipcs), self.t.calls,
                          marker.read_bytes() if marker.exists() else b''), (0, 0, b''),
                         'expired polling must prevent lifecycle dispatch and child startup')
        self.assertEqual(self.client.checkpoint(), record)

    def test_near_poll_deadline_shortens_actual_child_timeout(self):
        import subprocess
        record = self.prepare(ttl_ms=60000)
        clock, marker = self.dispatch_deadline_fixture(authority_delay=.75)
        with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])), \
                patch('android.subprocess.run', wraps=subprocess.run) as run:
            self.assertEqual(self.client.wait_active(max_attempts=1, timeout_ms=1000)['phase'], 'active')
        self.assertEqual((len(self.t.ipcs), self.t.calls, marker.read_bytes()), (1, 1, b'x'))
        self.assertEqual(run.call_count, 1)
        self.assertAlmostEqual(run.call_args.kwargs['timeout'], .25)
        self.assertAlmostEqual(self.t.ipcs[0][-1], .25)
        self.assertEqual(self.client.checkpoint(), record)

    def test_near_original_lease_shortens_actual_child_timeout_without_poll(self):
        import subprocess
        record = self.prepare(ttl_ms=1000)
        clock, marker = self.dispatch_deadline_fixture(authority_delay=.75)
        with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])), \
                patch('android.subprocess.run', wraps=subprocess.run) as run:
            self.assertEqual(self.client.status()['phase'], 'active')
        self.assertEqual((len(self.t.ipcs), self.t.calls, marker.read_bytes()), (1, 1, b'x'))
        self.assertEqual(run.call_count, 1)
        self.assertAlmostEqual(run.call_args.kwargs['timeout'], .24)
        self.assertEqual(self.client.checkpoint(), record)

    def test_original_lease_minimum_still_bounds_generous_poll_window(self):
        record = self.prepare(ttl_ms=1000)
        clock, marker = self.dispatch_deadline_fixture(authority_delay=.75)
        with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            with self.assertRaisesRegex(Refusal, 'remaining deadline budget'):
                self.client._dispatch('status', 300, until=200)
        self.assertEqual((len(self.t.ipcs), self.t.calls, marker.exists()), (0, 0, False))
        self.assertEqual(self.client.checkpoint(), record)

    def test_every_ordinary_api_refuses_slow_final_authority_without_renewal_or_replay(self):
        for name in ('status', 'request_once', 'release_once', 'assert_active'):
            with self.subTest(operation=name):
                self.client = self.m.MaintenanceClient(self.r, self.auth)
                record = self.prepare(ttl_ms=1000)
                clock, marker = self.dispatch_deadline_fixture(authority_delay=2)
                operation = (lambda: self.client.assert_active(minimum_remaining_ms=1)) \
                    if name == 'assert_active' else getattr(self.client, name)
                with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
                    for attempt in range(2):
                        with self.assertRaises(Refusal): operation()
                        if attempt == 0: self.assertEqual(clock[0], 102.0)
                self.assertEqual((len(self.t.ipcs), self.t.calls, marker.exists()), (0, 0, False))
                self.assertEqual(self.client.checkpoint(), record)
                if name == 'request_once': self.assertTrue(self.client.request_attempted)
                if name == 'release_once': self.assertTrue(self.client.release_attempted)

    def test_slow_preflight_return_cannot_pair_old_remaining_with_new_time(self):
        record = self.prepare(ttl_ms=1000)
        clock, marker = self.dispatch_deadline_fixture(preflight_delay=2)
        with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            with self.assertRaises(Refusal): self.client.wait_active(max_attempts=1, timeout_ms=10000)
        self.assertEqual((len(self.t.ipcs), self.t.calls, marker.exists()), (0, 0, False))
        self.assertEqual(self.client.checkpoint(), record)

    def test_slow_script_construction_is_charged_before_dispatch(self):
        record = self.prepare(ttl_ms=60000)
        clock, marker = self.dispatch_deadline_fixture(script_delay=2)
        with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            with self.assertRaises(Refusal): self.client.wait_active(max_attempts=1, timeout_ms=1000)
        self.assertEqual((len(self.t.ipcs), self.t.calls, marker.exists()), (0, 0, False))
        self.assertEqual(self.client.checkpoint(), record)

    def test_invalid_final_monotonic_elapsed_fails_closed_before_ipc(self):
        for delay in (-1, float('nan'), float('inf'), -float('inf')):
            with self.subTest(delay=delay):
                self.client = self.m.MaintenanceClient(self.r, self.auth)
                record = self.prepare(ttl_ms=60000)
                clock, marker = self.dispatch_deadline_fixture(authority_delay=delay)
                with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
                    with self.assertRaises(Refusal): self.client.status()
                self.assertEqual((len(self.t.ipcs), self.t.calls, marker.exists()), (0, 0, False))
                self.assertEqual(self.client.checkpoint(), record)

    def test_final_authority_still_rejects_expired_handoff_and_source_drift_before_ipc(self):
        record = self.prepare(ttl_ms=60000)
        original_authority = self.client._authority
        original_profile = self.i.profile_bytes
        checks = [0]
        def changed_authority():
            checks[0] += 1
            if checks[0] == 3:
                self.i.profile_path.write_bytes(original_profile+b' ')
            return original_authority()
        self.client._authority = changed_authority
        with self.assertRaises(Refusal): self.client.status()
        self.i.profile_path.write_bytes(original_profile)
        checks[0] = 0
        future = NOW+dt.timedelta(days=1)
        original_validate = __import__('upgrade').validate_maintenance
        def expired(*args, **kwargs):
            return original_validate(*args, **dict(kwargs, now=future))
        def expired_authority():
            checks[0] += 1
            if checks[0] == 3:
                with patch('upgrade.validate_maintenance', side_effect=expired):
                    return original_authority()
            return original_authority()
        self.client._authority = expired_authority
        with self.assertRaises(Refusal): self.client.status()
        self.assertEqual((len(self.t.ipcs), self.t.calls), (0, 0))
        self.assertEqual(self.client.checkpoint(), record)

    def test_clock_accepts_crlf_framing_without_trimming_tokens(self):
        original = self.t.clock
        self.t.clock = original.replace(b'\n', b'\r\n')
        record = self.prepare(ttl_ms=60000)
        self.assertEqual(record['request']['boot'], BOOT)
        self.assertEqual(record['request']['deadlineElapsedMs'], 160000)
        malformed = (original.replace(b'\n', b'\r'),
                     original.replace(b'\n', b'\r\r\n'),
                     b' '+original, original+b'\n', original+b'\x00')
        for raw in malformed:
            with self.subTest(raw=raw):
                self.t.clock = raw
                client = self.m.MaintenanceClient(self.r, self.auth)
                with self.assertRaises(Refusal):client.prepare()

    def test_host_tracer_stdin_fixed_classpath_fresh_ack_and_release(self):
        record = self.prepare(ttl_ms=60000)
        self.assertEqual(record['request']['deadlineElapsedMs'], 160000)
        self.assertEqual(self.client.request_once()['phase'], 'active')
        self.assertEqual(self.client.assert_active()['phase'], 'active')
        self.assertEqual(self.client.release_once()['phase'], 'released')
        self.assertEqual(len(self.t.ipcs), 3)
        for code, label, data, mutating, timeout in self.t.ipcs:
            self.assertIn('CLASSPATH='+APK, code)
            self.assertNotIn(record['request']['token'], code)
            self.assertLessEqual(len(data), 2048)
            self.assertFalse(mutating)
            self.assertGreater(timeout, 0)
        self.assertEqual(json.loads(self.t.ipcs[0][2]), record['request'])
        self.assertEqual(set(json.loads(self.t.ipcs[1][2])), {'version', 'token'})


    def ack(self, record, **changes):
        return json.dumps(dict(record['request'], phase='active', ownerUid=10123, **changes)).encode()

    def test_ack_schema_rejects_coercions_duplicate_unknown_and_wrong_bindings(self):
        record = self.prepare()
        good = dict(record['request'], phase='active', ownerUid=10123)
        mutations = [(key, value) for key, value in (
            ('version', True), ('version', 1.0), ('token', '0'*64), ('token', 'A'*64),
            ('profileSha256', '0'*64), ('releaseSha256', '1'*64), ('boot', BOOT.upper()+'x'),
            ('deadlineElapsedMs', good['deadlineElapsedMs']+1),
            ('deadlineElapsedMs', float(good['deadlineElapsedMs'])),
            ('baselineVersion', True), ('targetVersion', float(good['targetVersion'])),
            ('ownerUid', 10124), ('ownerUid', 10123.0), ('phase', 'future_phase'),
            ('phase', True), ('unknown', 1))]
        bad = []
        for key, value in mutations:
            obj = dict(good); obj[key] = value; bad.append(json.dumps(obj).encode())
        for key in good:
            obj = dict(good); del obj[key]; bad.append(json.dumps(obj).encode())
        wire = json.dumps(good).encode()
        bad += [wire[:-1]+b',"version":1}', wire[:-1]+b',"\\u0076ersion":1}',
                b'\xef\xbb\xbf'+wire, wire+b'{}', wire+b'\x00', wire+b' '*2049,
                b'\xff', b'[]', b'null', b'{"version":NaN}']
        for raw in bad:
            with self.subTest(raw_shape=len(raw)):
                self.t.response = raw
                with self.assertRaises(Refusal): self.client.assert_active()

    def test_negative_and_unknown_phases_are_terminal_not_pollable(self):
        record = self.prepare()
        phases = ('revoked', 'expired', 'version_mismatch', 'not_owner', 'busy',
                  'payload_mismatch', 'token_reused', 'capacity', 'store_error',
                  'expired_or_invalid_deadline', 'blocked_unknown_dispatch', 'cleanup_pending',
                  'released', 'future_phase')
        for phase in phases:
            for full in (False, True):
                obj = dict(record['request'], ownerUid=10123) if full else {'version': 1}
                obj['phase'] = phase
                self.t.response = json.dumps(obj).encode()
                before = len(self.t.ipcs)
                with self.assertRaises(Refusal): self.client.wait_active()
                self.assertEqual(len(self.t.ipcs), before+1)

    def test_fresh_ack_is_never_cached(self):
        self.prepare()
        self.client.assert_active()
        self.t.mode = 'pending'
        with self.assertRaises(Refusal): self.client.assert_active()
        self.assertEqual(len(self.t.ipcs), 2)

    def test_pending_poll_is_bounded_without_request_or_deadline_renewal(self):
        record = self.prepare()
        self.t.response = json.dumps(dict(record['request'], phase='pending', ownerUid=10123)).encode()
        with self.assertRaises(Refusal):
            self.client.wait_active(max_attempts=2, poll_ms=1)
        self.assertEqual(len(self.t.ipcs), 2)
        self.assertEqual(self.client.checkpoint(), record)
        self.assertTrue(all(json.loads(call[2]) == {'version': 1, 'token': record['request']['token']}
                            for call in self.t.ipcs))
        self.t.response = self.ack(record)
        self.assertEqual(self.client.wait_active()['phase'], 'active')

    def test_host_real_timeout_is_uncertain_and_no_operation_is_replayed(self):
        record = self.prepare()
        self.t.mode = 'timeout'; self.t.timeout_override = .03
        with self.assertRaises(self.m.MaintenanceUncertain): self.client.request_once()
        with self.assertRaises(Refusal): self.client.request_once()
        self.assertEqual(len(self.t.ipcs), 1)
        self.assertEqual(self.client.checkpoint(), record)
        # An explicit, separate status can reconcile ONLY the original token.
        self.t.mode = 'active'; self.t.timeout_override = None
        self.client.status()
        self.assertEqual(json.loads(self.t.ipcs[-1][2])['token'], record['request']['token'])
        self.t.mode = 'timeout'; self.t.timeout_override = .03
        with self.assertRaises(self.m.MaintenanceUncertain): self.client.release_once()
        with self.assertRaises(Refusal): self.client.release_once()
        self.assertEqual(len(self.t.ipcs), 3)
        with self.assertRaises(self.m.MaintenanceUncertain): self.client.wait_active()
        self.assertEqual(len(self.t.ipcs), 4)  # Unknown status is not a read-only retry.

    def test_unsupported_old_apk_envelope_is_terminal_with_no_fallback(self):
        self.prepare()
        self.t.response = b'{"version":1,"error":"unsupported"}\n'
        with self.assertRaises(self.m.MaintenanceUnsupported): self.client.request_once()
        self.assertEqual(len(self.t.ipcs), 1)
        self.assertNotIn('adb tcpip', self.t.ipcs[0][0])
        self.assertNotIn(' am ', self.t.ipcs[0][0])
        self.assertNotIn(' content ', self.t.ipcs[0][0])

    def test_resume_uses_exact_private_record_never_host_monotonic_or_rerequest(self):
        record = self.prepare()
        restored = self.m.MaintenanceClient(self.r, self.auth, checkpoint=record)
        with self.assertRaises(Refusal): restored.request_once()
        self.assertEqual(len(self.t.ipcs), 0)
        self.assertEqual(restored.assert_active()['phase'], 'active')
        self.t.clock = (BOOT+'\n700.00 700.00\n'+BOOT+'\n').encode()
        with self.assertRaises(Refusal): restored.assert_active()
        self.assertEqual(len(self.t.ipcs), 1)
        for key, value in [('version', True), ('deadlineElapsedMs', 1.0),
                           ('deadlineElapsedMs', 2**63), ('targetVersion', 0),
                           ('baselineVersion', 0), ('token', 'A'*64),
                           ('profileSha256', '0'*64), ('releaseSha256', '1'*64),
                           ('boot', 'not-a-uuid'), ('unknown', 1)]:
            obj = copy.deepcopy(record); obj['request'][key] = value
            with self.assertRaises(Refusal):
                self.m.MaintenanceClient(self.r, self.auth, checkpoint=obj)

    def test_every_api_requires_execute_original_inputs_and_authorization_bytes(self):
        record = self.prepare()
        methods = [lambda: self.m.MaintenanceClient(self.r, self.auth).prepare(),
                   self.client.request_once, self.client.status, self.client.wait_active,
                   self.client.assert_active, self.client.release_once]
        for mutate, undo in (
            (lambda: setattr(self.t, 'execute', False), lambda: setattr(self.t, 'execute', True)),
            (lambda: self.auth_path.write_bytes(self.auth.data+b' '), lambda: self.auth_path.write_bytes(self.auth.data)),
            (lambda: self.i.profile_path.write_bytes(self.i.profile_bytes+b' '), lambda: self.i.profile_path.write_bytes(self.i.profile_bytes)),
            (lambda: self.i.release_path.write_bytes(self.i.release_bytes+b' '), lambda: self.i.release_path.write_bytes(self.i.release_bytes)),
            (lambda: self.i.p.__setitem__('serial', 'FICTIONAL-CHANGED'), lambda: self.i.p.__setitem__('serial', profile()['serial']))):
            mutate()
            try:
                for operation in methods:
                    with self.assertRaises(Refusal): operation()
            finally: undo()
        self.assertEqual(self.t.ipcs, [])
        self.assertEqual(self.client.checkpoint(), record)

    def test_package_uid_version_hash_path_rechecked_before_each_ipc(self):
        self.prepare()
        original = dict(self.pkg)
        for key, value in [('uid', 10124), ('uid', 10123.0), ('version', True),
                           ('sha256', 'f'*64), ('version', 999),
                           ('path', '/data/app/FICTIONAL/../base.apk'),
                           ('path', '/data/app/FICTIONAL//base.apk')]:
            self.pkg[key] = value
            with self.assertRaises(Refusal): self.client.status()
            self.pkg = dict(original)
        self.assertEqual(self.t.ipcs, [])
        # Approved target relocation is allowed only together with target bytes/version.
        self.pkg = {'uid': 10123, 'version': self.i.r['version'],
                    'path': '/data/app/FICTIONAL-TARGET/base.apk', 'sha256': self.i.r['sha256']}
        self.client.assert_active()
        self.assertIn('CLASSPATH='+self.pkg['path'], self.t.ipcs[-1][0])
        self.assertIn(original['sha256'] if self.pkg == original else self.i.r['sha256'], self.t.ipcs[-1][0])

    def test_late_stop_before_or_after_ipc_fails_closed(self):
        record = self.prepare()
        reads = 0
        def late():
            nonlocal reads
            reads += 1
            control = copy.deepcopy(self.control)
            if reads >= 2: control['flags']['userStopped'] = 'true'
            return control
        self.r.late_control = late
        with self.assertRaises(Refusal): self.client.assert_active()
        self.assertEqual(self.t.ipcs, [])
        self.r.late_control = lambda: copy.deepcopy(self.control)
        original_app = self.t.app
        def changed_after_call(*args, **kwargs):
            result = original_app(*args, **kwargs)
            self.control['flags']['safetyPaused'] = 'true'
            return result
        self.t.response = self.ack(record)
        self.t.app = changed_after_call
        with self.assertRaises(Refusal): self.client.assert_active()
        self.assertEqual(len(self.t.ipcs), 1)

    def test_device_deadline_boot_and_minimum_operation_budget(self):
        from types import SimpleNamespace
        # Model device deadline boundaries, not real host I/O/scheduling speed.
        # Replace only this module binding; real subprocess clocks stay intact.
        with patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: 100.0)):
            self.prepare(ttl_ms=60000)
            self.t.clock = (BOOT+'\n159.99 159.99\n'+BOOT+'\n').encode()
            with self.assertRaises(Refusal): self.client.assert_active()
            self.assertEqual(self.t.ipcs, [])
            self.t.clock = (BOOT+'\n100.00 100.00\n'+BOOT+'\n').encode()
            for minimum in (True, 0, -1, 1.0, 600001):
                with self.assertRaises(Refusal): self.client.assert_active(minimum_remaining_ms=minimum)
            self.client.assert_active(minimum_remaining_ms=59000)
            self.t.clock = (BOOT+'\n160.00 160.00\n'+BOOT+'\n').encode()
            with self.assertRaises(Refusal): self.client.status()
            self.t.clock = (BOOT+'\n100.00 100.00\n'+'0'*36+'\n').encode()
            with self.assertRaises(Refusal): self.client.status()
            self.assertEqual(len(self.t.ipcs), 1)

    def test_explicit_status_reconciles_released_only_with_exact_bound_reply(self):
        record = self.prepare()
        released = dict(record['request'], ownerUid=10123, phase='released')
        self.t.response = json.dumps(released).encode()
        with self.assertRaises(self.m.MaintenanceRejected) as caught: self.client.status()
        self.assertEqual(caught.exception.phase, 'released')
        self.assertTrue(caught.exception.bound)
        self.assertNotIn(record['request']['token'], str(caught.exception))
        self.t.response = b'{"version":1,"phase":"not_owner"}'
        with self.assertRaises(self.m.MaintenanceRejected) as caught: self.client.status()
        self.assertEqual(caught.exception.phase, 'not_owner')
        self.assertFalse(caught.exception.bound)
        released['token'] = '0'*64
        self.t.response = json.dumps(released).encode()
        with self.assertRaises(Refusal) as caught: self.client.status()
        self.assertNotIsInstance(caught.exception, self.m.MaintenanceRejected)

    def test_active_from_old_apk_is_not_accepted_after_package_replacement(self):
        record = self.prepare()
        self.t.response = self.ack(record)
        original_app = self.t.app
        def replaced(*args, **kwargs):
            raw = original_app(*args, **kwargs)
            self.pkg = {'uid': 10123, 'version': self.i.r['version'],
                        'sha256': self.i.r['sha256'], 'path': '/data/app/FICTIONAL-TARGET/base.apk'}
            return raw
        self.t.app = replaced
        with self.assertRaises(Refusal): self.client.assert_active()
        self.assertEqual(len(self.t.ipcs), 1)

    def test_host_shell_old_class_failure_maps_to_unsupported_not_success(self):
        import shlex
        import subprocess
        self.prepare()
        old = self.root/'fictional-old.apk'; old.write_bytes(b'FICTIONAL old APK')
        runtime = self.root/'fictional-runtime.py'
        marker = self.root/'fictional-runtime-reached'
        # Some Windows bash launchers use WSL rather than MSYS. Discover the
        # actual host shell's interpreter/mount spelling; never feed native
        # Windows paths to a Linux Python or count a pre-runtime refusal as proof.
        probe = subprocess.run(['bash', '-c', 'command -v python3 || command -v python; pwd'],
                               capture_output=True, timeout=10, check=True)
        executable, shell_cwd = probe.stdout.decode().splitlines()
        def shell_path(native):
            value = str(native).replace('\\', '/')
            if os.name == 'nt' and shell_cwd.startswith('/mnt/') and value[1:3] == ':/':
                return '/mnt/'+value[0].lower()+value[2:]
            return value
        runtime.write_text('import json, pathlib, sys\n'
                           'p=json.loads(sys.stdin.buffer.read())\n'
                           'assert len(p)==8 and sys.argv[-2:]==["com.termux.app.privateadb.MaintenanceCli", "request"]\n'
                           'pathlib.Path('+repr(shell_path(marker))+').write_bytes(b"FICTIONAL reached")\n'
                           'sys.stderr.write("Fictional class not found\\n")\nsys.exit(1)\n')
        path = shell_path(old)
        code = self.client._script(self.pkg, 'request')
        self.assertIn('/system/bin/pm path com.termux', code)
        # Rewrite only fixed Android-tool paths/identity into this disposable
        # host fixture. Production permits NO path/UID/runtime overrides.
        code = code.replace(APK, path).replace('$(id -u)', '$(printf 10123)')
        code = code.replace('/system/bin/pm path com.termux',
                            "printf '%s\\n' "+shlex.quote('package:'+path))
        code = code.replace('[ -x /system/bin/app_process ]',
                            '[ -x '+shlex.quote(executable)+' ]')
        code = code.replace('/system/bin/app_process /system/bin',
                            shlex.quote(executable)+' '+shlex.quote(shell_path(runtime))+' /system/bin')
        result = subprocess.run(['bash', '-c', code], input=self.t.ipcs[0][2] if self.t.ipcs else
                                json.dumps(self.client.checkpoint()['request']).encode(),
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(marker.is_file(), 'host fixture never reached app_process substitute')
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), {'version': 1, 'error': 'unsupported'})
        with self.assertRaises(self.m.MaintenanceUnsupported): self.client._reply(result.stdout, 'request')

    def test_clock_schema_and_slow_read_do_not_authorize_old_deadline(self):
        self.prepare(ttl_ms=60000)
        for clock in (b'not-a-clock', (BOOT+'\nNaN 0\n'+BOOT+'\n').encode(),
                      (BOOT+'\v100.00 100.00\v'+BOOT+'\v').encode()):
            self.t.clock = clock
            with self.assertRaises(Refusal): self.client.assert_active()
        self.assertEqual(self.t.ipcs, [])
        self.t.clock = (BOOT+'\n100.00 100.00\n'+BOOT+'\n').encode()
        # Deterministic host boundary: clock round-trip itself consumed 40s.
        clock = [100.0]
        original_shell = self.t.shell
        def slow_clock(*args, **kwargs):
            raw = original_shell(*args, **kwargs)
            if (args[1] if len(args) > 1 else kwargs.get('label')) == 'clock':
                clock[0] += 40
            return raw
        with patch.object(self.t, 'shell', side_effect=slow_clock), \
                patch.object(self.m, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            with self.assertRaises(Refusal): self.client.assert_active()
        self.assertEqual(self.t.ipcs, [])

    def test_prepare_ttl_and_checkpoint_are_defensive_not_renewable(self):
        for ttl in (True, 0, -1, 600001, 1.0):
            with self.assertRaises(Refusal): self.client.prepare(ttl_ms=ttl)
        record = self.prepare()
        record['request']['deadlineElapsedMs'] += 5000
        self.assertNotEqual(record, self.client.checkpoint())
        with self.assertRaises(Refusal): self.client.prepare()
        self.assertEqual(self.t.ipcs, [])


if __name__ == '__main__': unittest.main()

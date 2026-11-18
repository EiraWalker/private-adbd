"""Deterministic fictional host-only control/dispatch regressions; no device IO."""
import copy
import json
import types
import unittest
from unittest.mock import patch

import android
import installer
import maintenance
import upgrade
from test_installer import profile
from test_local import release
from test_remote import SnapshotWire


BOOT = '00000000-0000-0000-0000-000000000001'


class ControlFreshnessTests(unittest.TestCase):
    def coupling(self, delay_label='clock', delay=21.0):
        p = profile()
        r = dict(release(), maintenance_api=1)
        pb, rb = json.dumps(p).encode(), json.dumps(r).encode()
        inputs = types.SimpleNamespace(p=p, r=r, profile_bytes=pb, release_bytes=rb,
            bindings={'profile_sha256':installer.sha(pb), 'release_sha256':installer.sha(rb)},
            unchanged=lambda:None)
        auth = types.SimpleNamespace(inputs=inputs, check=lambda:None)
        wire = SnapshotWire(p)
        for key, value in wire.files.items():
            wire.files[key] = value.replace(b'FICTIONAL-boot', BOOT.encode())
        clock = {'elapsed':0.0, 'slow':False}
        record = None
        original_shell = wire.shell
        status_replies = []

        def shell(code, label, data=None, mutating=False, timeout=45):
            if label == 'control':
                self.assertIn('MaintenanceCli status', code)
                self.assertEqual(json.loads(data), {'version':1, 'token':record['request']['token']})
                reply = dict(record['request'], ownerUid=p['app_uid'], phase='active')
                status_replies.append(copy.deepcopy(reply))
                return json.dumps(reply).encode()
            if label == 'clock':
                uptime = 120 + clock['elapsed']
                if 'getconf PAGE_SIZE' in code:
                    result = (BOOT+'\n'+str(uptime)+' 1.0\n0\nEnforcing\n4096\n').encode()
                    if clock['slow'] and delay_label == label:
                        clock['elapsed'] += delay  # Tail after uptime sampling, before response returns.
                    return result
                self.assertEqual(code, 'set -eu; cat /proc/sys/kernel/random/boot_id; '
                                      'cat /proc/uptime; cat /proc/sys/kernel/random/boot_id')
                return (BOOT+'\n'+format(uptime,'.2f')+' 100.00\n'+BOOT+'\n').encode()
            result = original_shell(code,label,data,mutating,timeout)
            if clock['slow'] and delay_label == label:
                clock['elapsed'] += delay
            return result

        wire.shell = shell
        remote = android.AndroidRemote(inputs, None, transport=wire)
        engine = upgrade.Engine(inputs, remote, None, auth)
        before, pkg = remote.snapshot(), remote.package()
        record = {'request': {'version':1,'token':'b'*64,'boot':BOOT,
            'deadlineElapsedMs':720000,'profileSha256':inputs.bindings['profile_sha256'],
            'releaseSha256':inputs.bindings['release_sha256'],'baselineVersion':1,'targetVersion':2},
            'control':{k:before['control'][k] for k in ('flags','lease_sha256','boot')}}
        engine.cp = {'before':before,'baseline_package':pkg,'apk_confirmed':False,
                     'done':['maintenance-acquire'],'intent':'install'}
        engine.files_progress = lambda:None  # Release has no payloads.
        client = maintenance.MaintenanceClient(remote, auth, checkpoint=record)
        engine.maintenance = client
        original_assert = client.assert_active

        def asserted(*args, **kwargs):
            reply = original_assert(*args, **kwargs)
            clock['slow'] = True  # Delay only the independent final gate AFTER a valid active ack.
            return reply

        client.assert_active = asserted
        transport = android.Transport(p, lambda *args:None, execute=True)
        android.AndroidRemote(inputs, None, transport=transport).bind_guard(engine.guard)
        return transport, clock, status_replies, record, client

    def assert_dispatch(self, delay_label, delay, blocked):
        transport, clock, replies, record, client = self.coupling(delay_label, delay)
        original = copy.deepcopy(record)
        attempts = client.request_attempted, client.release_attempted
        with patch('time.monotonic',lambda:100.0+clock['elapsed']), \
             patch.object(android.subprocess,'run',return_value=types.SimpleNamespace(
                 returncode=0,stdout=b'FICTIONAL-result',stderr=b'')) as child:
            try:
                if blocked:
                    with self.assertRaisesRegex(installer.Refusal, 'heartbeat freshness'):
                        transport.shell('FICTIONAL-NO-DEVICE', 'install', mutating=True, timeout=180)
                else:
                    transport.shell('FICTIONAL-NO-DEVICE', 'install', mutating=True, timeout=180)
            finally:
                # The 21-second cases have sampled age 10s and final age 31s.
                self.assertEqual(child.call_count, 0 if blocked else 1,
                                 'late control must block stale heartbeats before actual mutation dispatch')
        self.assertEqual(transport.calls, 0 if blocked else 1)
        self.assertEqual(clock['elapsed'], delay)
        self.assertEqual([r['phase'] for r in replies], ['active'])
        self.assertEqual(client.checkpoint(), original)
        self.assertEqual((client.request_attempted, client.release_attempted), attempts)

    def test_late_clock_response_refuses_after_valid_ack_before_actual_dispatch(self):
        self.assert_dispatch('clock', 21.0, blocked=True)

    def test_late_presence_response_refuses_after_valid_ack_before_actual_dispatch(self):
        self.assert_dispatch('presence', 21.0, blocked=True)

    def test_just_over_thirty_seconds_refuses_before_dispatch(self):
        for label in ('clock', 'presence'):
            with self.subTest(label=label):
                self.assert_dispatch(label, 20.001, blocked=True)

    def test_zero_delay_and_below_boundary_allow_one_actual_dispatch(self):
        for label in ('clock', 'presence'):
            for delay in (0.0, 19.0, 20.0):
                with self.subTest(label=label, delay=delay):
                    self.assert_dispatch(label, delay, blocked=False)

    def timed_remote(self, delay_label, delay):
        p = profile()
        wire = SnapshotWire(p)
        clock = {'elapsed':0.0, 'injected':False}
        original_shell = wire.shell

        def shell(code, label, *args, **kwargs):
            result = original_shell(code, label, *args, **kwargs)
            if label == delay_label and not clock['injected']:
                clock['elapsed'] += delay
                clock['injected'] = True
            return result

        wire.shell = shell
        remote = android.AndroidRemote(types.SimpleNamespace(p=p, r=release()), None, transport=wire)
        return remote, wire, clock

    def test_all_control_read_time_counts_without_comparing_absolute_clock_domains(self):
        # Device uptime stays 120s; the arbitrary host origin is unrelated.
        for label in ('read', 'clock', 'presence'):
            with self.subTest(label=label):
                remote, wire, clock = self.timed_remote(label, 21.0)
                with patch('time.monotonic', lambda:700000.0+clock['elapsed']):
                    with self.assertRaisesRegex(installer.Refusal, 'heartbeat freshness'):
                        remote.control()
                self.assertTrue(clock['injected'])
                self.assertTrue(all(not mutation for _, _, mutation in wire.operations))

    def test_backward_nonfinite_or_overbudget_elapsed_fails_closed(self):
        for delay in (-1.0, float('nan'), float('inf'), 600.0):
            with self.subTest(delay=delay):
                remote, wire, clock = self.timed_remote('presence', delay)
                with patch('time.monotonic', lambda:100.0+clock['elapsed']):
                    with self.assertRaises(installer.Refusal): remote.control()
                self.assertTrue(clock['injected'])

    def test_elapsed_cannot_rebase_a_future_heartbeat_into_validity(self):
        remote, wire, clock = self.timed_remote('presence', 21.0)
        health = json.loads(wire.files[installer.STATE+'health.json'])
        health['uptime_ms'] = 125000
        wire.files[installer.STATE+'health.json'] = json.dumps(health).encode()
        with patch('time.monotonic', lambda:100.0+clock['elapsed']):
            with self.assertRaisesRegex(installer.Refusal, 'heartbeat freshness'):
                remote.control()

    def test_existing_guards_still_refuse_before_transport_dispatch(self):
        for gate in ('stop', 'safety', 'phase', 'lease', 'pending', 'boot', 'stale',
                     'future', 'unhealthy', 'window', 'selinux', 'page-size'):
            with self.subTest(gate=gate):
                remote, wire, clock = self.timed_remote('presence', 0.0)
                prefs = installer.APP+'/shared_prefs/private_adb_autostart.xml'
                if gate == 'stop':
                    wire.files[prefs] = wire.files[prefs].replace(b'userStopped" value="false', b'userStopped" value="true')
                elif gate == 'safety':
                    wire.files[prefs] = wire.files[prefs].replace(b'safetyPaused" value="false', b'safetyPaused" value="true')
                elif gate == 'phase':
                    wire.files[prefs] = wire.files[prefs].replace(b'healthy', b'paused')
                elif gate == 'lease':
                    wire.files[installer.APP+'/shared_prefs/private_adb_native_lease.xml'] = b'<map><boolean name="ownedFlag" value="true"/></map>'
                elif gate == 'pending': wire.pending = True
                elif gate in ('boot', 'stale', 'future', 'unhealthy'):
                    health = json.loads(wire.files[installer.STATE+'health.json'])
                    if gate == 'boot': health['boot_id'] = 'FICTIONAL-other-boot'
                    elif gate == 'stale': health['uptime_ms'] = 89999
                    elif gate == 'future': health['uptime_ms'] = 120001
                    else: health['state'] = 'paused'
                    wire.files[installer.STATE+'health.json'] = json.dumps(health).encode()
                else:
                    original_shell = wire.shell
                    def shell(code, label, *args, **kwargs):
                        result = original_shell(code, label, *args, **kwargs)
                        if label == 'clock':
                            if gate == 'window': result = result.replace(b'\n0\n', b'\n1\n')
                            elif gate == 'selinux': result = result.replace(b'Enforcing', b'Permissive')
                            else: result = result.replace(b'4096', b'16384')
                        return result
                    wire.shell = shell
                transport = android.Transport(remote.p, lambda *args:None, execute=True)
                android.AndroidRemote(remote.inputs, None, transport=transport).bind_guard(remote.late_control)
                with patch('time.monotonic', lambda:100.0+clock['elapsed']), \
                     patch.object(android.subprocess, 'run') as child:
                    with self.assertRaises(installer.Refusal):
                        transport.shell('FICTIONAL-NO-DEVICE', 'payload', mutating=True)
                    self.assertEqual(child.call_count, 0)
                self.assertEqual(transport.calls, 0)


if __name__ == '__main__':
    unittest.main()

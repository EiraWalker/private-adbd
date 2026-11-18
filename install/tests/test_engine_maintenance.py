"""FICTIONAL host Engine/actual MaintenanceClient coverage; no Android acceptance."""
import argparse
import copy
import json
import re
import sys
import unittest
from unittest.mock import patch

from test_installer import profile  # also supplies the standalone test import path
import installer as m
import upgrade
from test_cli import OfflineSDK
import test_engine as fixture
from test_maintenance import BOOT
from android import Transport


WIRE = r'''
import json, os, pathlib, re, shlex, sys
path, mode, apk_version, operation, *args = sys.argv[1:]
if operation == 'fixture-mutation':
    sys.exit(0)
assert operation == 'shell'
outer = shlex.split(args[0])
assert outer[:4] == ['run-as', 'com.termux', '/system/bin/sh', '-c']
verb = re.search(r'com.termux.app.privateadb.MaintenanceCli (request|status|release)', outer[4]).group(1)
p = json.loads(sys.stdin.buffer.read())
state_path = pathlib.Path(path)
s = json.loads(state_path.read_text()) if state_path.exists() else {'events': []}
s['events'].append({'verb': verb, 'apk_version': int(apk_version)})
if mode == 'unsupported':
    reply = {'version': 1, 'error': 'unsupported'}
else:
    if verb == 'request':
        assert 'request' not in s, 'request replay'
        assert len(p) == 8
        s['request'] = p
        s['phase'] = 'active'
    else:
        assert set(p) == {'version', 'token'}
        assert p['token'] == s['request']['token']
    if verb == 'release': s['phase'] = 'released'
    phase = s['phase']
    if phase == 'pending': s['phase'] = 'active'
    reply = dict(s['request'], ownerUid=10123, phase=phase)
    if mode == 'wrong-token': reply['token'] = 'f'*64
    elif mode == 'wrong-owner': reply['ownerUid'] = 10124
    elif mode == 'unknown': reply['phase'] = 'unknown_dispatch'
    elif mode == 'pending': reply['phase'] = 'pending'
    elif mode in ('busy', 'expired', 'revoked', 'released'): reply['phase'] = mode
    elif mode == 'active-reply': reply['phase'] = 'active'
    elif mode == 'wrong-boot': reply['boot'] = '00000000-0000-0000-0000-000000000002'
    elif mode == 'wrong-profile': reply['profileSha256'] = '0'*64
    elif mode == 'wrong-release': reply['releaseSha256'] = '1'*64
    elif mode == 'unbound-released': reply = {'version': 1, 'phase': 'released'}
with os.fdopen(os.open(state_path, os.O_CREAT|os.O_WRONLY|os.O_TRUNC, 0o600), 'w') as f:
    json.dump(s, f)
sys.stdout.buffer.write((json.dumps(reply)+'\n').encode('ascii'))
'''


class MaintenanceTransport(Transport):
    """Real host subprocess/stdin fixture, never Android or an authorized ADB."""
    def __init__(self, remote):
        super().__init__(remote.p, lambda *args: None, execute=True)
        self.remote = remote
        self.path = remote.inputs.out.path/'fictional-wire.json'
        self.mode = 'active'
        self.loss = None
        self.ipcs = []
        self.elapsed = 100000
        self.guard_snapshots = []
        self.mode_by_intent = {}

    def command(self, args):
        cp = json.loads((self.remote.inputs.out.path/'checkpoint.json').read_text())
        mode = self.mode_by_intent.get(cp['intent'], self.mode)
        return [sys.executable, '-S', '-c', WIRE, str(self.path), mode,
                str(self.remote.pkg['version']), *args]

    def shell(self, code, label, data=None, mutating=False, timeout=45):
        if label == 'clock':
            return (BOOT+'\n'+str(self.elapsed//1000)+'.00 100.00\n'+BOOT+'\n').encode()
        return super().shell(code, label, data, mutating, timeout)

    def app(self, code, label, data=None, mutating=False, timeout=45):
        verb = re.search(r'MaintenanceCli (request|status|release)', code).group(1)
        cp = json.loads((self.remote.inputs.out.path/'checkpoint.json').read_text())
        if verb == 'request':
            assert cp['intent'] == 'maintenance-acquire'
            assert json.loads(data) == cp['maintenance']['request']
        if verb == 'release': assert cp['intent'] == 'maintenance-release'
        self.ipcs.append((verb, self.remote.pkg['version'], cp['intent']))
        raw = super().app(code, label, data, mutating, timeout)
        if self.loss == verb:
            raise m.Refusal('FICTIONAL response lost after lifecycle effect')
        return raw


class MaintenanceRemote(fixture.ModelRemote):
    def __init__(self, inputs):
        super().__init__(inputs)
        self.snap['control']['boot'] = BOOT
        self.t = MaintenanceTransport(self)
        self.snapshots = 0
        self.before_dispatch = None
        self.stop_after_snapshot_intent = None

    def bind_guard(self, guard):
        super().bind_guard(guard)
        self.t.before_mutation = guard

    def snapshot(self, allow_missing_native=False):
        self.snapshots += 1
        result = super().snapshot(allow_missing_native)
        cp_path = self.inputs.out.path/'checkpoint.json'
        if cp_path.exists() and self.stop_after_snapshot_intent is not None:
            if json.loads(cp_path.read_text())['intent'] == self.stop_after_snapshot_intent:
                self.late_stop = True
        return result

    def mutate(self, name, action):
        assert self.t.path.exists(), 'maintenance acquisition must precede first upgrade mutation'
        if self.before_dispatch is not None: self.before_dispatch(name)
        count = self.snapshots
        label = 'payload' if name.startswith('payload-') else name
        self.t.call(['fixture-mutation', name], label, mutating=True,
                    timeout=180 if name in ('push', 'install') else 45)
        self.t.guard_snapshots.append(self.snapshots-count)
        self.ops.append(name)
        action()
        if name == 'install':
            state = json.loads(self.t.path.read_text())
            state['phase'] = 'pending'  # Replacement app has lost static acknowledgement.
            self.t.path.write_text(json.dumps(state))
        if self.fail == name: raise m.Refusal('FICTIONAL mutation response lost after effect')


class EngineMaintenanceTests(unittest.TestCase):
    setUp = fixture.EngineTests.setUp
    make_inputs = fixture.EngineTests.make_inputs
    authorize = fixture.EngineTests.authorize
    engine = fixture.EngineTests.engine

    def opt_in(self, **kwargs):
        self.make_inputs(**kwargs)
        (self.root/'release.json').write_text(json.dumps(dict(self.inputs.r, maintenance_api=1)))
        self.inputs = m.Inputs(self.root/'profile.json', self.root/'release.json', OfflineSDK())
        self.inputs.out = self.out
        files = self.remote.files
        self.remote = MaintenanceRemote(self.inputs)
        self.remote.files = files
        self.authorize()

    def checkpoint(self):
        return json.loads((self.out.path/'checkpoint.json').read_text())

    def test_two_version_upgrade_acquires_reacks_releases_with_actual_client(self):
        self.opt_in(payload=True, legacy=True, phase='after_apk')
        self.assertEqual(self.engine().run()['result'], 'upgraded')
        cp = self.checkpoint()
        self.assertEqual(cp['schema'], 2)
        self.assertEqual(cp['done'][0], 'maintenance-acquire')
        self.assertEqual(cp['done'][cp['done'].index('install')+1], 'maintenance-reack')
        self.assertEqual(cp['done'][-1], 'maintenance-release')
        self.assertEqual(cp['phase'], 'complete')
        ipcs = self.remote.t.ipcs
        self.assertEqual(sum(v == 'request' for v, _, _ in ipcs), 1)
        self.assertEqual(sum(v == 'release' for v, _, _ in ipcs), 1)
        self.assertTrue(any(v == 'status' and apk == 2 and intent == 'maintenance-reack'
                            for v, apk, intent in ipcs))
        self.assertEqual(ipcs[-1][0], 'release')
        self.assertTrue(all(n == 1 for n in self.remote.t.guard_snapshots))
        self.assertEqual(cp['maintenance']['request']['baselineVersion'], 1)
        self.assertEqual(cp['maintenance']['request']['targetVersion'], 2)

    def resume(self):
        checkpoint = m.sha((self.out.path/'checkpoint.json').read_bytes())
        self.authorize(checkpoint)
        return self.engine().run(resume=True, checkpoint_hash=checkpoint)

    def test_unknown_install_resume_preserves_record_and_reacks_without_reinstall(self):
        self.opt_in(payload=True, phase='after_apk')
        self.remote.fail = 'install'
        with self.assertRaises(m.Refusal): self.engine().run()
        cp = self.checkpoint()
        self.assertEqual(cp['intent'], 'install')
        original = copy.deepcopy(cp['maintenance'])
        self.remote.fail = None
        self.assertEqual(self.resume()['result'], 'upgraded')
        self.assertEqual(self.checkpoint()['maintenance'], original)
        self.assertEqual(self.remote.ops.count('install'), 1)
        self.assertEqual(sum(v == 'request' for v, _, _ in self.remote.t.ipcs), 1)
        self.assertTrue(any(v == 'status' and version == 2 and intent == 'maintenance-reack'
                            for v, version, intent in self.remote.t.ipcs))

    def test_unknown_acquire_resume_uses_status_only_original_record(self):
        self.opt_in()
        self.remote.t.loss = 'request'
        with self.assertRaises(m.Refusal): self.engine().run()
        cp = self.checkpoint()
        self.assertEqual(cp['intent'], 'maintenance-acquire')
        self.assertEqual(self.remote.ops, [])
        self.remote.t.loss = None
        self.assertEqual(self.resume()['result'], 'upgraded')
        self.assertEqual(self.checkpoint()['maintenance'], cp['maintenance'])
        self.assertEqual(sum(v == 'request' for v, _, _ in self.remote.t.ipcs), 1)

    def test_unknown_release_requires_exact_released_status_never_replays(self):
        self.opt_in()
        self.remote.t.loss = 'release'
        with self.assertRaises(m.Refusal): self.engine().run()
        cp = self.checkpoint()
        self.assertEqual(cp['intent'], 'maintenance-release')
        self.assertEqual(self.remote.ops[-2:], ['stage-clean', 'lock-release'])
        self.remote.t.loss = None
        self.assertEqual(self.resume()['result'], 'upgraded')
        self.assertEqual(self.checkpoint()['maintenance'], cp['maintenance'])
        self.assertEqual(sum(v == 'release' for v, _, _ in self.remote.t.ipcs), 1)
        prior = list(self.remote.t.ipcs)
        raw = (self.out.path/'checkpoint.json').read_bytes()
        self.remote.t.elapsed = 800000  # Already released is not an active lease.
        self.assertEqual(self.resume()['result'], 'already-current')
        self.assertEqual(self.remote.t.ipcs, prior)
        self.assertEqual((self.out.path/'checkpoint.json').read_bytes(), raw)
        self.remote.late_stop = True
        with self.assertRaises(m.Refusal): self.resume()
        self.assertEqual(self.remote.t.ipcs, prior)

    def test_lost_release_after_original_expiry_resumes_exact_terminal_without_mutation(self):
        self.opt_in(payload=True, legacy=True, phase='after_apk')
        self.remote.t.loss = 'release'
        with self.assertRaises(m.Refusal): self.engine().run()
        raw = (self.out.path/'checkpoint.json').read_bytes()
        original = self.checkpoint()
        request_wire = json.dumps(original['maintenance']['request'], sort_keys=True)
        self.assertEqual(original['intent'], 'maintenance-release')
        self.assertEqual(json.loads(self.remote.t.path.read_text())['phase'], 'released')
        operations, prior = list(self.remote.ops), list(self.remote.t.ipcs)
        self.remote.t.loss = None
        self.remote.t.elapsed = original['maintenance']['request']['deadlineElapsedMs']+100000
        # The old apply handoff cannot authorize even terminal-only observation.
        with self.assertRaises(m.Refusal):
            self.engine().run(resume=True, checkpoint_hash=m.sha(raw))
        self.assertEqual(self.remote.t.ipcs, prior)
        try:
            result = self.resume()
        except m.Refusal as exc:
            self.fail('exact bound released must reconcile after expiry: '+str(exc))
        self.assertEqual(result['result'], 'upgraded')
        final = self.checkpoint()
        self.assertEqual(final['phase'], 'complete')
        self.assertIsNone(final['intent'])
        self.assertEqual(final['done'], original['done']+['maintenance-release'])
        self.assertEqual(final['maintenance'], original['maintenance'])
        self.assertEqual(json.dumps(final['maintenance']['request'], sort_keys=True), request_wire)
        self.assertEqual(self.remote.ops, operations)
        self.assertEqual(self.remote.t.ipcs[len(prior):], [('status', 2, 'maintenance-release')])
        self.assertTrue((self.out.path/'receipt.json').exists())

    def test_release_unknown_negative_status_does_not_turn_green_or_replay(self):
        self.opt_in()
        self.remote.t.loss = 'release'
        with self.assertRaises(m.Refusal): self.engine().run()
        original = self.checkpoint()
        self.remote.t.loss = None
        self.remote.t.elapsed = original['maintenance']['request']['deadlineElapsedMs']+100000
        operations = list(self.remote.ops)
        for mode in ('active-reply', 'pending', 'expired', 'revoked', 'unbound-released',
                     'wrong-token', 'wrong-owner', 'wrong-boot', 'wrong-profile', 'wrong-release', 'busy', 'unknown'):
            self.remote.t.mode = mode
            before = len(self.remote.t.ipcs)
            with self.subTest(mode=mode), self.assertRaises(m.Refusal): self.resume()
            self.assertEqual(len(self.remote.t.ipcs), before+1)
            self.assertEqual(self.checkpoint(), original)
            self.assertEqual(self.remote.ops, operations)
            self.assertFalse((self.out.path/'receipt.json').exists())
        self.assertEqual(sum(v == 'release' for v, _, _ in self.remote.t.ipcs), 1)
        self.assertEqual(sum(v == 'request' for v, _, _ in self.remote.t.ipcs), 1)

    def test_unsent_release_intent_with_active_server_cannot_be_completed_or_replayed(self):
        self.opt_in()
        self.remote.t.mode_by_intent['maintenance-release'] = 'pending'
        with self.assertRaises(m.Refusal): self.engine().run()
        original = self.checkpoint()
        operations = list(self.remote.ops)
        self.assertEqual(original['intent'], 'maintenance-release')
        self.assertEqual(sum(v == 'release' for v, _, _ in self.remote.t.ipcs), 0)
        self.assertEqual(json.loads(self.remote.t.path.read_text())['phase'], 'active')
        self.remote.t.mode_by_intent.clear()
        self.remote.t.elapsed = original['maintenance']['request']['deadlineElapsedMs']+100000
        before = len(self.remote.t.ipcs)
        with self.assertRaises(m.Refusal): self.resume()
        self.assertEqual(self.remote.t.ipcs[before:], [('status', 2, 'maintenance-release')])
        self.assertEqual(self.remote.ops, operations)
        self.assertEqual(self.checkpoint(), original)
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_terminal_release_preserves_final_runtime_and_stop_gates(self):
        self.opt_in()
        self.remote.t.loss = 'release'
        with self.assertRaises(m.Refusal): self.engine().run()
        original = self.checkpoint()
        self.remote.t.loss = None
        self.remote.t.elapsed = original['maintenance']['request']['deadlineElapsedMs']+100000
        operations = list(self.remote.ops)
        original_app = self.remote.t.app
        def drift_after_terminal(*args, **kwargs):
            reply = original_app(*args, **kwargs)
            self.remote.snap['pids']['FICTIONAL'] = 'changed-after-terminal'
            return reply
        self.remote.t.app = drift_after_terminal
        with self.assertRaises(m.Refusal): self.resume()
        self.assertEqual(self.checkpoint(), original)
        self.assertEqual(self.remote.ops, operations)
        self.assertFalse((self.out.path/'receipt.json').exists())
        self.remote.snap['pids']['FICTIONAL'] = 'unchanged'
        self.remote.t.app = original_app
        self.remote.late_stop = True
        prior = list(self.remote.t.ipcs)
        with self.assertRaises(m.Refusal): self.resume()
        self.assertEqual(self.remote.t.ipcs, prior)
        self.assertEqual(self.checkpoint(), original)

    def test_terminal_release_checkpoint_phase_prefix_hash_and_target_are_not_exempt(self):
        self.opt_in()
        self.remote.t.loss = 'release'
        with self.assertRaises(m.Refusal): self.engine().run()
        original = self.checkpoint()
        self.remote.t.loss = None
        self.remote.t.elapsed = original['maintenance']['request']['deadlineElapsedMs']+100000
        prior, operations = list(self.remote.t.ipcs), list(self.remote.ops)
        bad = []
        cp = copy.deepcopy(original); cp['done'].pop(); bad.append(cp)
        cp = copy.deepcopy(original); cp['phase'] = 'complete'; bad.append(cp)
        cp = copy.deepcopy(original); cp['maintenance']['request']['targetVersion'] = 3; bad.append(cp)
        cp = copy.deepcopy(original); cp['maintenance']['control']['lease_sha256'] = 'f'*64; bad.append(cp)
        for index, cp in enumerate(bad):
            self.out.write('checkpoint.json', cp)
            with self.subTest(case=index), self.assertRaises(m.Refusal): self.resume()
            self.assertEqual(self.remote.t.ipcs, prior)
            self.assertEqual(self.checkpoint(), cp)
        self.out.write('checkpoint.json', original)
        raw = (self.out.path/'checkpoint.json').read_bytes()
        checkpoint_hash = m.sha(raw)
        self.authorize(checkpoint_hash)
        self.out.target('checkpoint.json').write_bytes(raw+b' ')
        with self.assertRaises(m.Refusal): self.engine().run(resume=True, checkpoint_hash=checkpoint_hash)
        self.out.target('checkpoint.json').write_bytes(raw)
        target = copy.deepcopy(self.remote.pkg)
        self.remote.pkg = copy.deepcopy(original['baseline_package'])
        with self.assertRaises(m.Refusal): self.resume()
        self.remote.pkg = target
        self.assertEqual(self.remote.t.ipcs, prior)
        self.assertEqual(self.remote.ops, operations)
        self.assertEqual(self.checkpoint(), original)
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_late_stop_after_terminal_reply_snapshot_prevents_done_and_receipt(self):
        self.opt_in()
        self.remote.t.loss = 'release'
        with self.assertRaises(m.Refusal): self.engine().run()
        original = self.checkpoint()
        self.remote.t.loss = None
        self.remote.t.elapsed = original['maintenance']['request']['deadlineElapsedMs']+100000
        prior, operations = len(self.remote.t.ipcs), list(self.remote.ops)
        original_app = self.remote.t.app
        def arm_stop_after_terminal(*args, **kwargs):
            raw = original_app(*args, **kwargs)
            self.remote.stop_after_snapshot_intent = 'maintenance-release'
            return raw
        self.remote.t.app = arm_stop_after_terminal
        with self.assertRaises(m.Refusal): self.resume()
        self.assertTrue(self.remote.late_stop)
        self.assertEqual(self.remote.t.ipcs[prior:], [('status', 2, 'maintenance-release')])
        self.assertEqual(self.checkpoint(), original)
        self.assertEqual(self.remote.ops, operations)
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_unsupported_old_helper_stops_before_every_payload_and_install(self):
        self.opt_in(payload=True)
        self.remote.t.mode = 'unsupported'
        from maintenance import MaintenanceUnsupported
        with self.assertRaises(MaintenanceUnsupported): self.engine().run()
        self.assertEqual(self.remote.ops, [])
        self.assertEqual(self.remote.t.ipcs, [('request', 1, 'maintenance-acquire')])
        self.assertEqual(self.checkpoint()['intent'], 'maintenance-acquire')
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_guard_never_polls_pending_or_accepts_foreign_or_expired_ack(self):
        for mode in ('pending', 'expired', 'wrong-token', 'wrong-owner', 'busy', 'unknown'):
            self.opt_in(payload=True)
            self.remote.t.mode_by_intent['acquire-lock'] = mode
            with self.subTest(mode=mode), self.assertRaises(m.Refusal): self.engine().run()
            self.assertEqual(self.remote.ops, [])
            calls = [x for x in self.remote.t.ipcs if x[2] == 'acquire-lock']
            self.assertEqual(calls, [('status', 1, 'acquire-lock')])
            self.assertEqual(self.checkpoint()['intent'], 'acquire-lock')

    def test_install_budget_uses_actual_180_seconds_plus_margin(self):
        self.opt_in()
        def elapsed(name):
            if name == 'install': self.remote.t.elapsed = 500000
        self.remote.before_dispatch = elapsed
        with self.assertRaises(m.Refusal): self.engine().run()
        self.assertNotIn('install', self.remote.ops)
        self.assertEqual(self.checkpoint()['intent'], 'install')

    def test_late_stop_after_full_snapshot_is_terminal_before_first_mutation(self):
        self.opt_in()
        self.remote.stop_after_snapshot_intent = 'acquire-lock'
        with self.assertRaises(m.Refusal): self.engine().run()
        self.assertEqual(self.remote.ops, [])
        self.assertEqual(self.checkpoint()['intent'], 'acquire-lock')

    def test_prepare_failure_preserves_original_refusal_without_fake_checkpoint(self):
        self.opt_in()
        self.remote.snap['control']['boot'] = 'FICTIONAL-invalid-boot'
        with self.assertRaises(m.Refusal): self.engine().run()
        self.assertEqual(self.remote.ops, [])
        self.assertFalse((self.out.path/'checkpoint.json').exists())

    def test_slow_final_late_gates_cannot_spend_the_dispatch_deadline(self):
        self.opt_in()
        clock = {'elapsed': 0, 'late_reads': 0}
        original = self.remote.late_control
        def slow_late():
            cp_path = self.out.path/'checkpoint.json'
            if cp_path.exists() and self.checkpoint()['intent'] == 'install':
                if self.remote.t.ipcs[-1][2] == 'install':
                    clock['late_reads'] += 1
                    # Post-status preflight has two reads; the third is the
                    # Engine's final late gate, after the fresh active ack.
                    if clock['late_reads'] == 3: clock['elapsed'] += 31
            return original()
        self.remote.late_control = slow_late
        with patch('time.monotonic', lambda: 100+clock['elapsed']):
            with self.assertRaises(m.Refusal): self.engine().run()
        self.assertNotIn('install', self.remote.ops)
        self.assertEqual(self.checkpoint()['intent'], 'install')

    def test_checkpoint_load_rejects_malformed_original_record_and_phase_without_ipc(self):
        self.opt_in()
        self.remote.fail = 'install'
        with self.assertRaises(m.Refusal): self.engine().run()
        baseline = self.checkpoint()
        bad = []
        for field in ('request', 'control'):
            cp = copy.deepcopy(baseline); del cp['maintenance'][field]; bad.append(cp)
        for key, value in (('version', True), ('deadlineElapsedMs', 1.0),
                           ('baselineVersion', 2), ('targetVersion', 3),
                           ('profileSha256', '0'*64), ('token', 'f'*63)):
            cp = copy.deepcopy(baseline); cp['maintenance']['request'][key] = value; bad.append(cp)
        cp = copy.deepcopy(baseline); del cp['before']['control']['flags']; bad.append(cp)
        cp = copy.deepcopy(baseline); cp['done'].append('install')
        cp['phase'] = cp['intent'] = 'maintenance-reack'; bad.append(cp)
        cp = copy.deepcopy(baseline); cp['schema'] = 1; bad.append(cp)
        cp = copy.deepcopy(baseline); cp['done'].append('maintenance-release'); bad.append(cp)
        for index, cp in enumerate(bad):
            self.out.write('checkpoint.json', cp)
            prior = list(self.remote.t.ipcs)
            with self.subTest(case=index), self.assertRaises(m.Refusal): self.resume()
            self.assertEqual(self.remote.t.ipcs, prior)

    def test_api_already_current_is_not_a_maintenance_upgrade_receipt(self):
        self.opt_in()
        self.remote.pkg.update(version=self.inputs.r['version'], sha256=self.inputs.r['sha256'])
        self.assertEqual(self.engine().run()['result'], 'already-current')
        self.assertEqual(self.remote.t.ipcs, [])
        self.assertEqual(self.remote.ops, [])
        self.assertFalse((self.out.path/'checkpoint.json').exists())
        receipt = json.loads((self.out.path/'receipt.json').read_text())
        self.assertEqual(receipt['result'], 'already-current')

    def test_unknown_native_start_is_reconciled_without_restarting(self):
        self.opt_in()
        self.remote.fail = 'native-start'
        with self.assertRaises(m.Refusal): self.engine().run()
        original = self.checkpoint()
        self.remote.fail = None
        self.assertEqual(self.resume()['result'], 'upgraded')
        self.assertEqual(self.remote.ops.count('native-start'), 1)
        self.assertEqual(self.checkpoint()['maintenance'], original['maintenance'])

    def test_lease_does_not_exempt_any_original_pid_or_json_type(self):
        self.opt_in()
        self.remote.snap['control']['extension'] = {'enabled': True}
        def drift(name):
            self.remote.snap['control']['extension']['enabled'] = 1
        self.remote.before_dispatch = drift
        with self.assertRaises(m.Refusal): self.engine().run()
        self.assertEqual(self.remote.ops, [])

    def test_every_actual_android_upgrade_mutation_requires_transport_guard(self):
        from android import AndroidRemote
        class GateTransport(Transport):
            # Only preliminary read-only stage probes are synthetic. Every
            # mutation must still reach the real Transport.call dispatch gate.
            def shell(self, code, label, data=None, mutating=False, timeout=45):
                if not mutating: return b''
                return super().shell(code, label, data, mutating, timeout)
        transport = GateTransport(self.inputs.p, lambda *args: None, execute=True)
        remote = AndroidRemote(self.inputs, self.out, transport=transport)
        class DispatchBlocked(Exception): pass
        guarded = []
        def stop():
            guarded.append(True)
            raise DispatchBlocked()
        remote.bind_guard(stop)
        remote.stage_owned = lambda *args, **kwargs: True
        remote.key_metadata = lambda: '0'*64
        token = 'a'*32
        payload = {'path': m.MANAGER, 'before_sha256': None, 'sha256': m.sha(b'FICTIONAL payload'),
                   'mode': '700'}
        self.inputs.payloads[m.MANAGER] = b'FICTIONAL payload'
        old = {'path': m.BIN+'tablet-daemon', 'sha256': '0'*64, 'mode': '700'}
        methods = [lambda: remote.acquire_lock(token), lambda: remote.reserve_stage(token),
                   lambda: remote.push_apk(token), lambda: remote.seal_stage(token),
                   lambda: remote.install_apk(token), lambda: remote.write_payload(payload, token),
                   remote.start_native, lambda: remote.remove_legacy(old),
                   lambda: remote.clean_stage(token), lambda: remote.release_lock(token)]
        for method in methods:
            with self.assertRaises(DispatchBlocked): method()
        self.assertEqual(len(guarded), len(methods))
        self.assertEqual(remote.calls, 0)

    def test_native_guard_rejects_equal_number_with_different_json_type(self):
        self.opt_in()
        def drift(name):
            if name == 'acquire-lock':
                self.remote.snap['native']['starttime'] = float(self.remote.snap['native']['starttime'])
        self.remote.before_dispatch = drift
        with self.assertRaises(m.Refusal): self.engine().run()
        self.assertEqual(self.remote.ops, [])

    def test_release_opt_in_is_type_strict_and_plan_never_constructs_remote(self):
        obj = dict(self.inputs.r, maintenance_api=1)
        self.assertEqual(m.validate_release(obj, self.root), obj)
        for value in (True, False, 0, 2, 1.0, '1', None):
            with self.subTest(value=value), self.assertRaises(m.Refusal):
                m.validate_release(dict(obj, maintenance_api=value), self.root)
        (self.root/'release.json').write_text(json.dumps(obj))
        def forbidden(*args):
            self.fail('offline maintenance plan constructed a remote')
        for command in ('plan', 'apply', 'resume'):
            args = argparse.Namespace(command=command, profile=self.root/'profile.json',
                release=self.root/'release.json', output=self.root/('plan-'+command),
                execute=False, maintenance=None, checkpoint_sha256=None,
                apksigner_argv='[]', aapt_argv='[]')
            result = m.run(args, remote_factory=forbidden, sdk=OfflineSDK())
            self.assertEqual(result['device_calls'], 0)
            ops = result['operations']
            self.assertLess(ops.index('maintenance-acquire'), ops.index('owned-lock'))
            self.assertLess(ops.index('install-r-once'), ops.index('maintenance-reack'))
            self.assertEqual(ops[-1], 'maintenance-release')


if __name__ == '__main__':
    unittest.main()

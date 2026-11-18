"""Fictional package readiness models; no Android/device acceptance claims."""
import copy
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android
import common
import test_engine as fixture
import upgrade


class ReadinessTests(unittest.TestCase):
    setUp = fixture.EngineTests.setUp
    make_inputs = fixture.EngineTests.make_inputs
    authorize = fixture.EngineTests.authorize
    engine = fixture.EngineTests.engine

    def test_confirmed_install_retries_only_unavailable_package_once(self):
        original = self.remote.package
        observations = []
        def package(*, deadline=None, expected_version=None):
            if self.remote.ops.count('install') == 1:
                observations.append(deadline)
                if len(observations) == 1:
                    raise common.ObservationUnavailable('FICTIONAL read unavailable')
            return original()
        self.remote.package = package
        with patch.object(upgrade.time, 'sleep'):
            result = self.engine().run()
        self.assertEqual(result['result'], 'upgraded')
        self.assertEqual(self.remote.ops.count('install'), 1)
        self.assertEqual(self.remote.ops.count('native-start'), 1)
        self.assertIsNotNone(observations[0])
        self.assertEqual(observations[0], observations[1])
        self.assertIsNone(observations[2])  # Ordinary guard is not a retry scope.
        self.assertEqual(json.loads((self.out.path/'checkpoint.json').read_text())['phase'], 'complete')


    def after_install_package(self, response):
        original = self.remote.package
        seen = []
        def package(*, deadline=None, expected_version=None):
            if deadline is not None:
                seen.append((deadline, expected_version))
                return response(len(seen))
            return original()
        self.remote.package = package
        return seen

    def assert_install_pending(self):
        cp = json.loads((self.out.path/'checkpoint.json').read_text())
        self.assertEqual(cp['intent'], 'install')
        self.assertNotIn('install', cp['done'])
        self.assertFalse(cp['apk_confirmed'])
        self.assertEqual(self.remote.ops.count('install'), 1)
        self.assertNotIn('native-start', self.remote.ops)
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_continuous_unavailability_is_three_attempts_without_success(self):
        def unavailable(attempt):
            raise common.ObservationUnavailable('FICTIONAL unavailable')
        seen = self.after_install_package(unavailable)
        with patch.object(upgrade.time, 'sleep') as sleep:
            with self.assertRaises(common.Refusal):
                self.engine().run()
        self.assertEqual(len(seen), 3)
        self.assertEqual(len({x[0] for x in seen}), 1)
        self.assertEqual(sleep.call_count, 2)
        self.assert_install_pending()

    def test_expired_total_budget_does_not_open_another_read_window(self):
        clock = [100.0]
        def unavailable(attempt):
            clock[0] += 15
            raise common.ObservationUnavailable('FICTIONAL timeout')
        seen = self.after_install_package(unavailable)
        with patch.object(upgrade.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(upgrade.time, 'sleep') as sleep:
            with self.assertRaises(common.Refusal):
                self.engine().run()
        self.assertEqual(len(seen), 1)
        sleep.assert_not_called()
        self.assert_install_pending()

    def test_valid_baseline_version_is_not_polled_until_target(self):
        baseline = copy.deepcopy(self.remote.pkg)
        seen = self.after_install_package(lambda attempt: baseline)
        with self.assertRaises(common.Refusal):
            self.engine().run()
        self.assertEqual(len(seen), 1)
        self.assert_install_pending()

    def test_valid_wrong_target_hash_is_not_polled_until_match(self):
        seen = self.after_install_package(lambda attempt: {**self.remote.pkg, 'sha256': '1'*64})
        with self.assertRaises(common.Refusal):
            self.engine().run()
        self.assertEqual(len(seen), 1)
        self.assert_install_pending()

    def test_security_refusal_after_install_is_terminal(self):
        def forbidden(attempt):
            raise common.Refusal('FICTIONAL identity/security/schema denied')
        seen = self.after_install_package(forbidden)
        with patch.object(upgrade.time, 'sleep') as sleep:
            with self.assertRaises(common.Refusal):
                self.engine().run()
        self.assertEqual(len(seen), 1)
        sleep.assert_not_called()
        self.assert_install_pending()

    def test_changed_handoff_after_unavailable_stops_before_next_read(self):
        def unavailable(attempt):
            obj = json.loads(self.auth_path.read_text()); obj['ready'] = False
            self.auth_path.write_text(json.dumps(obj))
            raise common.ObservationUnavailable('FICTIONAL unavailable')
        seen = self.after_install_package(unavailable)
        with patch.object(upgrade.time, 'sleep'):
            with self.assertRaisesRegex(common.Refusal, 'handoff changed'):
                self.engine().run()
        self.assertEqual(len(seen), 1)
        self.assert_install_pending()

    def test_manifest_drift_after_unavailable_stops_before_next_read(self):
        def unavailable(attempt):
            path = self.root/'release.json'
            path.write_bytes(path.read_bytes()+b' ')
            raise common.ObservationUnavailable('FICTIONAL unavailable')
        seen = self.after_install_package(unavailable)
        with patch.object(upgrade.time, 'sleep'):
            with self.assertRaises(common.Refusal):
                self.engine().run()
        self.assertEqual(len(seen), 1)
        self.assert_install_pending()

    def test_expired_handoff_stops_after_wait_before_next_read(self):
        def unavailable(attempt):
            raise common.ObservationUnavailable('FICTIONAL unavailable')
        seen = self.after_install_package(unavailable)
        validate = upgrade.validate_maintenance
        now = [None]
        def check(obj, **kwargs):
            return validate(obj, **kwargs, now=now[0])
        def sleep(seconds):
            now[0] = dt.datetime.fromisoformat(json.loads(self.auth_path.read_text())['expires_at'])+dt.timedelta(seconds=1)
        with patch.object(upgrade, 'validate_maintenance', side_effect=check), patch.object(upgrade.time, 'sleep', side_effect=sleep):
            with self.assertRaises(common.Refusal):
                self.engine().run()
        self.assertEqual(len(seen), 1)
        self.assert_install_pending()

    def test_late_stop_after_read_retry_still_blocks_native_start(self):
        def observe(attempt):
            if attempt == 1:
                raise common.ObservationUnavailable('FICTIONAL unavailable')
            self.remote.late_stop = True
            return copy.deepcopy(self.remote.pkg)
        seen = self.after_install_package(observe)
        with patch.object(upgrade.time, 'sleep'):
            with self.assertRaisesRegex(common.Refusal, 'late Stop'):
                self.engine().run()
        self.assertEqual(len(seen), 2)
        self.assertEqual(self.remote.ops.count('install'), 1)
        self.assertNotIn('native-start', self.remote.ops)
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_unknown_install_outcome_never_enters_read_retry(self):
        self.remote.fail = 'install'
        seen = self.after_install_package(lambda attempt: copy.deepcopy(self.remote.pkg))
        with self.assertRaises(common.Refusal):
            self.engine().run()
        self.assertEqual(seen, [])
        self.assert_install_pending()

    def test_handoff_changed_during_successful_read_is_not_confirmed(self):
        def changed(attempt):
            self.auth_path.write_bytes(self.auth_path.read_bytes()+b' ')
            return copy.deepcopy(self.remote.pkg)
        self.after_install_package(changed)
        with self.assertRaisesRegex(common.Refusal, 'handoff changed'):
            self.engine().run()
        self.assert_install_pending()

    def test_real_host_package_timeout_then_same_fixture_target(self):
        # Real subprocess/timeout and real AndroidRemote parsing; install/runtime
        # remain an explicit lifecycle model, not an Android acceptance receipt.
        tool = self.root/'wire.py'; count = self.root/'hash-count'
        metadata = (self.inputs.p['serial']+'\n2000\nu:r:shell:s0\nEnforcing\n'+str(self.inputs.p['app_uid'])+
                    '\nversionCode=2\n userId='+str(self.inputs.p['app_uid'])+
                    '\npackage:/data/app/FICTIONAL/base.apk\n')
        hash_reply = self.inputs.r['sha256']+'  /data/app/FICTIONAL/base.apk\n'
        tool.write_text('import sys,time\nfrom pathlib import Path\n'+
                        'counter=Path('+repr(str(count))+')\n'+
                        'if "getprop ro.serialno" in sys.argv[-1]:\n sys.stdout.buffer.write('+repr(metadata.encode())+')\n'+
                        'else:\n n=int(counter.read_text()) if counter.exists() else 0\n counter.write_text(str(n+1))\n'+
                        ' if n==0: time.sleep(6)\n sys.stdout.buffer.write('+repr(hash_reply.encode())+')\n')
        p = copy.deepcopy(self.inputs.p)
        p['transport']['argv'] = [sys.executable, '-S', str(tool)]
        transport = android.Transport(p, self.out.event)
        remote = android.AndroidRemote(SimpleNamespace(p=p, r=self.inputs.r), self.out, transport=transport)
        seen = []
        original = self.remote.package
        def package(*, deadline=None, expected_version=None):
            if deadline is not None:
                seen.append((deadline, expected_version))
                return remote.package(deadline=deadline, expected_version=expected_version)
            return original()
        self.remote.package = package
        result = self.engine().run()
        self.assertEqual(result['result'], 'upgraded')
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0][0], seen[1][0])
        self.assertEqual(count.read_text(), '2')
        self.assertEqual(self.remote.ops.count('install'), 1)


class TransportReadinessTests(unittest.TestCase):
    def test_installed_hash_accepts_exact_crlf_record_framing(self):
        from test_remote import WireModel
        from test_installer import profile
        from test_local import release, digest
        p = profile(); t = WireModel(p); original = t.shell
        def shell(code, label, data=None, mutating=False, timeout=45):
            raw = original(code, label, data, mutating, timeout)
            return raw.replace(b'\n', b'\r\n')
        t.shell = shell
        remote = android.AndroidRemote(SimpleNamespace(p=p, r=release()), SimpleNamespace(), transport=t)
        self.assertEqual(remote.package()['sha256'], digest(b'FICTIONAL old APK'))

    def test_installed_hash_rejects_non_record_carriage_return_or_suffix(self):
        from test_remote import WireModel
        from test_installer import profile
        from test_local import release
        for ending in (b'\r', b'\r\r\n', b'\n\n', b'\r\nEXTRA', b'\x00\n'):
            with self.subTest(ending=ending):
                p = profile(); t = WireModel(p); original = t.shell
                def shell(code, label, data=None, mutating=False, timeout=45):
                    raw = original(code, label, data, mutating, timeout)
                    return raw[:-1] + ending if label == 'installed-apk' else raw
                t.shell = shell
                remote = android.AndroidRemote(SimpleNamespace(p=p, r=release()), SimpleNamespace(), transport=t)
                with self.assertRaises(common.Refusal):remote.package()

    def test_package_subcalls_share_deadline_and_five_second_cap(self):
        from test_remote import WireModel
        from test_installer import profile
        from test_local import release
        p = profile(); t = WireModel(p); original = t.shell
        clock = [100.0]; budgets = []
        def shell(code, label, data=None, mutating=False, timeout=45):
            budgets.append(timeout)
            clock[0] += 4
            return original(code, label, data, mutating, timeout)
        t.shell = shell
        remote = android.AndroidRemote(SimpleNamespace(p=p, r=release()), SimpleNamespace(), transport=t)
        with patch.object(android.time, 'monotonic', side_effect=lambda: clock[0]):
            remote.package(deadline=106)
        self.assertEqual(budgets, [5, 2])
        budgets.clear(); clock[0] = 100
        with patch.object(android.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(common.ObservationUnavailable):
                remote.package(deadline=104)
        self.assertEqual(budgets, [4])

    def test_wrong_metadata_version_refuses_before_unavailable_hash(self):
        from test_remote import WireModel
        from test_installer import profile
        from test_local import release
        p = profile(); t = WireModel(p); original = t.shell
        def shell(code, label, data=None, mutating=False, timeout=45):
            if label == 'installed-apk':
                raise common.ObservationUnavailable('FICTIONAL hash unavailable')
            return original(code, label, data, mutating, timeout)
        t.shell = shell
        remote = android.AndroidRemote(SimpleNamespace(p=p, r=release()), SimpleNamespace(), transport=t)
        with self.assertRaises(common.Refusal) as caught:
            remote.package(deadline=android.time.monotonic()+15, expected_version=2)
        self.assertNotIsInstance(caught.exception, common.ObservationUnavailable)
        self.assertEqual([x[0] for x in t.operations], ['package'])

    def test_malformed_hash_response_is_terminal_refusal(self):
        from test_remote import WireModel
        from test_installer import profile
        from test_local import release
        for raw in (b'', b'\xff', b'not-a-hash\n', b'0'*64+b'  /data/app/FICTIONAL/other.apk\n',
                    b'0'*64+b'  /data/app/FICTIONAL/base.apk\nEXTRA\n'):
            with self.subTest(raw=raw):
                p = profile(); t = WireModel(p); original = t.shell
                def shell(code, label, data=None, mutating=False, timeout=45):
                    if label == 'installed-apk':
                        return raw
                    return original(code, label, data, mutating, timeout)
                t.shell = shell
                remote = android.AndroidRemote(SimpleNamespace(p=p, r=release()), SimpleNamespace(), transport=t)
                with self.assertRaises(common.Refusal) as caught:
                    remote.package()
                self.assertNotIsInstance(caught.exception, common.ObservationUnavailable)

    def test_nonzero_permission_and_unknown_host_errors_are_terminal(self):
        from test_installer import profile
        failures = [PermissionError(), OSError('FICTIONAL exec error')]
        failures += [subprocess.CompletedProcess(['FICTIONAL'], 1, b'', err)
                     for err in (b'Permission denied', b'FICTIONAL unknown failure', b'error: device offline')]
        for failure in failures:
            with self.subTest(kind=type(failure).__name__):
                t = android.Transport(profile(), lambda *args: None)
                kwargs = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
                with patch.object(android.subprocess, 'run', **kwargs) as run:
                    with self.assertRaises(common.Refusal) as caught:
                        t.shell('FICTIONAL', 'package')
                self.assertNotIsInstance(caught.exception, common.ObservationUnavailable)
                self.assertEqual(run.call_count, 1)

    def test_arbitrary_status_and_shell_timeout_are_never_retried_by_transport(self):
        from test_installer import profile
        for args, label in ((['status'], 'status'), (['shell', 'FICTIONAL arbitrary command'], 'installed-apk')):
            with self.subTest(label=label):
                t = android.Transport(profile(), lambda *args: None)
                with patch.object(android.subprocess, 'run', side_effect=subprocess.TimeoutExpired('FICTIONAL', 1)) as run:
                    with self.assertRaises(common.Refusal):
                        t.call(args, label)
                self.assertEqual(run.call_count, 1)

    def test_identity_or_schema_rejection_is_not_availability(self):
        from test_remote import WireModel
        from test_installer import profile
        from test_local import release
        variants = [('2000\n', '0\n'), ('u:r:shell:s0', 'u:r:su:s0'), ('Enforcing', 'Permissive'),
                    ('10123', '10124'), ('FICTIONAL-SERIAL-001', 'FICTIONAL-other'),
                    ('versionCode=1', 'versionCode=garbage')]
        for old, new in variants:
            with self.subTest(field=old):
                p = profile(); t = WireModel(p)
                t.package_text = t.package_text.replace(old.encode(), new.encode())
                remote = android.AndroidRemote(SimpleNamespace(p=p, r=release()), SimpleNamespace(), transport=t)
                with self.assertRaises(common.Refusal) as caught:
                    remote.package(deadline=android.time.monotonic()+15, expected_version=2)
                self.assertNotIsInstance(caught.exception, common.ObservationUnavailable)
                self.assertEqual([x[0] for x in t.operations], ['package'])

    def test_timeout_and_spawn_unavailable_are_typed_only_for_reads(self):
        from test_installer import profile
        for exc in (subprocess.TimeoutExpired('FICTIONAL', 0.01), FileNotFoundError()):
            for mutating in (False, True):
                with self.subTest(error=type(exc).__name__, mutating=mutating):
                    t = android.Transport(profile(), lambda *args: None, execute=True)
                    t.before_mutation = lambda: None
                    with patch.object(android.subprocess, 'run', side_effect=exc) as run:
                        with self.assertRaises(common.Refusal) as caught:
                            t.shell('FICTIONAL', 'install' if mutating else 'package', mutating=mutating)
                    self.assertEqual(isinstance(caught.exception, common.ObservationUnavailable), not mutating)
                    self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()

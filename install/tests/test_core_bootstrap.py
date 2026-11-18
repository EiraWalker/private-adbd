"""Fictional host fixtures; no device/official ADB or Android acceptance."""
import base64
import datetime as dt
import importlib.util
import json
import os
import shutil
import socket
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'install'))


def load_core():
    spec = importlib.util.spec_from_file_location('core_bootstrap', ROOT/'install/core_bootstrap.py')
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def public_key(seed=1):
    # Synthetic Android-format public numbers; never a real controller key.
    raw = bytearray(524)
    struct.pack_into('<I', raw, 0, 64)
    raw[8] = seed | 1
    raw[263] = 128
    struct.pack_into('<I', raw, 520, 65537)
    return base64.b64encode(raw) + b' fixture@example.invalid\n'


class LocalPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='core-fixture-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.core = load_core()
        self.serial = 'FIXTURE-SERIAL-001'
        self.profile = {'schema': 1, 'serial': self.serial,
                        'base': '/data/local/tmp/fixture-core',
                        'transport': {'kind': 'adb', 'argv': [str(self.root/'fixture-adb')],
                                      'serial': 'FIXTURE-TRANSPORT-ONLY'}}
        elf = bytearray(64)
        elf[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', elf, 16, 2, 183, 1)
        self.bundle = {'schema': 1, 'artifacts': [self.asset('core-arm64', bytes(elf), abi='arm64-v8a')],
                       'service': self.asset('service.sh', (ROOT/'lifecycle/service.sh').read_bytes()),
                       'keys': self.asset('allow.pub', public_key()),
                       'controller': self.asset('controller.pub', public_key())}
        self.save()

    def asset(self, name, data, **extra):
        (self.root/name).write_bytes(data)
        return {'source': name, 'sha256': self.core.sha(data), **extra}

    def save(self):
        (self.root/'profile.json').write_text(json.dumps(self.profile))
        (self.root/'bundle.json').write_text(json.dumps(self.bundle))

    def inputs(self):
        return self.core.CoreInputs(self.root/'profile.json', self.root/'bundle.json')

    def test_unsafe_base_and_noncanonical_serial_are_not_normalized(self):
        for base in ('/data/local/tmp/a/b', '/data/local/tmp/../evil', '/data/local/tmp/.hidden', '/data/local/tmp/a;id'):
            with self.subTest(base=base):
                self.profile['base'] = base
                self.save()
                with self.assertRaises(self.core.Refusal):
                    self.inputs()
        self.profile['base'] = '/data/local/tmp/fixture-core'
        self.profile['serial'] += '\n'
        self.save()
        with self.assertRaises(self.core.Refusal):
            self.inputs()

    def test_wrong_elf_machine_or_unknown_abi_is_rejected_offline(self):
        for abi, machine in (('arm64-v8a', 62), ('unknown-fixture-abi', 183)):
            with self.subTest(abi=abi):
                data = bytearray((self.root/'core-arm64').read_bytes())
                struct.pack_into('<H', data, 18, machine)
                self.bundle['artifacts'] = [self.asset('core-arm64', bytes(data), abi=abi)]
                self.save()
                with self.assertRaises(self.core.Refusal):
                    self.inputs()

    def test_private_key_pem_is_never_accepted_as_public_policy(self):
        self.bundle['keys'] = self.asset('allow.pub', b'-----BEGIN PRIVATE KEY-----\nfixture-not-a-key\n')
        self.save()
        with self.assertRaises(self.core.Refusal):
            self.inputs()

    def test_hash_or_service_template_drift_fails_offline(self):
        original = (self.root/'core-arm64').read_bytes()
        (self.root/'core-arm64').write_bytes(b'changed')
        with self.assertRaises(self.core.Refusal):
            self.inputs()
        (self.root/'core-arm64').write_bytes(original)
        # A correctly hashed arbitrary service is still not the reviewed contract.
        self.bundle['service'] = self.asset('service.sh', b'BASE=/data/local/tmp/private-adbd\necho invented\n')
        self.save()
        with self.assertRaises(self.core.Refusal):
            self.inputs()

    def test_only_exact_host_loopback_listeners_are_accepted(self):
        self.assertTrue(self.core.loopback_addresses(['127.0.0.1']))
        self.assertTrue(self.core.loopback_addresses(['127.0.0.1', '::1']))
        for rows in ([], ['0.0.0.0'], ['::'], ['127.0.0.1','0.0.0.0'], ['192.0.2.10']):
            self.assertFalse(self.core.loopback_addresses(rows))

    def test_arbitrary_command_prefix_in_transport_is_rejected(self):
        self.profile['transport']['argv'].append('--some-prefix')
        self.save()
        with self.assertRaises(self.core.Refusal):
            self.inputs()

    def test_plan_is_standard_library_offline_even_with_missing_adb(self):
        # Fake executable intentionally does not exist: a subprocess would fail.
        result = subprocess.run([sys.executable, '-S', str(ROOT/'install/core_bootstrap.py'),
                                 'plan', '--profile', str(self.root/'profile.json'),
                                 '--bundle', str(self.root/'bundle.json')], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        obj = json.loads(result.stdout)
        self.assertEqual(obj['device_calls'], 0)
        self.assertFalse(obj['ready'])
        self.assertEqual(obj['supported_abis'], ['arm64-v8a'])
        self.assertNotIn('app_uid', obj)


# The executable fixture is a separate Python subprocess, not a fake Remote.
FAKE_ADB = r'''
import json, pathlib, sys
state_path = pathlib.Path(__file__).with_name('state.json')
s = json.loads(state_path.read_text())
a = sys.argv[1:]
s['calls'].append(a)
def done(out='', code=0):
    state_path.write_text(json.dumps(s))
    sys.stdout.buffer.write(out.encode())
    sys.exit(code)
if len(a) >= 2 and a[0] == '-s':
    selector, a = a[1], a[2:]
else:
    done('missing exact selector', 2)
if a[:2] == ['shell', '-T']:
    script = a[2]
    label = script.splitlines()[0].split(':', 1)[1]
    if label == 'identity':
        if selector.startswith('127.0.0.1:') and s.get('authfail'):
            done('unauthorized', 1)
        done('\n'.join([str(s.get('uid',2000)), s.get('context','u:r:shell:s0'),
                         s.get('enforcing','Enforcing'), s.get('serial','FIXTURE-SERIAL-001'),
                         s.get('abi','arm64-v8a')])+'\n')
    if label in ('listener-absent', 'listener-bound'):
        if s.get('foreign_listener'):
            done('unknown listener', 2)
        done('NO-LISTENER\n' if label == 'listener-absent' else 'BOUND-LISTENER\n')
    if label == 'preflight':
        done('FRESH\n' if not s.get('nonempty') else 'existing base', 0 if not s.get('nonempty') else 2)
    if label == 'push-target':
        done('PUSH-TARGET\n')
    if label == 'reserve':
        s['reserved'] = True
        done('RESERVED\n')
    if label == 'seal':
        s['sealed'] = True
        done('SEALED\n')
    if label == 'publish':
        s['published'] = True
        done('PUBLISHED\n')
    if label == 'files':
        done('FILES\n' if s.get('published') else '', 0 if s.get('published') else 2)
    if label == 'start':
        s['starts'] = s.get('starts',0)+1
        done('' if s.get('loststart') else 'STARTED\n', 1 if s.get('loststart') else 0)
    if label == 'cleanup':
        s['reserved'] = False
        done('CLEAN\n')
    done('unknown fixture command',2)
if a[:1] == ['push']:
    s.setdefault('pushes', []).append(a[-1])
    done('pushed\n')
if a == ['devices']:
    done('List of devices attached\n\n')
if a == ['forward','--list']:
    if s.get('foreign_forward') and s.get('forward'):
        done('FOREIGN-TRANSPORT tcp:45671 tcp:27184\n')
    done(('FIXTURE-TRANSPORT-ONLY tcp:45671 tcp:27184\n' if s.get('forward') else '')+
         'FOREIGN-TRANSPORT tcp:45672 tcp:27184\n')
if a == ['forward','tcp:0','tcp:27184']:
    s['forward'] = True
    done('45671\n')
if a == ['forward','--remove','tcp:45671']:
    s['forward'] = False
    done()
if a == ['connect','127.0.0.1:45671']:
    done('failed to authenticate\n' if s.get('authfail') else 'connected to 127.0.0.1:45671\n')
if a == ['disconnect','127.0.0.1:45671']:
    s['disconnected'] = True
    done('disconnected\n')
done('unsupported fake argv',2)
'''


class SubprocessBootstrapTests(LocalPlanTests):
    def setUp(self):
        super().setUp()
        # Real host-only loopback listener for the OS-level bind-scope check.
        # No Android/ADB/TLS behavior is claimed for this inert socket.
        self.listener = socket.socket()
        self.addCleanup(self.listener.close)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.endpoint = '127.0.0.1:'+str(self.listener.getsockname()[1])
        (self.root/'fake_adb.py').write_text(FAKE_ADB.replace('45671', str(self.listener.getsockname()[1])))
        # Test-only executable adapter: production still accepts ONE trusted executable.
        # Every selected-ADB dispatch runs the fixture as a real child subprocess.
        adapter = ('import sys\nsys.path.insert(0, '+repr(str(ROOT/'install'))+')\n'
                   'import core_bootstrap as core\nreal_run = core.subprocess.run\n'
                   'def fixture_run(args, **kwargs):\n'
                   '    if args[0] != '+repr(str(self.root/'fixture-adb'))+':\n'
                   '        return real_run(args, **kwargs)\n'
                   '    return real_run([sys.executable, '+repr(str(self.root/'fake_adb.py'))+
                   ']+args[1:], **kwargs)\n'
                   'core.subprocess.run = fixture_run\nsys.exit(core.main())\n')
        (self.root/'fixture_cli.py').write_text(adapter)
        self.state: dict[str, Any] = {'calls': []}
        self.save_state()
        now = dt.datetime.now(dt.timezone.utc)
        self.maintenance = {'schema': 1, **self.inputs().bindings, 'serial': self.serial,
                            'owner': 'fixture-owner', 'ready': True, 'released': True, 'no_parallel': True,
                            'issued_at': (now-dt.timedelta(seconds=1)).isoformat(),
                            'expires_at': (now+dt.timedelta(minutes=5)).isoformat()}
        (self.root/'handoff.json').write_text(json.dumps(self.maintenance))

    def save_state(self):
        (self.root/'state.json').write_text(json.dumps(self.state))

    def read_state(self):
        return json.loads((self.root/'state.json').read_text())

    def cli(self, command='apply', execute=True):
        args = [sys.executable, '-S', str(self.root/'fixture_cli.py'), command,
                '--profile', str(self.root/'profile.json'), '--bundle', str(self.root/'bundle.json'),
                '--maintenance', str(self.root/'handoff.json'), '--output', str(self.root/'receipt')]
        if execute:
            args.append('--execute')
        return subprocess.run(args, capture_output=True)

    def test_apply_and_verify_without_execute_make_zero_device_calls(self):
        for command in ('apply', 'verify'):
            result = self.cli(command, execute=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['ready'])
        self.assertEqual(self.read_state()['calls'], [])
        self.assertFalse((self.root/'receipt').exists())

    def test_wrong_handoff_hash_refuses_before_first_device_call(self):
        self.maintenance['profile_sha256'] = '0'*64
        (self.root/'handoff.json').write_text(json.dumps(self.maintenance))
        self.assertEqual(self.cli().returncode, 2)
        self.assertEqual(self.read_state()['calls'], [])

    def test_wrong_identity_or_missing_actual_abi_refuses_before_mutation(self):
        for field, value in (('uid',0), ('context','u:r:untrusted_app:s0'),
                             ('enforcing','Permissive'), ('serial','FIXTURE-OTHER-PHONE'),
                             ('abi','mips64-fixture')):
            with self.subTest(field=field):
                # Each rejected apply has its own private receipt directory.
                self.state = {'calls': [], field: value}
                self.save_state()
                receipt = self.root/'receipt'
                if receipt.exists():
                    receipt.rename(self.root/('rejected-'+field))
                self.assertEqual(self.cli().returncode, 2)
                s = self.read_state()
                self.assertNotIn('reserved', s)
                self.assertNotIn('pushes', s)
                self.assertNotIn('starts', s)

    def test_nonempty_base_is_never_replaced(self):
        self.state['nonempty'] = True
        self.save_state()
        self.assertEqual(self.cli().returncode, 2)
        self.assertNotIn('pushes', self.read_state())
        self.assertNotIn('starts', self.read_state())

    def test_authentication_failure_preserves_deployment_without_readiness(self):
        self.state['authfail'] = True
        self.save_state()
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        s = self.read_state()
        self.assertTrue(s['published'])
        self.assertEqual(s['starts'], 1)
        self.assertFalse(s['forward'])
        self.assertTrue(s['reserved'])
        state = json.loads((self.root/'receipt/core-state.json').read_text())
        self.assertEqual(state['phase'], 'authentication-unverified')
        self.assertNotIn('kill-server', str(s['calls']))

    def test_verify_does_not_allocate_another_forward_after_unknown_owned_cleanup(self):
        self.state['foreign_forward'] = True
        self.save_state()
        self.assertEqual(self.cli().returncode, 2)
        before = len(self.read_state()['calls'])
        self.assertEqual(self.cli('verify').returncode, 2)
        self.assertEqual(len(self.read_state()['calls']), before)

    def test_foreign_forward_is_not_removed_or_disconnected(self):
        self.state['foreign_forward'] = True
        self.save_state()
        self.assertEqual(self.cli().returncode, 2)
        s = self.read_state()
        self.assertTrue(s['forward'])
        self.assertNotIn('disconnected', s)
        self.assertFalse(any('--remove' in c for c in s['calls']))
        state = json.loads((self.root/'receipt/core-state.json').read_text())
        self.assertEqual(state['forward']['outcome'], 'ownership-unknown-left-untouched')

    def test_another_fictional_phone_selects_its_pinned_x86_64_asset(self):
        self.profile['serial'] = 'FIXTURE-SERIAL-X86-002'
        self.state['serial'] = self.profile['serial']
        self.state['abi'] = 'x86_64'
        self.save_state()
        data = bytearray((self.root/'core-arm64').read_bytes())
        struct.pack_into('<H', data, 18, 62)
        self.bundle['artifacts'].append(self.asset('core-x86', bytes(data), abi='x86_64'))
        self.save()
        self.maintenance.update(self.inputs().bindings)
        self.maintenance['serial'] = self.profile['serial']
        (self.root/'handoff.json').write_text(json.dumps(self.maintenance))
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['abi'], 'x86_64')
        self.assertEqual((self.root/'receipt/payload-private-adbd').read_bytes(), bytes(data))
        self.assertEqual((self.root/'receipt/payload-service.serial').read_bytes(),
                         b'FIXTURE-SERIAL-X86-002\n')

    def test_verify_after_lost_start_checks_without_replaying_and_cleans_owned_lock(self):
        self.state['loststart'] = True
        self.save_state()
        self.assertEqual(self.cli().returncode, 2)
        self.assertEqual(self.read_state()['starts'], 1)
        result = self.cli('verify')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.read_state()['starts'], 1)
        self.assertFalse(self.read_state()['reserved'])

    def test_unknown_preexisting_listener_cannot_establish_readiness(self):
        self.state['foreign_listener'] = True
        self.save_state()
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('starts', self.read_state())

    def test_verify_refuses_receipt_payload_policy_substitution(self):
        self.assertEqual(self.cli().returncode, 0)
        p = self.root/'receipt/core-state.json'
        receipt = json.loads(p.read_text())
        receipt['files'] = {}
        p.write_text(json.dumps(receipt))
        before = len(self.read_state()['calls'])
        self.assertEqual(self.cli('verify').returncode, 2)
        self.assertEqual(len(self.read_state()['calls']), before)

    def test_selected_controller_requires_singleton_allowlist(self):
        self.bundle['keys'] = self.asset('allow.pub', public_key()+public_key(3))
        self.save()
        with self.assertRaises(self.core.Refusal):
            self.inputs()

    def test_verify_checks_listener_child_binding_without_replaying_start(self):
        self.assertEqual(self.cli().returncode, 0)
        s = self.read_state()
        s['foreign_listener'] = True
        self.state = s
        self.save_state()
        result = self.cli('verify')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.read_state()['starts'], 1)

    def test_fresh_core_succeeds_without_termux_through_real_subprocess_chain(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        obj = json.loads(result.stdout)
        self.assertTrue(obj['ready'])
        s = self.read_state()
        self.assertEqual(s['starts'], 1)
        self.assertFalse(s['forward'])
        self.assertFalse(s['reserved'])
        self.assertTrue(s['disconnected'])
        self.assertEqual(len(s['pushes']), 4)
        for call in s['calls']:
            self.assertEqual(call[0], '-s')
            self.assertIn(call[1], ['FIXTURE-TRANSPORT-ONLY', self.endpoint])
            self.assertNotIn('kill-server', call)
            self.assertNotIn('keygen', call)
            self.assertNotIn('run-as', call)
        receipt = json.loads((self.root/'receipt/core-state.json').read_text())
        self.assertEqual(receipt['phase'], 'ready')
        self.assertEqual(receipt['bindings'], self.inputs().bindings)
        # Parse the actual generated production shell, not only fixture label dispatch.
        bash = shutil.which('bash') or shutil.which('sh')
        if bash:
            for call in s['calls']:
                if call[2:4] == ['shell', '-T']:
                    checked = subprocess.run([bash, '-n'], input=call[4].encode(), capture_output=True)
                    self.assertEqual(checked.returncode, 0, checked.stderr)


@unittest.skipUnless(os.name == 'posix', 'requires genuine POSIX uid/mode/hardlink semantics; Windows is not coverage')
class PosixFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.core = load_core()
        self.tmp = tempfile.TemporaryDirectory(prefix='core-posix-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root/'data/local/tmp/fixture-core'
        self.base.mkdir(mode=0o700, parents=True)
        self.token = 'a'*32
        (self.base/'.core-bootstrap').write_text(self.token+'\n')
        (self.base/'.core-bootstrap').chmod(0o600)
        self.data = b'fictional-payload\n'
        (self.base/'private-adbd').write_bytes(self.data)
        (self.base/'private-adbd').chmod(0o700)
        self.policy = {'private-adbd': {'sha256': self.core.sha(self.data), 'mode': '700'}}

    def execute(self, body):
        # Translate only generated fixed namespace roots and fixture's own UID.
        # Production exposes neither override.
        script = self.core.shell_script('fixture', body)
        for src, mark in (('/data/local/tmp','__TMP__'), ('/data/local','__LOCAL__'), ('/data','__DATA__')):
            script = script.replace(src, mark)
        for mark, dest in (('__TMP__',self.root/'data/local/tmp'), ('__LOCAL__',self.root/'data/local'), ('__DATA__',self.root/'data')):
            script = script.replace(mark, str(dest))
        script = script.replace('= 2000:', '= '+str(os.getuid())+':')
        script = script.replace('PATH=/system/bin:/system/xbin', 'PATH='+os.environ['PATH'])
        return subprocess.run(['/bin/sh'], input=script.encode(), capture_output=True)

    def checks(self):
        base = '/data/local/tmp/fixture-core'
        return self.core.owned_directory(base,self.token)+self.core.file_checks(base,self.policy,True,exact=True)

    def test_real_owned_namespace_hash_and_permissions(self):
        self.assertEqual(self.execute(self.checks()).returncode, 0)
        (self.base/'private-adbd').chmod(0o755)
        self.assertNotEqual(self.execute(self.checks()).returncode, 0)

    def test_real_symlink_and_hardlink_are_rejected_without_modification(self):
        target = self.base/'private-adbd'
        target.unlink()
        outside = self.root/'outside'
        outside.write_bytes(self.data)
        outside.chmod(0o700)
        target.symlink_to(outside)
        self.assertNotEqual(self.execute(self.checks()).returncode, 0)
        target.unlink()
        os.link(outside,target)
        self.assertNotEqual(self.execute(self.checks()).returncode, 0)
        self.assertEqual(outside.read_bytes(),self.data)

    def test_real_extra_hidden_file_and_marker_tampering_are_rejected(self):
        (self.base/'.unknown').write_text('leave me')
        self.assertNotEqual(self.execute(self.checks()).returncode, 0)
        (self.base/'.unknown').unlink()
        (self.base/'.core-bootstrap').write_text('different owner\n')
        self.assertNotEqual(self.execute(self.checks()).returncode, 0)


if __name__ == '__main__':
    unittest.main()

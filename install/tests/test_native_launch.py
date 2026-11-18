"""Fictional launch-domain fixtures, NOT evidence of Android exec behavior."""
import copy
import json
import types
import unittest
from test_installer import profile
import android as a
import installer as m
from test_local import release, digest
from test_remote import SnapshotWire
import test_engine as engine_fixture

LAUNCH = {'uid':10123, 'context':'u:r:runas_app:s0:c1,c2'}
LAUNCH_COMMAND = 'set -eu; run-as com.termux id -u; run-as com.termux id -Z'


class LaunchWire(SnapshotWire):
    def __init__(self,p):
        super().__init__(p)
        self.launch_bytes=b'10123\nu:r:runas_app:s0:c1,c2\n'
    def shell(self,code,label,*args,**kwargs):
        if code==LAUNCH_COMMAND:
            self.calls+=1;self.operations.append((label,code,False))
            if isinstance(self.launch_bytes,Exception):raise self.launch_bytes
            return self.launch_bytes
        return super().shell(code,label,*args,**kwargs)


class LaunchWireTests(unittest.TestCase):
    def remote(self):
        p=profile();wire=LaunchWire(p)
        remote=a.AndroidRemote(types.SimpleNamespace(p=p,r=release()),types.SimpleNamespace(event=lambda *x:None),transport=wire)
        return remote,wire

    def test_snapshot_captures_fixed_actual_run_as_uid_and_label(self):
        remote,wire=self.remote()
        snap=remote.snapshot()
        self.assertEqual(snap.get('native_launch'),LAUNCH)
        self.assertIn(('process',LAUNCH_COMMAND,False),wire.operations)
        self.assertEqual(snap['native']['context'],'u:r:untrusted_app:s0:c1,c2')

    def test_snapshot_observes_exact_launch_label_not_a_broader_runas_regex(self):
        remote,wire=self.remote()
        wire.files['/proc/201/attr/current']=LAUNCH['context'].encode()
        wire.files['/proc/201/cmdline']=wire.files['/proc/201/cmdline'].replace(b'10\0',b'4\0')
        snap=remote.snapshot(allow_missing_native=True)
        self.assertEqual(snap['native']['context'],LAUNCH['context'])
        self.assertEqual(snap['native']['argv_sha256'],digest(wire.files['/proc/201/cmdline']))
        for context in (b'u:r:runas_app:s0:c1,c3', b'u:r:shell:s0', b'u:r:system_app:s0',
                        b'u:r:su:s0',b'u:r:untrusted_app:s0:c1,c3',b''):
            with self.subTest(context=context):
                wire.files['/proc/201/attr/current']=context
                with self.assertRaises(m.Refusal):remote.snapshot(allow_missing_native=True)

    def test_launch_read_denial_bad_uid_domain_or_mcs_fail_closed(self):
        for raw in (b'',b'10123\n',b'10123\nu:r:shell:s0\n', b'0\nu:r:runas_app:s0:c1,c2\n',
                    b'10124\nu:r:runas_app:s0:c1,c2\n', b'10123\nu:r:system_app:s0:c1,c2\n',
                    b'10123\nu:r:runas_app:s0:c1,c3\n', b'10123\nu:r:runas_app:s0:c1,c2\nextra\n',
                    b'10123\n\xff\n',m.Refusal('FICTIONAL launch label denied')):
            with self.subTest(raw=raw):
                remote,wire=self.remote();wire.launch_bytes=raw
                with self.assertRaises(m.Refusal):remote.snapshot()

    def test_producer_uid_is_independent_of_matching_launch_and_native_label(self):
        remote,wire=self.remote()
        wire.files['/proc/101/status']=b'Uid:\t10123\t10123\t10123\t10123\n'
        with self.assertRaises(m.Refusal):remote.snapshot()

    def test_native_uid_quartet_is_required_independently_of_matching_context(self):
        for fields in ([0]*4,[2000]*4,[10124]*4,
                       *[[10124 if i==j else 10123 for i in range(4)] for j in range(4)]):
            with self.subTest(fields=fields):
                remote,wire=self.remote()
                wire.files['/proc/201/attr/current']=LAUNCH['context'].encode()
                wire.files['/proc/201/status']=('Uid:\t'+'\t'.join(map(str,fields))+'\n').encode()
                with self.assertRaises(m.Refusal):remote.snapshot(allow_missing_native=True)


class LaunchRemote(engine_fixture.ModelRemote):
    """Models an expected exec result; does not assert real Android behavior."""
    def __init__(self,inputs):
        super().__init__(inputs)
        self.snap['native_launch']=copy.deepcopy(LAUNCH)
        self.snap['native']['context']='u:r:untrusted_app_25:s0:c1,c2'
        self.snap['native']['argv_sha256']=digest((m.BIN+'adb').encode()+b'\0-L\0tcp:localhost:5038\0fork-server\0server\0--reply-fd\x004\0')
        self.original=copy.deepcopy(self.snap['native'])
    def native_launch(self):return copy.deepcopy(self.snap['native_launch'])
    def start_native(self):
        def effect():
            self.snap['native']={**self.original,'pid':202,'starttime':110,'context':LAUNCH['context']}
            self.snap['listeners']=['127.0.0.1:27184','127.0.0.1:5038']
        self.mutate('native-start',effect)


class LaunchEngineTests(unittest.TestCase):
    make_inputs=engine_fixture.EngineTests.make_inputs
    authorize=engine_fixture.EngineTests.authorize
    engine=engine_fixture.EngineTests.engine
    def setUp(self):
        engine_fixture.EngineTests.setUp(self)
        self.remote=LaunchRemote(self.inputs)

    def test_controlled_launch_transition_persists_original_and_actual_context(self):
        self.assertEqual(self.engine().run()['result'],'upgraded')
        cp=json.loads((self.out.path/'checkpoint.json').read_text())
        self.assertEqual(cp['before']['native_launch'],LAUNCH)
        self.assertEqual(cp['before']['native']['context'],self.remote.original['context'])
        self.assertEqual(cp['native_after']['context'],LAUNCH['context'])
        self.assertEqual(self.remote.ops.count('native-start'),1)

    def test_guard_rechecks_launch_identity_even_when_native_absent(self):
        e=self.engine();e.new()
        baseline=copy.deepcopy(self.remote.snap)
        # Exercise both pre-APK and missing-native post-APK guards.
        for missing in (False,True):
            self.remote.snap=copy.deepcopy(baseline)
            e.cp['apk_confirmed']=missing
            if missing:
                self.remote.pkg.update(version=self.inputs.r['version'],sha256=self.inputs.r['sha256'])
                self.remote.snap['native']=None;self.remote.snap['listeners']=['127.0.0.1:27184']
            for proof in [None,{}, {**LAUNCH,'uid':10124}, {**LAUNCH,'context':'u:r:runas_app:s0:c1,c3'},
                          {**LAUNCH,'context':'u:r:shell:s0'},{**LAUNCH,'context':'u:r:untrusted_app:s0:c1,c2'}]:
                with self.subTest(missing=missing,proof=proof):
                    self.remote.snap['native_launch']=proof
                    with self.assertRaises(m.Refusal):e.guard()
        self.assertEqual(self.remote.ops,[])

    def test_late_launch_drift_blocks_dispatch_after_snapshot(self):
        e=self.engine();e.new()
        self.remote.native_launch=lambda:{**LAUNCH,'context':'u:r:runas_app:s0:c1,c3'}
        with self.assertRaises(m.Refusal):e.guard()
        self.assertEqual(self.remote.ops,[])

    def test_lost_start_response_resumes_exactly_once_and_complete_resume_keeps_proof(self):
        self.remote.fail='native-start'
        with self.assertRaises(m.Refusal):self.engine().run()
        cp_path=self.out.path/'checkpoint.json';cp=json.loads(cp_path.read_text())
        self.assertEqual(cp['intent'],'native-start');self.assertIsNone(cp['native_after'])
        checkpoint=digest(cp_path.read_bytes());self.authorize(checkpoint);self.remote.fail=None
        self.assertEqual(self.engine().run(resume=True,checkpoint_hash=checkpoint)['result'],'upgraded')
        self.assertEqual(self.remote.ops.count('native-start'),1)
        prior=list(self.remote.ops);raw=cp_path.read_bytes();checkpoint=digest(raw)
        self.authorize(checkpoint)
        self.assertEqual(self.engine().run(resume=True,checkpoint_hash=checkpoint)['result'],'already-current')
        self.assertEqual(self.remote.ops,prior);self.assertEqual(cp_path.read_bytes(),raw)
        self.assertEqual(json.loads(raw)['before']['native_launch'],LAUNCH)

    def test_completed_checkpoint_rejects_forged_phase(self):
        self.engine().run()
        cp_path=self.out.path/'checkpoint.json';cp=json.loads(cp_path.read_text())
        cp['phase']='preflight';self.out.write('checkpoint.json',cp)
        checkpoint=digest(cp_path.read_bytes());self.authorize(checkpoint)
        prior=list(self.remote.ops)
        with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
        self.assertEqual(self.remote.ops,prior)

    def pending_start(self):
        self.remote.fail='native-start'
        with self.assertRaises(m.Refusal):self.engine().run()
        self.remote.fail=None
        return json.loads((self.out.path/'checkpoint.json').read_text()),copy.deepcopy(self.remote.snap)

    def test_uncertain_start_resume_refuses_every_nonexact_identity_without_replay(self):
        cp,snap=self.pending_start();prior=list(self.remote.ops)
        variants=[('native',None),('native.pid',201),('native.starttime',100),('native.starttime',99),
                  ('native.uid',0),('native.uid',2000),('native.uid',10124),
                  ('native.exe','/system/bin/adb'),('native.inode','1:201'),
                  ('native.argv_sha256',digest((m.BIN+'adb').encode()+b'\0-L\0tcp:localhost:5038\0fork-server\0server\0--reply-fd\x0010\0')),
                  ('native.listener','0.0.0.0:5038'),('native.context','u:r:shell:s0'),
                  ('native.context','u:r:su:s0'),('native.context','u:r:system_app:s0:c1,c2'),
                  ('native.context','u:r:runas_app:s0:c1,c3'),('native.context','u:r:untrusted_app_26:s0:c1,c2'),
                  ('native_launch',None),('native_launch.uid',10124),('native_launch.context','u:r:runas_app:s0:c1,c3'),
                  ('listeners',['127.0.0.1:27184','0.0.0.0:5038']),('key_metadata_sha256','1'*64),
                  ('pids',{'FICTIONAL':'changed'}),('shell_files',{'FICTIONAL':'changed'}),
                  ('wrapper_state',{'FICTIONAL':'changed'}),('control.flags',{'userStopped':'true','safetyPaused':'false'})]
        for field,value in variants:
            with self.subTest(field=field,value=value):
                self.out.write('checkpoint.json',copy.deepcopy(cp))
                self.remote.snap=copy.deepcopy(snap)
                target=self.remote.snap;parts=field.split('.')
                for part in parts[:-1]:target=target[part]
                target[parts[-1]]=value
                if field=='native':self.remote.snap['listeners']=['127.0.0.1:27184']
                checkpoint=digest((self.out.path/'checkpoint.json').read_bytes());self.authorize(checkpoint)
                with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
                self.assertEqual(self.remote.ops,prior)
                saved=json.loads((self.out.path/'checkpoint.json').read_text())
                self.assertIsNone(saved['native_after']);self.assertEqual(saved['intent'],'native-start')
                self.assertFalse((self.out.path/'receipt.json').exists())

    def test_surviving_original_is_not_restarted_and_unknown_launch_replacement_before_intent_refuses(self):
        self.remote.kill_native=False
        self.assertEqual(self.engine().run()['result'],'upgraded')
        self.assertNotIn('native-start',self.remote.ops)
        self.assertIsNone(json.loads((self.out.path/'checkpoint.json').read_text())['native_after'])
        e=self.engine();e.cp=json.loads((self.out.path/'checkpoint.json').read_text())
        self.remote.snap['native']={**self.remote.original,'pid':999,'starttime':999,'context':LAUNCH['context']}
        with self.assertRaises(m.Refusal):e.guard()

    def test_unknown_replacement_after_install_before_native_intent_refuses(self):
        install=self.remote.install_apk
        def replace(token):
            install(token)
            self.remote.snap['native']={**self.remote.original,'pid':999,'starttime':999,'context':LAUNCH['context']}
            self.remote.snap['listeners']=['127.0.0.1:27184','127.0.0.1:5038']
        self.remote.install_apk=replace
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertNotIn('native-start',self.remote.ops)
        self.assertIsNone(json.loads((self.out.path/'checkpoint.json').read_text())['native_after'])

    def test_checkpoint_after_requires_original_launch_proof_and_exact_transition(self):
        self.engine().run()
        cp_path=self.out.path/'checkpoint.json';original=json.loads(cp_path.read_text());prior=list(self.remote.ops)
        changes=[('before.native_launch',None),('before.native_launch',{}),('before.native_launch.uid',10124),
                 ('before.native_launch.context','u:r:runas_app:s0:c1,c3'),('native_after.pid',201),
                 ('native_after.starttime',100),('native_after.argv_sha256','1'*64),
                 ('native_after.inode','1:201'),('native_after.uid',2000),
                 ('native_after.context','u:r:system_app:s0:c1,c2'),
                 ('native_after.context','u:r:runas_app:s0:c1,c3'),('native_after.listener','0.0.0.0:5038')]
        for field,value in changes+[('missing-proof',None),('fake-phase',None)]:
            with self.subTest(field=field):
                cp=copy.deepcopy(original)
                if field=='missing-proof':del cp['before']['native_launch']
                elif field=='fake-phase':
                    cp['done']=cp['done'][:cp['done'].index('native-start')]
                    cp['phase']='native-start';cp['intent']='native-start'
                else:
                    target=cp;parts=field.split('.')
                    for part in parts[:-1]:target=target[part]
                    target[parts[-1]]=value
                self.out.write('checkpoint.json',cp);checkpoint=digest(cp_path.read_bytes());self.authorize(checkpoint)
                with self.assertRaises(m.Refusal):self.engine().load(checkpoint)
                self.assertEqual(self.remote.ops,prior)

    def test_dispatch_late_gate_refuses_changed_launch_after_intent(self):
        start=self.remote.start_native
        def changed_launch():
            self.remote.snap['native_launch']={**LAUNCH,'uid':10124}
            start()
        self.remote.start_native=changed_launch
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertNotIn('native-start',self.remote.ops)
        cp=json.loads((self.out.path/'checkpoint.json').read_text())
        self.assertEqual(cp['intent'],'native-start');self.assertIsNone(cp['native_after'])

    def test_response_loss_reconciliation_rechecks_late_launch_stop_and_target(self):
        cp,snap=self.pending_start();prior=list(self.remote.ops)
        for fault in ('late-launch','late-stop','target-apk'):
            with self.subTest(fault=fault):
                self.remote.snap=copy.deepcopy(snap)
                self.remote.late_stop=False
                self.remote.native_launch=lambda:copy.deepcopy(LAUNCH)
                self.remote.pkg.update(version=self.inputs.r['version'],sha256=self.inputs.r['sha256'])
                if fault=='late-launch':self.remote.native_launch=lambda:{**LAUNCH,'context':'u:r:runas_app:s0:c1,c3'}
                elif fault=='late-stop':self.remote.late_stop=True
                else:self.remote.pkg.update(version=1,sha256=digest(b'FICTIONAL old APK'))
                self.out.write('checkpoint.json',copy.deepcopy(cp))
                checkpoint=digest((self.out.path/'checkpoint.json').read_bytes());self.authorize(checkpoint)
                with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
                self.assertEqual(self.remote.ops,prior)
                self.assertIsNone(json.loads((self.out.path/'checkpoint.json').read_text())['native_after'])

    def test_slow_launch_observation_cannot_make_late_stop_gate_stale(self):
        e=self.engine();e.new()
        def launch_then_stop():
            self.remote.late_stop=True
            return copy.deepcopy(LAUNCH)
        self.remote.native_launch=launch_then_stop
        with self.assertRaises(m.Refusal):e.guard()
        self.assertEqual(self.remote.ops,[])

    def test_final_postcheck_refuses_stop_after_snapshot_control_capture(self):
        snapshot=self.remote.snapshot
        def snapshot_then_stop(allow_missing_native=False):
            result=snapshot(allow_missing_native)
            if 'lock-release' in self.remote.ops:
                self.remote.snap['control']['flags']['userStopped']='true'
            return result
        self.remote.snapshot=snapshot_then_stop
        with self.assertRaises(m.Refusal):self.engine().run()
        cp=json.loads((self.out.path/'checkpoint.json').read_text())
        self.assertNotEqual(cp['phase'],'complete')
        self.assertFalse((self.out.path/'receipt.json').exists())
        self.assertEqual(self.remote.ops.count('native-start'),1)

    def test_complete_resume_refuses_stop_after_postcheck_control_capture(self):
        self.engine().run()
        cp_path=self.out.path/'checkpoint.json';raw=cp_path.read_bytes()
        checkpoint=digest(raw);self.authorize(checkpoint)
        prior=list(self.remote.ops);snapshot=self.remote.snapshot;calls=0
        def snapshot_then_stop(allow_missing_native=False):
            nonlocal calls
            calls+=1
            result=snapshot(allow_missing_native)
            if calls==2:
                self.remote.snap['control']['flags']['userStopped']='true'
            return result
        self.remote.snapshot=snapshot_then_stop
        with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
        self.assertEqual(self.remote.ops,prior)
        self.assertEqual(cp_path.read_bytes(),raw)


if __name__=='__main__':unittest.main()

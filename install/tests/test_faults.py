"""Fault-injection models, explicitly not evidence of Android acceptance."""
import copy
import datetime as dt
import json
import unittest
import test_engine as engine_fixture
from test_local import digest
import installer as m


class FaultTests(unittest.TestCase):
    setUp=engine_fixture.EngineTests.setUp
    make_inputs=engine_fixture.EngineTests.make_inputs
    authorize=engine_fixture.EngineTests.authorize
    engine=engine_fixture.EngineTests.engine

    def test_late_payload_drift_blocks_subsequent_install(self):
        self.make_inputs(payload=True)
        original=self.remote.reserve_stage
        def drift(token):
            self.remote.files[m.MANAGER]=(b'FICTIONAL concurrent edit','700')
            return original(token)
        self.remote.reserve_stage=drift
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertNotIn('stage-reserve',self.remote.ops)
        self.assertNotIn('install',self.remote.ops)

    def test_postinstall_apk_regression_blocks_native_dispatch(self):
        original=self.remote.start_native
        def drift():
            self.remote.pkg.update(version=1,sha256=digest(b'FICTIONAL old APK'))
            return original()
        self.remote.start_native=drift
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertNotIn('native-start',self.remote.ops)

    def test_final_readback_rejects_recreated_legacy_command(self):
        self.make_inputs(payload=True,legacy=True)
        original=self.remote.release_lock
        def recreate(token):
            original(token)
            self.remote.files[m.BIN+'tablet-daemon']=(b'FICTIONAL unexpected recreation','700')
        self.remote.release_lock=recreate
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_corrupt_checkpoint_shapes_are_refused_before_mutation(self):
        self.remote.fail='install'
        with self.assertRaises(m.Refusal):self.engine().run()
        path=self.out.path/'checkpoint.json';original=json.loads(path.read_text());prior=list(self.remote.ops)
        variants=[('schema',True),('token','../escape'),('done',['install']),('intent','unknown'),
                  ('bindings',{}),('before',{}),('baseline_package',[]),('native_after',[]),
                  ('backups',{'arbitrary':{}}),('apk_confirmed',True),('phase','complete')]
        for key,value in variants:
            with self.subTest(key=key):
                cp=copy.deepcopy(original);cp[key]=value;self.out.write('checkpoint.json',cp)
                checkpoint=digest(path.read_bytes());self.authorize(checkpoint)
                with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
                self.assertEqual(self.remote.ops,prior)

    def test_native_start_unconfirmed_without_server_never_retries(self):
        original=self.remote.mutate
        def timeout(name,action):
            if name=='native-start':
                self.remote.ops.append(name)
                raise m.Refusal('FICTIONAL timeout before confirmed server')
            return original(name,action)
        self.remote.mutate=timeout
        with self.assertRaises(m.Refusal):self.engine().run()
        checkpoint=digest((self.out.path/'checkpoint.json').read_bytes());self.authorize(checkpoint)
        prior=list(self.remote.ops)
        with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
        self.assertEqual(self.remote.ops,prior)
        self.assertEqual(self.remote.ops.count('native-start'),1)
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_uncertain_install_still_at_baseline_never_replays(self):
        original=self.remote.mutate
        def timeout(name,action):
            if name=='install':
                self.remote.ops.append(name);raise m.Refusal('FICTIONAL uncertain install')
            return original(name,action)
        self.remote.mutate=timeout
        with self.assertRaises(m.Refusal):self.engine().run()
        checkpoint=digest((self.out.path/'checkpoint.json').read_bytes());self.authorize(checkpoint)
        prior=list(self.remote.ops)
        with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
        self.assertEqual(self.remote.ops,prior)

    def test_durable_completed_checkpoint_cut_resumes_without_repush(self):
        original=self.out.write
        def cut(name,obj):
            original(name,obj)
            if name=='checkpoint.json' and obj['done'] and obj['done'][-1]=='push' and obj['intent'] is None:
                raise OSError('FICTIONAL host cut after durable completion')
        self.out.write=cut
        with self.assertRaises(OSError):self.engine().run()
        self.out.write=original
        checkpoint=digest((self.out.path/'checkpoint.json').read_bytes());self.authorize(checkpoint)
        self.assertEqual(self.engine().run(resume=True,checkpoint_hash=checkpoint)['result'],'upgraded')
        self.assertEqual(self.remote.ops.count('push'),1)

    def test_native_rebuild_cannot_claim_original_pid_identity(self):
        original=self.remote.start_native
        old=copy.deepcopy(self.remote.snap['native'])
        def wrong_identity():
            original();self.remote.snap['native']=old
        self.remote.start_native=wrong_identity
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_stop_after_slow_snapshot_is_refreshed_before_dispatch(self):
        original=self.remote.snapshot;count=0
        def stale_snapshot(allow_missing_native=False):
            nonlocal count
            value=original(allow_missing_native);count+=1
            if count>=2:self.remote.late_stop=True
            return value
        self.remote.snapshot=stale_snapshot
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertEqual(self.remote.ops,[])

    def test_unknown_native_replacement_is_not_adopted(self):
        original=self.remote.install_apk
        def install(token):
            original(token)
            self.remote.snap['native']={**json.loads((self.out.path/'checkpoint.json').read_text())['before']['native'],'pid':999,'starttime':999}
            self.remote.snap['listeners']=['127.0.0.1:27184','127.0.0.1:5038']
        self.remote.install_apk=install
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertNotIn('native-start',self.remote.ops)
        self.assertFalse((self.out.path/'receipt.json').exists())

    def test_surviving_native_server_is_not_restarted(self):
        self.remote.kill_native=False
        self.assertEqual(self.engine().run()['result'],'upgraded')
        self.assertNotIn('native-start',self.remote.ops)

    def test_maintenance_is_reread_after_intent_before_dispatch(self):
        original=self.remote.mutate
        def edit_owner(name,action):
            if name=='push':
                obj=json.loads(self.auth_path.read_text());obj['ready']=False
                self.auth_path.write_text(json.dumps(obj))
            return original(name,action)
        self.remote.mutate=edit_owner
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertNotIn('push',self.remote.ops)
        self.assertNotIn('install',self.remote.ops)
        self.assertEqual(json.loads((self.out.path/'checkpoint.json').read_text())['intent'],'push')

    def test_wrong_baseline_version_or_hash_refused_before_mutation(self):
        for version,hash_value in [(0,'0'*64),(3,self.inputs.r['sha256']),(1,'1'*64)]:
            with self.subTest(version=version):
                self.remote.pkg.update(version=version,sha256=hash_value)
                with self.assertRaises(m.Refusal):self.engine().run()
                self.assertEqual(self.remote.ops,[])

    def test_target_with_wrong_payload_not_completed_as_another_task(self):
        self.make_inputs(payload=True)
        self.remote.pkg.update(version=self.inputs.r['version'],sha256=self.inputs.r['sha256'])
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertEqual(self.remote.ops,[])

    def test_resume_needs_exact_checkpoint_and_new_bound_handoff(self):
        self.remote.fail='install'
        with self.assertRaises(m.Refusal):self.engine().run()
        checkpoint=digest((self.out.path/'checkpoint.json').read_bytes())
        prior=list(self.remote.ops)
        with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
        self.authorize(checkpoint)
        with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash='0'*64)
        self.assertEqual(self.remote.ops,prior)

    def test_tampered_backup_refuses_resume(self):
        self.make_inputs(payload=True);self.remote.fail='install'
        with self.assertRaises(m.Refusal):self.engine().run()
        (self.out.path/'backup-0.bin').write_bytes(b'FICTIONAL tampered')
        checkpoint=digest((self.out.path/'checkpoint.json').read_bytes());self.authorize(checkpoint)
        prior=list(self.remote.ops)
        with self.assertRaises(m.Refusal):self.engine().run(resume=True,checkpoint_hash=checkpoint)
        self.assertEqual(self.remote.ops,prior)


def lost_response(phase):
    def test(self):
        self.make_inputs(payload=True,legacy=True);self.remote.fail=phase
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertFalse((self.out.path/'receipt.json').exists())
        cp=json.loads((self.out.path/'checkpoint.json').read_text())
        self.assertEqual(cp['intent'],phase)
        checkpoint=digest((self.out.path/'checkpoint.json').read_bytes())
        self.authorize(checkpoint);self.remote.fail=None
        self.assertEqual(self.engine().run(resume=True,checkpoint_hash=checkpoint)['result'],'upgraded')
        self.assertEqual(self.remote.ops.count(phase),1)
        self.assertEqual(self.remote.ops.count('install'),1)
    return test


for _phase in ('acquire-lock','payload-0','stage-reserve','push','stage-seal','native-start','legacy-remove','stage-clean','lock-release'):
    setattr(FaultTests,'test_response_lost_after_'+_phase.replace('-','_'),lost_response(_phase))


if __name__=='__main__':unittest.main()

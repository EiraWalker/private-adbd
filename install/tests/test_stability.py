"""Fictional stability observations; not Android execution evidence."""
import copy
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import Refusal


class Clock:
    def __init__(self):self.now=0
    def __call__(self):return self.now
    def sleep(self,seconds):self.now+=seconds


class Output:
    def __init__(self):self.files={}
    def write(self,name,value):self.files[name]=copy.deepcopy(value)


class Remote:
    def __init__(self):
        self.index=0;self.calls=[];self.change: str | None=None;self.late_stop=False
        self.snapshot_data={'control':{'boot':'FICTIONAL-boot','lease_sha256':'2'*64,
            'flags':{'userStopped':'false','safetyPaused':'false'},'config_preserved':{'enabled':True}},
            'pids':{'v2.watch':{'pid':101,'starttime':'100'}},'shell_files':{},'wrapper_state':{},
            'key_metadata_sha256':'3'*64,'listeners':['127.0.0.1:27184','127.0.0.1:5038'],
            'native':{'pid':201,'starttime':100},'native_launch':{'uid':10123,'context':'FICTIONAL'},'health_uptime':100}
        self.package_data={'uid':10123,'version':2,'sha256':'1'*64,'path':'/data/app/FICTIONAL/base.apk'}
        self.t=types.SimpleNamespace(shell=self.shell)
    def package(self):
        self.calls.append('package')
        value=copy.deepcopy(self.package_data)
        if self.change=='package' and self.index:value['sha256']='4'*64
        return value
    def snapshot(self):
        self.calls.append('snapshot');self.index+=1
        value=copy.deepcopy(self.snapshot_data)
        if self.change!='heartbeat':value['health_uptime']+=self.index
        if self.change=='pid' and self.index>1:value['pids']['v2.watch']['pid']=102
        if self.change=='config-type' and self.index>1:value['control']['config_preserved']['enabled']=1
        return value
    def late_control(self):
        self.calls.append('late-control')
        value={k:copy.deepcopy(self.snapshot_data['control'][k]) for k in ('boot','lease_sha256','flags')}
        if self.late_stop:value['flags']['userStopped']='true'
        return value
    def shell(self,code,label):
        self.calls.append('foreground')
        assert code=='dumpsys activity services com.termux/.app.privateadb.PrivateAdbService'
        assert label=='process'
        return b'* ServiceRecord{FICTIONAL u0 com.termux/.app.privateadb.PrivateAdbService}\n isForeground=true\n'


class StabilityTests(unittest.TestCase):
    def run_probe(self,remote=None,clock=None,**kwargs):
        from stability import verify_stability
        self.remote=remote or Remote();self.clock=clock or Clock();self.out=Output()
        self.inputs=types.SimpleNamespace(r={'version':2,'sha256':'1'*64},p={'app_uid':10123},unchanged=lambda:None)
        return verify_stability(self.remote,self.inputs,self.out,stable_seconds=10,interval_seconds=5,
                                clock=self.clock,sleep=self.clock.sleep,**kwargs)

    def test_stable_epoch_requires_observed_span_samples_and_heartbeat_progress(self):
        result=self.run_probe()
        self.assertEqual(result['result'],'stable')
        self.assertEqual(result['samples'],3)
        self.assertGreaterEqual(result['observed_span_seconds'],10)
        self.assertTrue(result['heartbeat_advanced'])
        self.assertIn('stability.json',self.out.files)
        self.assertNotIn('install',self.remote.calls)

    def test_late_control_projection_does_not_compare_unrelated_config_field(self):
        self.assertEqual(self.run_probe()['result'],'stable')

    def test_pid_change_refuses_instead_of_resetting_baseline(self):
        remote=Remote();remote.change='pid'
        with self.assertRaises(Refusal):self.run_probe(remote)
        self.assertNotIn('stability.json',self.out.files)

    def test_control_boolean_number_change_is_not_equal(self):
        remote=Remote();remote.change='config-type'
        with self.assertRaises(Refusal):self.run_probe(remote)

    def test_stale_heartbeat_cannot_pass_only_from_elapsed_time(self):
        remote=Remote();remote.change='heartbeat'
        with self.assertRaises(Refusal):self.run_probe(remote)

    def test_late_stop_refuses_even_when_snapshot_was_healthy(self):
        remote=Remote();remote.late_stop=True
        with self.assertRaises(Refusal):self.run_probe(remote)
        self.assertNotIn('stability.json',self.out.files)

    def test_target_package_change_refuses(self):
        remote=Remote();remote.change='package'
        with self.assertRaises(Refusal):self.run_probe(remote)

    def test_missing_foreground_service_refuses(self):
        remote=Remote();remote.t.shell=lambda *args:b'No services\n'
        with self.assertRaises(Refusal):self.run_probe(remote)

    def test_actual_clock_does_not_advance_merely_from_requested_sleep(self):
        class FrozenClock(Clock):
            def sleep(self,seconds):pass
        with self.assertRaises(Refusal):self.run_probe(clock=FrozenClock())


class StabilityCliTests(unittest.TestCase):
    def arguments(self,*extra):
        import installer
        return installer.parser().parse_args(['verify','--profile','FICTIONAL-profile.json',
            '--release','FICTIONAL-release.json','--output','FICTIONAL-output',*extra])

    def test_verify_is_an_explicit_read_only_command(self):
        args=self.arguments()
        self.assertEqual(args.command,'verify')
        self.assertFalse(args.execute)

    def test_verify_never_accepts_execute(self):
        import installer
        args=self.arguments('--execute')
        with self.assertRaises(Refusal):installer.run(args)

    def test_verify_rejects_maintenance_not_silently_ignored(self):
        with self.assertRaises(SystemExit):self.arguments('--maintenance','FICTIONAL-maintenance.json')


if __name__=='__main__':unittest.main()

import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from test_installer import profile
from test_local import SCRATCH, release, digest
from test_cli import OfflineSDK
import installer as m


class ModelRemote:
    """Explicit lifecycle/byte-state model boundary, not a real deployment receipt."""
    def __init__(self,inputs):
        self.inputs=inputs;self.p=inputs.p;self.calls=0;self.ops=[];self.fail=None
        self.pkg={'version':1,'uid':self.p['app_uid'],'path':'/data/app/FICTIONAL/base.apk','sha256':digest(b'FICTIONAL old APK')}
        self.files={};self.lock=None;self.stage=None;self.staged=None;self.stage_mode=None
        native={'pid':201,'starttime':100,'exe':m.BIN+'adb','argv_sha256':'0'*64,'inode':'1:200',
                'uid':10123,'context':'u:r:untrusted_app:s0:c1,c2','listener':'127.0.0.1:5038'}
        self.snap={'control':{'flags':{'userStopped':'false','safetyPaused':'false'},'lease_sha256':'2'*64,'boot':'FICTIONAL-boot','config_preserved':{'FICTIONAL':'unchanged'}},'pids':{'FICTIONAL':'unchanged'},
                   'shell_files':{},'wrapper_state':{},'key_metadata_sha256':'0'*64,
                   'listeners':['127.0.0.1:27184','127.0.0.1:5038'],'native':native,'health_uptime':100}
        self.kill_native=True
    def snapshot(self,allow_missing_native=False):
        self.calls+=1;self.snap['health_uptime']+=1
        if self.snap['native'] is None and not allow_missing_native:raise m.Refusal('model native missing')
        return copy.deepcopy(self.snap)
    def late_control(self):
        self.calls+=1
        if getattr(self,'late_stop',False):raise m.Refusal('FICTIONAL late Stop')
        return {k:v for k,v in self.snap['control'].items() if k!='config_preserved'}
    def package(self):self.calls+=1;return copy.deepcopy(self.pkg)
    def backup_installed(self,pkg,name):
        self.calls+=1;self.inputs.out.raw(name,b'FICTIONAL old APK' if pkg['version']==1 else b'FICTIONAL APK')
        return self.inputs.out.path/name
    def file_state(self,path):
        self.calls+=1
        if path not in self.files:return None
        data,mode=self.files[path]
        return {'sha256':digest(data),'metadata':[mode,'10123','10123','1',str(len(data))]}
    def read(self,path):self.calls+=1;return self.files[path][0]
    def mutate(self,name,action):
        self.late_gate()
        self.ops.append(name);action()
        if self.fail==name:raise m.Refusal('model response lost after effect')
    def bind_guard(self,guard):self.late_gate=guard
    def acquire_lock(self,token):self.mutate('acquire-lock',lambda:setattr(self,'lock',token))
    def lock_owned(self,token):self.calls+=1;return self.lock==token
    def lock_absent(self):self.calls+=1;return self.lock is None
    def reserve_stage(self,token):self.mutate('stage-reserve',lambda:setattr(self,'stage',token))
    def stage_owned(self,token,require_apk=False,allow_unsealed=False):
        self.calls+=1;return self.stage==token and (not require_apk or (self.staged==self.inputs.r['sha256'] and (allow_unsealed or self.stage_mode=='600')))
    def stage_absent(self,token):self.calls+=1;return self.stage is None
    def push_apk(self,token):
        def effect():self.staged=self.inputs.r['sha256'];self.stage_mode='644'
        self.mutate('push',effect)
    def seal_stage(self,token):self.mutate('stage-seal',lambda:setattr(self,'stage_mode','600'))
    def install_apk(self,token):
        def effect():
            self.pkg['version']=self.inputs.r['version'];self.pkg['sha256']=self.inputs.r['sha256']
            if self.kill_native:
                self.snap['native']=None;self.snap['listeners']=['127.0.0.1:27184']
        self.mutate('install',effect)
    def write_payload(self,p,token):
        self.mutate('payload-'+str(self.inputs.r['payloads'].index(p)),lambda:self.files.__setitem__(p['path'],(self.inputs.payloads[p['path']],p['mode'])))
    def start_native(self):
        def effect():
            self.snap['native']={'pid':202,'starttime':110,'exe':m.BIN+'adb','argv_sha256':'0'*64,'inode':'1:200',
                                'uid':10123,'context':'u:r:untrusted_app:s0:c1,c2','listener':'127.0.0.1:5038'}
            self.snap['listeners']=['127.0.0.1:27184','127.0.0.1:5038']
        self.mutate('native-start',effect)
    def remove_legacy(self,item):self.mutate('legacy-remove',lambda:self.files.pop(item['path']))
    def clean_stage(self,token):
        def effect():self.stage=None;self.staged=None
        self.mutate('stage-clean',effect)
    def release_lock(self,token):self.mutate('lock-release',lambda:setattr(self,'lock',None))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('upgrade'),'upgrade state machine missing')
        import upgrade
        self.u=upgrade
        self.temp=tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-engine-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.make_inputs()
    def make_inputs(self,payload=False,legacy=False,phase='before_apk'):
        (self.root/'fixture.apk').write_bytes(b'FICTIONAL APK')
        r=release()
        if payload:
            (self.root/'code').write_bytes(b'FICTIONAL updated wrapper')
            r['payloads']=[{'path':m.MANAGER,'source':'code','sha256':digest(b'FICTIONAL updated wrapper'),
                            'before_sha256':digest(b'FICTIONAL old wrapper'),'mode':'700','phase':phase}]
        if legacy:r['remove_legacy']=[{'path':m.BIN+'tablet-daemon','sha256':digest(b'FICTIONAL legacy'),'mode':'700'}]
        (self.root/'profile.json').write_text(json.dumps(profile()));(self.root/'release.json').write_text(json.dumps(r))
        self.inputs=m.Inputs(self.root/'profile.json',self.root/'release.json',OfflineSDK())
        self.out=m.PrivateOutput(self.root/('out-'+str(len(list(self.root.glob('out-*'))))),True);self.inputs.out=self.out
        self.remote=ModelRemote(self.inputs)
        if payload:self.remote.files[m.MANAGER]=(b'FICTIONAL old wrapper','700')
        if legacy:self.remote.files[m.BIN+'tablet-daemon']=(b'FICTIONAL legacy','700')
        self.authorize()
    def authorize(self,checkpoint=None):
        now=dt.datetime.now(dt.timezone.utc)
        obj={'schema':1,**self.inputs.bindings,'serial':self.inputs.p['serial'],'owner':'FICTIONAL-owner',
             'ready':True,'released':True,'no_parallel':True,'issued_at':now.isoformat(),
             'expires_at':(now+dt.timedelta(minutes=10)).isoformat()}
        if checkpoint:obj['checkpoint_sha256']=checkpoint
        self.auth_path=self.root/'maintenance.json';self.auth_path.write_text(json.dumps(obj))
        self.auth=self.u.Authorization(self.auth_path,self.inputs,checkpoint)
    def engine(self):return self.u.Engine(self.inputs,self.remote,self.out,self.auth)

    def test_config_preservation_rejects_boolean_number_coercion_before_mutation(self):
        original = {'version': 1, 'enabled': True, 'expectedSerial': profile()['serial'],
                    'managerPath': m.BIN+'tablet-daemon', 'heartbeatPath': m.STATE+'health.json',
                    'extension': {'flags': [True, False]}}
        for index, field in enumerate(('enabled', 'extension', None)):
            with self.subTest(field=field):
                candidate = copy.deepcopy(original)
                candidate['managerPath'] = m.MANAGER
                if field is not None:
                    candidate[field] = 1 if field == 'enabled' else {'flags': [1, 0]}
                before = json.dumps(original).encode()
                after = json.dumps(candidate).encode()
                (self.root/'config-candidate.json').write_bytes(after)
                r = release()
                r['payloads'] = [{'path': m.STATE+'autostart.json', 'source': 'config-candidate.json',
                                  'sha256': digest(after), 'before_sha256': digest(before),
                                  'mode': '600', 'phase': 'before_apk'}]
                (self.root/'release.json').write_text(json.dumps(r))
                self.inputs = m.Inputs(self.root/'profile.json', self.root/'release.json', OfflineSDK())
                self.out = m.PrivateOutput(self.root/('config-type-out-'+str(index)), True)
                setattr(self.inputs, 'out', self.out)
                self.remote = ModelRemote(self.inputs)
                self.remote.files[m.STATE+'autostart.json'] = (before, '600')
                self.authorize()
                if field is None:
                    self.assertEqual(self.engine().run()['result'], 'upgraded')
                    self.assertEqual(self.remote.read(m.STATE+'autostart.json'), after)
                    continue
                with self.assertRaises(m.Refusal):
                    self.engine().run()
                self.assertEqual(self.remote.ops, [])
                self.assertEqual(self.remote.read(m.STATE+'autostart.json'), before)
                self.assertFalse((self.out.path/'receipt.json').exists())

    def test_payload_bytes_backup_phase_order_and_legacy_removal_after_postcheck(self):
        self.make_inputs(payload=True,legacy=True)
        result=self.engine().run()
        self.assertEqual(result['result'],'upgraded')
        self.assertEqual(self.remote.files[m.MANAGER][0],b'FICTIONAL updated wrapper')
        self.assertNotIn(m.BIN+'tablet-daemon',self.remote.files)
        self.assertLess(self.remote.ops.index('payload-0'),self.remote.ops.index('install'))
        self.assertLess(self.remote.ops.index('native-start'),self.remote.ops.index('legacy-remove'))
        cp=json.loads((self.out.path/'checkpoint.json').read_text())
        self.assertEqual((self.out.path/cp['backups'][m.MANAGER]['file']).read_bytes(),b'FICTIONAL old wrapper')
        self.make_inputs(payload=True)
        self.remote.files[m.MANAGER]=(b'FICTIONAL unknown drift','700')
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertEqual(self.remote.ops,[])

    def test_install_response_loss_resumes_forward_without_reinstall(self):
        self.make_inputs(payload=True,legacy=True)
        self.remote.fail='install'
        with self.assertRaises(m.Refusal):self.engine().run()
        cp_path=self.out.path/'checkpoint.json';cp=json.loads(cp_path.read_text())
        self.assertEqual(cp['intent'],'install')
        self.assertNotIn('native-start',self.remote.ops)
        checkpoint=digest(cp_path.read_bytes())
        try:
            self.authorize(checkpoint);self.remote.fail=None
            result=self.engine().run(resume=True,checkpoint_hash=checkpoint)
        except m.Refusal:
            self.fail('exact checkpoint-bound resume must reconcile installed APK without replay')
        self.assertEqual(result['result'],'upgraded')
        self.assertEqual(self.remote.ops.count('install'),1)
        self.assertEqual(self.remote.ops.count('payload-0'),1)
        self.assertEqual(self.remote.ops.count('native-start'),1)

    def test_already_current_and_completed_resume_are_readonly(self):
        result=self.engine().run()
        self.assertEqual(result['result'],'upgraded')
        cp_path=self.out.path/'checkpoint.json';raw=cp_path.read_bytes();checkpoint=digest(raw)
        prior=list(self.remote.ops);self.authorize(checkpoint)
        result=self.engine().run(resume=True,checkpoint_hash=checkpoint)
        self.assertEqual(result['result'],'already-current')
        self.assertEqual(self.remote.ops,prior)
        self.assertEqual(cp_path.read_bytes(),raw)
        self.authorize()
        self.out=m.PrivateOutput(self.root/'already-current-out',True);self.inputs.out=self.out
        result=self.engine().run()
        self.assertEqual(result['result'],'already-current')
        self.assertEqual(self.remote.ops,prior)

    def test_pure_apk_upgrade_rebuilds_native_and_finishes(self):
        result=self.engine().run()
        self.assertEqual(result['result'],'upgraded')
        self.assertEqual(self.remote.ops,['acquire-lock','stage-reserve','push','stage-seal','install','native-start','stage-clean','lock-release'])
        cp=json.loads((self.out.path/'checkpoint.json').read_text())
        self.assertEqual(cp['phase'],'complete')
        self.assertEqual(cp['native_after']['pid'],202)
        self.assertTrue((self.out.path/'receipt.json').is_file())

    def test_after_apk_payload_and_response_loss_resume(self):
        self.make_inputs(payload=True,phase='after_apk');self.remote.fail='payload-0'
        with self.assertRaises(m.Refusal):self.engine().run()
        self.assertLess(self.remote.ops.index('install'),self.remote.ops.index('payload-0'))
        checkpoint=digest((self.out.path/'checkpoint.json').read_bytes());self.authorize(checkpoint)
        self.remote.fail=None
        self.assertEqual(self.engine().run(resume=True,checkpoint_hash=checkpoint)['result'],'upgraded')
        self.assertEqual(self.remote.ops.count('payload-0'),1)


if __name__=='__main__':unittest.main()

import base64
import json
from pathlib import Path
import tempfile
import types
import unittest
from test_installer import profile
from test_local import SCRATCH, release, digest
import installer as m
import android as a


class WireModel:
    """Read-only synthetic wire responses; NOT an Android compatibility test."""
    def __init__(self,p):
        self.p=p;self.calls=0;self.execute=True;self.operations=[]
        self.package_text=(p['serial']+'\n2000\nu:r:shell:s0\nEnforcing\n'+str(p['app_uid'])+
            '\nversionCode=1\n userId='+str(p['app_uid'])+'\n appId='+str(p['app_uid'])+
            '\npackage:/data/app/FICTIONAL/base.apk\n').encode()
    def shell(self,code,label,data=None,mutating=False,timeout=45):
        self.calls+=1;self.operations.append((label,code,mutating))
        if label=='package':return self.package_text
        if label=='installed-apk':return (digest(b'FICTIONAL old APK')+'  /data/app/FICTIONAL/base.apk\n').encode()
        raise AssertionError('unexpected fixture operation '+label)
    def app(self,*args,**kwargs):return self.shell(*args,**kwargs)


class SnapshotWire(WireModel):
    def __init__(self,p):
        super().__init__(p)
        self.files={
            m.APP+'/shared_prefs/private_adb_autostart.xml': b'<map><boolean name="userStopped" value="false"/><boolean name="safetyPaused" value="false"/><string name="phase">healthy</string></map>',
            m.APP+'/shared_prefs/private_adb_native_lease.xml': b'<map><boolean name="ownedFlag" value="false"/></map>',
            m.STATE+'health.json':json.dumps({'state':'healthy','boot_id':'FICTIONAL-boot','uptime_ms':110000,'watch_pid':101,'child_pid':102}).encode(),
            m.STATE+'autostart.json':json.dumps({'enabled':True,'expectedSerial':p['serial'],'managerPath':m.MANAGER,'heartbeatPath':m.STATE+'health.json'}).encode(),
            m.STATE+'port':b'5038', m.STATE+'device.serial':p['serial'].encode(),m.STATE+'session.lock':b'FICTIONAL-lock',
        }
        base=p['base'];shell=b'/system/bin/mksh'
        processes=[(101,shell,b'/system/bin/sh\0'+(base+'/service.sh').encode()+b'\0watch\0',2000),
                   (102,(base+'/private-adbd').encode(),b'\0'.join([(base+'/private-adbd').encode(),b'--keys',(base+'/authorized_keys').encode(),b'--serial',p['serial'].encode(),b'']),2000),
                   (201,(m.BIN+'adb').encode(),b'\0'.join([(m.BIN+'adb').encode(),b'-L',b'tcp:localhost:5038',b'fork-server',b'server',b'--reply-fd',b'10',b'']),p['app_uid'])]
        self.exe={};self.inodes={}
        for pid,exe,cmd,uid in processes:
            self.exe[str(pid)]=exe;self.inodes[str(pid)]='1:500'
            head=f'/proc/{pid}/'
            self.files[head+'stat']=(str(pid)+' (FICTIONAL process) '+' '.join(['S']+['0']*18+['50']+['0']*5)).encode()
            self.files[head+'cmdline']=cmd
            self.files[head+'status']=('Uid:\t'+'\t'.join([str(uid)]*4)+'\n').encode()
            self.files[head+'attr/current']=b'u:r:shell:s0' if uid==2000 else b'u:r:untrusted_app:s0:c1,c2'
            if uid==2000:
                name='v2.watch' if pid==101 else 'v2.child'
                self.files[base+'/'+name]=(f'{pid} 50 FICTIONAL-boot {exe.hex()} {cmd.hex()} 2000 u:r:shell:s0\n').encode()
        self.state_mode='700'
        self.base_mode='700'
        self.pending=False;self.addresses=b'LISTEN 0 10 127.0.0.1:27184 0.0.0.0:*\nLISTEN 0 10 127.0.0.1:5038 0.0.0.0:*\n'
    def shell(self,code,label,data=None,mutating=False,timeout=45):
        import shlex,re
        if label in ('package','installed-apk'):return super().shell(code,label,data,mutating,timeout)
        self.calls+=1;self.operations.append((label,code,mutating))
        if label=='read':return base64.b64encode(self.files[shlex.split(code)[-1]])+b'\n'
        if label=='clock':return b'FICTIONAL-boot\n120.0 1.0\n0\nEnforcing\n'
        if label=='presence':return b'yes' if self.pending else b'no'
        if label=='lock-probe':return b''
        if label=='keys-stat':return b'700 10123 10123 1 1 FICTIONAL-key-directory\n600 10123 10123 1 1 FICTIONAL-existing-key\n'
        if label=='listeners':return self.addresses
        if label=='metadata':
            if shlex.split(code)[-1]==m.STATE.rstrip('/'):return (self.state_mode+' 10123 10123\n').encode()
            if shlex.split(code)[-1]==self.p['base']:return (self.base_mode+' 2000 2000\n').encode()
            return b'600 10123 10123 1 1\n'
        if label=='invariant':
            mode=b'600' if 'authorized_keys' in code or 'service.serial' in code else b'700'
            return mode+b' 2000 2000 1 1\n'+b'0'*64+b'  FICTIONAL-file\n'
        if label=='process':
            if code=='pidof adb || true':return b'201\n'
            if code=='readlink -f /system/bin/sh':return b'/system/bin/mksh\n'
            pid=re.search(r'/proc/(\d+)/',code).group(1)
            if code.startswith('readlink '):return self.exe[pid]+b'\n'
            return (self.inodes[pid]+'\n1:500\n').encode()
        raise AssertionError('unexpected fixture operation '+label)


class RemoteTests(unittest.TestCase):
    def test_private_reads_check_ancestors_and_state_requires_0700(self):
        p=profile();t=SnapshotWire(p)
        remote=a.AndroidRemote(types.SimpleNamespace(p=p,r=release()),types.SimpleNamespace(event=lambda *x:None),True,transport=t)
        remote.snapshot()
        reads='\n'.join(code for label,code,_ in t.operations if label=='read')
        self.assertIn('[ ! -L '+m.APP+'/shared_prefs ]',reads)
        t.state_mode='755'
        with self.assertRaises(m.Refusal):remote.snapshot()
        t.state_mode='700';t.base_mode='755'
        with self.assertRaises(m.Refusal):remote.snapshot()
        for path in [m.STATE+'native-home/.android/adbkey',m.APP+'/files/home/.android/adbkey.pub','/proc/201/environ']:
            count=t.calls
            with self.assertRaises(m.Refusal):remote.read(path)
            self.assertEqual(t.calls,count)

    def test_snapshot_captures_healthy_chain_without_reading_keys(self):
        self.assertTrue(hasattr(a.AndroidRemote,'snapshot'),'full remote snapshot missing')
        p=profile();t=SnapshotWire(p)
        remote=a.AndroidRemote(types.SimpleNamespace(p=p,r=release()),types.SimpleNamespace(event=lambda *x:None),True,transport=t)
        snap=remote.snapshot()
        self.assertEqual(set(snap['pids']),{'v2.watch','v2.child'})
        self.assertEqual(snap['native']['pid'],201)
        self.assertEqual(snap['native']['inode'],'1:500')
        for label,code,mutating in t.operations:
            self.assertFalse(mutating)
            if 'adbkey' in code:self.assertEqual(label,'keys-stat')
            if label=='read':self.assertNotIn('authorized_keys',code)
        t.pending=True
        with self.assertRaises(m.Refusal):remote.snapshot()
        t.pending=False;t.addresses=t.addresses.replace(b'127.0.0.1:5038',b'0.0.0.0:5038')
        with self.assertRaises(m.Refusal):remote.snapshot()

    def test_reviewed_mutations_are_argv_or_fixed_scripts_and_token_scoped(self):
        self.assertTrue(hasattr(a.AndroidRemote,'install_apk'),'live mutation engine missing')
        with tempfile.TemporaryDirectory(dir=SCRATCH,prefix='fictional-wire-') as temp:
            root=Path(temp);(root/'fixture.apk').write_bytes(b'FICTIONAL APK')
            inputs=types.SimpleNamespace(p=profile(),r=release(),apk=root/'fixture.apk',payloads={})
            class Recorder:
                def __init__(self):self.calls=0;self.execute=True;self.ops=[]
                def shell(self,code,label,data=None,mutating=False,timeout=45):
                    self.calls+=1;self.ops.append((label,code,mutating))
                    if label=='stage-check':return b'yes'
                    if label=='install':return b'Success\n'
                    return b''
                def app(self,*args,**kwargs):return self.shell(*args,**kwargs)
                def call(self,args,label,**kwargs):
                    self.ops.append((label,args,kwargs.get('mutating',False)));return b''
            t=Recorder();out=types.SimpleNamespace(path=root,event=lambda *x:None,raw=lambda n,b:(root/n).write_bytes(b))
            remote=a.AndroidRemote(inputs,out,True,transport=t);token='a'*32
            remote.acquire_lock(token);remote.reserve_stage(token);remote.push_apk(token)
            self.assertTrue(hasattr(remote,'seal_stage'),'staged APK mode seal missing')
            remote.seal_stage(token);remote.install_apk(token)
            remote.start_native();remote.clean_stage(token);remote.release_lock(token)
            labels=[x[0] for x in t.ops]
            self.assertIn('push',labels);self.assertIn('native-start',labels)
            code='\n'.join(x[1] for x in t.ops if isinstance(x[1],str))
            self.assertIn('pm install -r ',code);self.assertNotIn('pm install -r -d',code)
            self.assertIn('} 9<',code);self.assertNotIn('exec 9',code)
            self.assertNotIn('rm -rf',code);self.assertNotIn('kill-server',code)
            self.assertNotIn('keygen',code);self.assertNotIn(' pair ',code)
            self.assertIn('sha256sum',code);self.assertIn('[ ! -L',code)
            for bad in ('bad','../bad','a'*33):
                with self.assertRaises(m.Refusal):remote.reserve_stage(bad)

    def test_package_reads_independent_identity_even_with_controller(self):
        self.assertTrue(hasattr(a,'AndroidRemote'),'Android remote engine missing')
        p=profile();t=WireModel(p)
        inputs=types.SimpleNamespace(p=p,r=release())
        remote=a.AndroidRemote(inputs,types.SimpleNamespace(event=lambda *x:None),True,transport=t)
        pkg=remote.package()
        self.assertEqual(pkg['sha256'],digest(b'FICTIONAL old APK'))
        self.assertEqual(t.calls,2)
        for token in ['getprop ro.serialno','id -u','id -Z','getenforce','run-as com.termux id -u','pm path com.termux']:
            self.assertIn(token,t.operations[0][1])
        t.package_text=t.package_text.replace(b'u:r:shell:s0',b'u:r:su:s0')
        with self.assertRaises(m.Refusal): remote.package()


if __name__=='__main__':unittest.main()

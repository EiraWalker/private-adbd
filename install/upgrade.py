"""Durable, forward-only state machine. Mutation responses are never retried."""
from __future__ import annotations

import time
import uuid
import re
from common import Refusal, ObservationUnavailable, need, sha
from installer import json_bytes, validate_maintenance
from private_output import no_links
from android import validate_native_transition, validate_native_launch


def same_json_value(left, right):
    """Preserve JSON types, including booleans nested in extension fields."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            same_json_value(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(
            same_json_value(a, b) for a, b in zip(left, right))
    return left == right


class Authorization:
    def __init__(self,path,inputs,checkpoint_hash=None):
        need(path is not None,'maintenance handoff required')
        self.path=no_links(path);self.inputs=inputs
        self.data=self.path.read_bytes();self.checkpoint_hash=checkpoint_hash
        self.check()

    def check(self):
        no_links(self.path)
        need(self.path.read_bytes()==self.data,'maintenance handoff changed; new explicit resume required')
        obj=json_bytes(self.data)
        validate_maintenance(obj,**self._arguments())
        if self.checkpoint_hash is not None:
            from installer import digest
            digest(self.checkpoint_hash)
            need(obj.get('checkpoint_sha256')==self.checkpoint_hash,'resume maintenance checkpoint binding')
        else:
            need('checkpoint_sha256' not in obj,'resume-only maintenance used for apply')
        return obj

    def _arguments(self):
        return {'profile_hash':self.inputs.bindings['profile_sha256'],
                'release_hash':self.inputs.bindings['release_sha256'],'serial':self.inputs.p['serial']}


class Engine:
    def __init__(self,inputs,remote,out,authorization):
        self.i=inputs;self.r=remote;self.out=out;self.auth=authorization;self.cp=None
        self.maintenance=None
        self.api=inputs.r.get('maintenance_api')==1
        self.r.bind_guard(self.guard)

    def save(self): self.out.write('checkpoint.json',self.cp)

    def operation_order(self):
        return ((['maintenance-acquire'] if self.api else [])+['acquire-lock']+
                ['payload-'+str(n) for n,p in enumerate(self.i.r['payloads']) if p['phase']=='before_apk']+
                ['stage-reserve','push','stage-seal','install']+
                (['maintenance-reack'] if self.api else [])+
                ['payload-'+str(n) for n,p in enumerate(self.i.r['payloads']) if p['phase']=='after_apk']+
                ['native-start']+(['legacy-remove'] if self.i.r['remove_legacy'] else [])+
                ['stage-clean','lock-release']+(['maintenance-release'] if self.api else []))

    def package_allowed(self,pkg):
        r=self.i.r
        need((pkg['version'],pkg['sha256']) in
             [(b['version'],b['sha256']) for b in r['baselines']]+[(r['version'],r['sha256'])], 'installed APK outside approved versions/hashes')

    def target_package(self):
        pkg=self.r.package()
        need(pkg['version']==self.i.r['version'] and pkg['sha256']==self.i.r['sha256'],'installed APK target readback')
        return pkg

    def preserved(self,after,allow_missing=False,expected_native=None):
        before=self.cp['before']
        if 'native_launch' in before:
            validate_native_launch(before['native_launch'],self.i.p['app_uid'],before['native']['context'])
            need(same_json_value(before['native_launch'],after.get('native_launch')), 'native launch identity changed')
        for name in ('control','pids','shell_files','wrapper_state','key_metadata_sha256'):
            need(same_json_value(before[name],after[name]),'runtime invariant changed')
        native=after['native']
        expected=expected_native or self.cp.get('native_after') or before['native']
        if native is None:
            need(allow_missing and after['listeners']==[x for x in before['listeners'] if x!=before['native']['listener']], 'unexpected missing native server/listeners')
        else:
            need(same_json_value(native,expected) and same_json_value(after['listeners'],before['listeners']),
                 'unapproved native server replacement/listeners')

    def guard(self, *, lease=True):
        self.auth.check();self.i.unchanged()
        pkg=self.r.package();self.package_allowed(pkg)
        if self.cp['apk_confirmed']:
            need(pkg['version']==self.i.r['version'] and pkg['sha256']==self.i.r['sha256'],'confirmed APK changed')
        else:
            need(pkg==self.cp['baseline_package'],'baseline APK changed')
        after=self.r.snapshot(allow_missing_native=self.cp['apk_confirmed'])
        self.preserved(after,self.cp['apk_confirmed'])
        self.files_progress()
        ack_started=None
        if self.api and lease and 'maintenance-release' not in self.cp['done']:
            need('maintenance-acquire' in self.cp['done'],'maintenance acquisition required')
            need(not self.cp['apk_confirmed'] or 'maintenance-reack' in self.cp['done'],
                 'replacement APK fresh acknowledgement required')
            # Actual AndroidRemote bounds: install/push 180s, native start 15s,
            # all other mutating transport calls 45s. Reserve 30s for the
            # acknowledgement/final late gates AND 30s dispatch safety margin.
            timeout_ms={'install':180000,'push':180000,'native-start':15000}.get(self.cp['intent'],45000)
            ack_started=time.monotonic()
            self.maintenance.assert_active(minimum_remaining_ms=timeout_ms+60000)
        self.late_gates()
        if ack_started is not None:
            need(0<=time.monotonic()-ack_started<=30,'maintenance final dispatch budget exhausted')
        return after

    def late_gates(self):
        if 'native_launch' in self.cp['before']:
            launch=self.r.native_launch()
            need(same_json_value(launch,self.cp['before']['native_launch']), 'late native launch identity changed')
        # Launch observation is another potentially slow remote round trip.
        # Keep Stop/lease/boot freshness after it, not before it.
        late=self.r.late_control()
        expected={k:self.cp['before']['control'][k] for k in ('flags','lease_sha256','boot')}
        need(same_json_value(late,expected),'late Stop/lease/boot gate changed')
        self.auth.check()

    def mutate(self,name,action,confirm):
        if name in self.cp['done']:return
        need(self.operation_order()[len(self.cp['done'])]==name,'operation ordering')
        if self.api:
            # Only schema 2 journals before the real Transport dispatch guard.
            # Every AndroidRemote mutation still uses its bound before_mutation;
            # never detach/cache that full runtime/material check.
            self.auth.check();self.i.unchanged()
        else:
            self.guard()
        self.cp['phase']=name;self.cp['intent']=name;self.save()
        action()
        need(confirm(),'mutation readback incomplete')
        self.cp['done'].append(name);self.cp['intent']=None;self.save()

    def maintenance_step(self,name):
        if name in self.cp['done']:return
        need(self.operation_order()[len(self.cp['done'])]==name,'maintenance operation ordering')
        self.auth.check();self.i.unchanged()
        self.cp['phase']=name;self.cp['intent']=name;self.save()
        self.guard(lease=name=='maintenance-release')
        if name=='maintenance-acquire':
            reply=self.maintenance.request_once()
        elif name=='maintenance-reack':
            need(self.cp['apk_confirmed'],'maintenance reack requires confirmed APK')
            reply=self.maintenance.status()
        else:
            reply=self.maintenance.release_once()
        if name!='maintenance-release' and reply['phase']=='pending':
            self.maintenance.wait_active(max_attempts=3,poll_ms=250,timeout_ms=10000)
        self.late_gates()
        self.cp['done'].append(name);self.cp['intent']=None;self.save()

    def confirmed_install(self):
        """Bounded package-only observation after a successful install response.

        No operation replay, status command, snapshot or arbitrary shell retries.
        A valid but unexpected package returns False immediately. Resume of an
        unknown install outcome deliberately retains the one-shot installed().
        """
        deadline=time.monotonic()+15
        for attempt in range(3):
            self.auth.check();self.i.unchanged()
            need(time.monotonic()<deadline,'installed APK observation budget exhausted')
            try:
                pkg=self.r.package(deadline=deadline,expected_version=self.i.r['version'])
            except ObservationUnavailable:
                if attempt==2 or time.monotonic()>=deadline:
                    raise Refusal('installed APK observation unavailable; explicit resume required') from None
                time.sleep(min(1, max(0, deadline-time.monotonic())))
                continue
            self.auth.check();self.i.unchanged()
            need(time.monotonic()<=deadline,'installed APK observation budget exhausted')
            return pkg['version']==self.i.r['version'] and pkg['sha256']==self.i.r['sha256']

    def installed(self):
        pkg=self.r.package()
        return pkg['version']==self.i.r['version'] and pkg['sha256']==self.i.r['sha256']

    def exact_payload(self,p):
        state=self.r.file_state(p['path'])
        return state is not None and state['sha256']==p['sha256'] and state['metadata'][:4]==[
            p['mode'],str(self.i.p['app_uid']),str(self.i.p['app_uid']),'1']

    def capture_files(self):
        from installer import STATE, MANAGER
        for index,p in enumerate(self.i.r['payloads']):
            state=self.r.file_state(p['path'])
            if p['before_sha256'] is None:
                need(state is None,'payload expected absent')
                self.cp['backups'][p['path']]={'file':None,'sha256':None,'metadata':None}
                continue
            need(state is not None and state['sha256']==p['before_sha256'] and state['metadata'][0]==p['mode'], 'payload baseline bytes/mode')
            data=self.r.read(p['path'])
            need(sha(data)==p['before_sha256'],'payload changed during backup')
            if p['path']==STATE+'autostart.json':
                original=json_bytes(data);candidate=json_bytes(self.i.payloads[p['path']])
                need(same_json_value(candidate,{**original,'managerPath':MANAGER}),
                     'config update must preserve every other field')
            name='backup-'+str(index)+'.bin'
            self.out.raw(name,data)
            self.cp['backups'][p['path']]={'file':name,'sha256':sha(data),'metadata':state['metadata']}
        for item in self.i.r['remove_legacy']:
            state=self.r.file_state(item['path'])
            need(state is not None and state['sha256']==item['sha256'] and state['metadata'][0]==item['mode'],'legacy baseline')
            data=self.r.read(item['path']);need(sha(data)==item['sha256'],'legacy backup changed')
            self.out.raw('legacy-backup.bin',data)
            self.cp['backups'][item['path']]={'file':'legacy-backup.bin','sha256':sha(data),'metadata':state['metadata']}

    def postcheck(self,save=True):
        self.target_package()
        self.files_progress()
        if 'stage-clean' in self.cp['done']:need(self.r.stage_absent(self.cp['token']),'final stage cleanup readback')
        if 'lock-release' in self.cp['done']:need(self.r.lock_absent(),'final lock cleanup readback')
        need(all(self.exact_payload(p) for p in self.i.r['payloads']),'payload readback')
        after=self.r.snapshot()
        self.preserved(after)
        deadline=time.monotonic()+30
        while after['health_uptime']<=self.cp['before']['health_uptime']:
            need(time.monotonic()<deadline,'heartbeat did not advance')
            time.sleep(1)
            after=self.r.snapshot();self.preserved(after)
        self.late_gates()
        if save and not (self.api and 'maintenance-release' in self.cp['done']):
            self.cp['phase']='postcheck';self.save()

    def new(self):
        self.auth.check();self.i.unchanged()
        package=self.r.package();self.package_allowed(package)
        before=self.r.snapshot()
        backup=self.r.backup_installed(package,'baseline.apk')
        expected={**self.i.r,'version':package['version'],'sha256':package['sha256']}
        self.i.sdk.verify(backup,expected)
        if package['version']==self.i.r['version']:
            need(all(self.exact_payload(p) for p in self.i.r['payloads']) and
                 all(self.r.file_state(p['path']) is None for p in self.i.r['remove_legacy']), 'target APK with incomplete files requires original checkpoint')
            self.auth.check();self.i.unchanged()
            self.out.write('receipt.json',{'schema':1,'result':'already-current','bindings':self.i.bindings,
                                         'source_metadata_verified':False,'native_window_validation':'not-run'})
            return {'result':'already-current','device_calls':self.r.calls,'native_window_validation':'not-run'}
        need(package['version']<self.i.r['version'],'target already present; inspect or explicit checkpoint resume')
        cp={'schema':2 if self.api else 1,'bindings':self.i.bindings,'token':uuid.uuid4().hex,'phase':'preflight',
                 'intent':None,'done':[],'before':before,'baseline_package':package,
                 'backups':{},'native_after':None,'apk_confirmed':False}
        if self.api:
            from maintenance import MaintenanceClient
            self.maintenance=MaintenanceClient(self.r,self.auth)
            cp['maintenance']=self.maintenance.prepare(ttl_ms=600000)
        self.cp=cp
        self.save()
        self.capture_files()
        self.save()

    def finish(self):
        token=self.cp['token']
        if self.api:self.maintenance_step('maintenance-acquire')
        self.mutate('acquire-lock',lambda:self.r.acquire_lock(token),lambda:self.r.lock_owned(token))
        for index,p in enumerate(self.i.r['payloads']):
            if p['phase']=='before_apk':
                self.mutate('payload-'+str(index),lambda p=p:self.r.write_payload(p,token),lambda p=p:self.exact_payload(p))
        self.mutate('stage-reserve',lambda:self.r.reserve_stage(token),lambda:self.r.stage_owned(token))
        self.mutate('push',lambda:self.r.push_apk(token),lambda:self.r.stage_owned(token,True,allow_unsealed=True))
        self.mutate('stage-seal',lambda:self.r.seal_stage(token),lambda:self.r.stage_owned(token,True))
        self.mutate('install',lambda:self.r.install_apk(token),self.confirmed_install)
        self.cp['apk_confirmed']=True;self.save()
        if self.api:self.maintenance_step('maintenance-reack')
        for index,p in enumerate(self.i.r['payloads']):
            if p['phase']=='after_apk':
                self.mutate('payload-'+str(index),lambda p=p:self.r.write_payload(p,token),lambda p=p:self.exact_payload(p))
        current=self.guard()
        if current['native'] is None:
            def confirm_native():
                after=self.r.snapshot()
                self.confirm_native(after)
                return True
            self.mutate('native-start',self.r.start_native,confirm_native)
        elif 'native-start' not in self.cp['done']:
            self.cp['phase']='native-start';self.cp['done'].append('native-start');self.save()
        self.postcheck()
        for item in self.i.r['remove_legacy']:
            self.mutate('legacy-remove',lambda item=item:self.r.remove_legacy(item),lambda item=item:self.r.file_state(item['path']) is None)
        self.mutate('stage-clean',lambda:self.r.clean_stage(token),lambda:self.r.stage_absent(token))
        self.mutate('lock-release',lambda:self.r.release_lock(token),self.r.lock_absent)
        self.postcheck()
        if self.api:self.maintenance_step('maintenance-release')
        self.cp['phase']='complete';self.save()
        self.out.write('receipt.json',{'schema':1,'result':'upgraded','bindings':self.i.bindings,
                                     'source_metadata_verified':False,'native_window_validation':'not-run'})
        return {'result':'upgraded','device_calls':self.r.calls,'native_window_validation':'not-run'}

    def confirm_native(self,after):
        need(self.cp['apk_confirmed'] and 'install' in self.cp['done'] and
             self.cp['intent']=='native-start' and self.cp['phase']=='native-start',
             'native launch checkpoint phase')
        self.auth.check();self.i.unchanged();self.target_package();self.files_progress()
        need(after['native'] is not None and after['native']!=self.cp['before']['native'],
             'native rebuild must prove a replacement identity')
        validate_native_transition(self.cp['before']['native'],after['native'],
                                   self.cp['before'].get('native_launch'))
        self.preserved(after,expected_native=after['native'])
        self.late_gates()
        self.cp['native_after']=after['native']

    def load(self,checkpoint_hash):
        from installer import digest,fields
        digest(checkpoint_hash)
        need(self.auth.checkpoint_hash==checkpoint_hash,'resume authorization binding')
        self.auth.check();self.i.unchanged();self.out.verify()
        data=(self.out.path/'checkpoint.json').read_bytes()
        need(sha(data)==checkpoint_hash,'checkpoint hash mismatch')
        cp=json_bytes(data)
        fields(cp,('schema','bindings','token','phase','intent','done','before','baseline_package',
                   'backups','native_after','apk_confirmed')+(('maintenance',) if self.api else ()))
        need(type(cp['schema']) is int and cp['schema']==(2 if self.api else 1) and
             same_json_value(cp['bindings'],self.i.bindings),'checkpoint input binding')
        need(isinstance(cp['token'],str) and re.fullmatch('[0-9a-f]{32}',cp['token']),'checkpoint token')
        order=self.operation_order();done=cp['done']
        need(type(done) is list and done==order[:len(done)] and len(done)<=len(order),'checkpoint operation prefix')
        need(cp['intent'] is None or (len(done)<len(order) and cp['intent']==order[len(done)]),'checkpoint pending operation')
        need(cp['phase'] in ['preflight','postcheck','complete']+order and
             (cp['intent'] is None or cp['phase']==cp['intent']),'checkpoint phase')
        need(cp['phase']!='complete' or (done==order and cp['intent'] is None),'incomplete complete checkpoint')
        need(type(cp['apk_confirmed']) is bool and (not cp['apk_confirmed'] or 'install' in done), 'checkpoint APK flag')
        if self.api:
            from maintenance import MaintenanceClient
            # Construction validates every original record field without IPC;
            fields(cp['before'],('control','pids','shell_files','wrapper_state','key_metadata_sha256',
                                 'listeners','native','health_uptime'),('native_launch',))
            fields(cp['baseline_package'],('uid','version','sha256','path'))
            need(type(cp['before']['control']) is dict and
                 {'flags','lease_sha256','boot'}<=cp['before']['control'].keys(), 'checkpoint control fields')
            need(type(cp['baseline_package']['uid']) is int and
                 cp['baseline_package']['uid']==self.i.p['app_uid'],'checkpoint maintenance UID')
            # restored clients are status-only, never request again.
            self.maintenance=MaintenanceClient(self.r,self.auth,checkpoint=cp['maintenance'])
            req=cp['maintenance']['request']
            control={k:cp['before']['control'][k] for k in ('flags','lease_sha256','boot')}
            need(same_json_value(control,cp['maintenance']['control']) and
                 type(cp['baseline_package']['version']) is int and
                 req['baselineVersion']==cp['baseline_package']['version'], 'checkpoint maintenance baseline binding')
            need(('maintenance-reack' not in done and cp['intent']!='maintenance-reack') or
                 cp['apk_confirmed'],'checkpoint reack APK flag')
            if cp['intent'] is None:
                need(cp['phase']==(done[-1] if done else 'preflight') or
                     (cp['phase']=='postcheck' and 'native-start' in done and 'maintenance-release' not in done) or
                     cp['phase']=='complete','checkpoint maintenance phase progress')
        fields(cp['before'],('control','pids','shell_files','wrapper_state','key_metadata_sha256','listeners','native','health_uptime'),('native_launch',))
        fields(cp['baseline_package'],('uid','version','sha256','path'))
        need(type(cp['before']['native']) is dict and cp['baseline_package']['uid']==self.i.p['app_uid'],'checkpoint baseline identity')
        if 'native_launch' in cp['before']:
            validate_native_launch(cp['before']['native_launch'],self.i.p['app_uid'],cp['before']['native'].get('context'))
            need(cp['before']['native'].get('uid')==self.i.p['app_uid'],'checkpoint native UID')
            if cp['intent'] is None:
                need(cp['phase']==(done[-1] if done else 'preflight') or
                     (cp['phase']=='postcheck' and 'native-start' in done) or
                     cp['phase']=='complete','checkpoint launch phase progress')
        need((cp['baseline_package']['version'],cp['baseline_package']['sha256']) in
             [(b['version'],b['sha256']) for b in self.i.r['baselines']], 'checkpoint baseline APK')
        expected_paths={p['path'] for p in self.i.r['payloads']}|{p['path'] for p in self.i.r['remove_legacy']}
        need(type(cp['backups']) is dict and set(cp['backups'])==expected_paths,'checkpoint backup set')
        for n,p in enumerate(self.i.r['payloads']):
            pr=cp['backups'][p['path']]
            expected_name='backup-'+str(n)+'.bin' if p['before_sha256'] is not None else None
            need(pr['file']==expected_name and pr['sha256']==p['before_sha256'],'checkpoint backup identity')
        for p in self.i.r['remove_legacy']:
            pr=cp['backups'][p['path']]
            need(pr['file']=='legacy-backup.bin' and pr['sha256']==p['sha256'],'checkpoint legacy backup identity')
        for pr in cp['backups'].values():
            if pr['file'] is not None:
                need(sha(self.out.target(pr['file']).read_bytes())==pr['sha256'],'private backup integrity')
        self.i.sdk.verify(self.out.path/'baseline.apk',{**self.i.r,'version':cp['baseline_package']['version'],
                                                    'sha256':cp['baseline_package']['sha256']})
        self.cp=cp
        if 'install' in done:self.cp['apk_confirmed']=True
        if cp['native_after'] is not None:
            need('native-start' in done,'checkpoint native transition phase')
            need(cp['native_after']!=cp['before']['native'],'checkpoint native rebuild identity')
            validate_native_transition(cp['before']['native'],cp['native_after'],cp['before'].get('native_launch'))

    def reconcile(self):
        intent=self.cp['intent'];token=self.cp['token']
        if intent is None:return
        checks={
            'acquire-lock':lambda:self.r.lock_owned(token),
            'stage-reserve':lambda:self.r.stage_owned(token),
            'push':lambda:self.r.stage_owned(token,True,allow_unsealed=True),
            'stage-seal':lambda:self.r.stage_owned(token,True),
            'install':lambda:self.r.stage_owned(token,True) and self.installed(),
            'legacy-remove':lambda:all(self.r.file_state(x['path']) is None for x in self.i.r['remove_legacy']),
            'stage-clean':lambda:self.r.stage_absent(token),
            'lock-release':self.r.lock_absent,
        }
        if self.api and intent in ('maintenance-acquire','maintenance-reack'):
            self.guard(lease=False)
            reply=self.maintenance.status()
            if reply['phase']=='pending':
                self.maintenance.wait_active(max_attempts=3,poll_ms=250,timeout_ms=10000)
            self.late_gates()
        elif self.api and intent=='maintenance-release':
            self.validate_progress(lease=False)
            self.maintenance.reconcile_release(checkpoint_hash=self.auth.checkpoint_hash)
            # Terminal proof grants no lease: retain all original independent
            # runtime/package/control checks without dispatching any mutation.
            self.guard(lease=False)
        elif intent.startswith('payload-'):
            n=int(intent.split('-')[1]);need(self.exact_payload(self.i.r['payloads'][n]),'uncertain payload; no replay')
        elif intent=='native-start':
            after=self.r.snapshot(allow_missing_native=True)
            need(after['native'] is not None and after['native']!=self.cp['before']['native'],'uncertain native start; inspect only, no second start')
            self.confirm_native(after)
        else:
            need(checks[intent](),'uncertain operation; inspect only, no replay')
        self.cp['done'].append(intent);self.cp['intent']=None
        if intent=='install':self.cp['apk_confirmed']=True
        self.save()

    def validate_progress(self, *, lease=True):
        token=self.cp['token'];done=self.cp['done']
        if 'acquire-lock' in done and 'lock-release' not in done:need(self.r.lock_owned(token),'checkpoint lock no longer owned')
        if 'lock-release' in done:need(self.r.lock_absent(),'completed lock cleanup changed')
        if 'stage-reserve' in done and 'stage-clean' not in done:
            need(self.r.stage_owned(token,'push' in done,allow_unsealed='stage-seal' not in done),'checkpoint stage no longer owned')
        if 'stage-clean' in done:need(self.r.stage_absent(token),'completed stage cleanup changed')
        if 'install' in done:self.target_package()
        else:need(self.r.package()==self.cp['baseline_package'],'baseline APK changed outside pending install')
        self.files_progress()
        self.guard(lease=lease)

    def files_progress(self):
        done=self.cp['done']
        for n,p in enumerate(self.i.r['payloads']):
            state=self.r.file_state(p['path'])
            if 'payload-'+str(n) in done:need(self.exact_payload(p),'completed payload drift')
            else:
                pr=self.cp['backups'][p['path']]
                need((state is None and pr['sha256'] is None) or
                     (state is not None and state['sha256']==pr['sha256'] and state['metadata']==pr['metadata']),'unprocessed payload drift')
        for p in self.i.r['remove_legacy']:
            state=self.r.file_state(p['path'])
            if 'legacy-remove' in done:need(state is None,'legacy removal changed')
            else:need(state=={'sha256':p['sha256'],'metadata':self.cp['backups'][p['path']]['metadata']},'legacy code drift')

    def run(self,resume=False,checkpoint_hash=None):
        with self.out.session():
            return self._run(resume,checkpoint_hash)

    def _run(self,resume=False,checkpoint_hash=None):
        try:
            if resume:
                self.load(checkpoint_hash)
                self.reconcile()
                reack=self.api and self.cp['apk_confirmed'] and 'maintenance-reack' not in self.cp['done']
                self.validate_progress(lease=not reack)
                if self.cp['phase']=='complete':
                    self.postcheck(save=False)
                    return {'result':'already-current','device_calls':self.r.calls,'native_window_validation':'not-run'}
            else:
                result=self.new()
                if result is not None:return result
            return self.finish()
        except BaseException as exc:
            if self.cp is not None:
                self.out.write('failure.json',{'schema':1,'phase':self.cp['phase'],
                    'checkpoint_sha256':sha((self.out.path/'checkpoint.json').read_bytes()),
                    'exception_type':type(exc).__name__,'replay':'forbidden-without-readback-and-new-handoff'})
            raise

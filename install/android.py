"""Reviewed Android shell operations. No transport discovery or auto-enrollment."""
from __future__ import annotations
import base64
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
import math

from common import Refusal, need, sha
from installer import APP, BIN, STATE, MANAGER, validate_profile
from private_output import LABELS

q = shlex.quote


def prefs_values(data):
    try: root=ET.fromstring(data)
    except ET.ParseError: raise Refusal('preferences XML') from None
    need(root.tag=='map','preferences root')
    result={}
    for child in root:
        name=child.attrib.get('name')
        need(name is not None and name not in result,'duplicate preferences')
        result[name]=child.attrib.get('value',child.text)
    return result


def validate_control(prefs,lease,health,clock,pending):
    flags=prefs_values(prefs); owner=prefs_values(lease)
    need(flags.get('userStopped')=='false' and flags.get('safetyPaused')=='false' and
         flags.get('phase')=='healthy', 'Stop/safety/guardian gate')
    need(owner.get('ownedFlag')=='false', 'native lease owned')
    need(len(clock)==4 and clock[2:]==['0','Enforcing'], 'native window/SELinux gate')
    need(pending is False, 'pending dispatch')
    try:
        uptime=float(clock[1].split()[0])*1000
        stamp=health['uptime_ms']
        need(math.isfinite(uptime) and type(stamp) is int and
             health.get('state')=='healthy' and health.get('boot_id')==clock[0] and
             0 <= uptime-stamp <= 30000,'heartbeat freshness')
    except (KeyError,ValueError,TypeError,IndexError):
        raise Refusal('heartbeat schema') from None
    return {'flags':{k:flags[k] for k in ('userStopped','safetyPaused')},
            'lease_sha256':sha(lease),'boot':clock[0]}
def validate_native_launch(launch,uid,context=None):
    need(type(launch) is dict and set(launch)=={'uid','context'} and
         type(launch['uid']) is int and launch['uid']==uid and
         isinstance(launch['context'],str) and
         re.fullmatch(r'u:r:runas_app:s0(?::c[0-9]+(?:,c[0-9]+)*)?',launch['context']),
         'native launch identity')
    if context is not None:
        need(isinstance(context,str) and
             (re.fullmatch(r'u:r:untrusted_app(?:_[0-9]+)?:s0(?::c[0-9]+(?:,c[0-9]+)*)?',context) or
              context==launch['context']) and
             context.split(':',3)[3]==launch['context'].split(':',3)[3], 'native launch MCS/context')


def validate_native_transition(before,after,launch=None):
    need(type(before) is dict and type(after) is dict and set(before)==set(after), 'native transition schema')
    if before==after: return
    need(before['pid']!=after['pid'] and after['starttime']>before['starttime'], 'native PID/starttime transition')
    ignored=('pid','starttime')
    if before['context']!=after['context']:
        need(launch is not None,'native context change requires checkpoint launch proof')
        validate_native_launch(launch,before['uid'],before['context'])
        need(after['context']==launch['context'], 'native context outside captured launch')
        ignored+=('context',)
    need({k:v for k,v in before.items() if k not in ignored} ==
         {k:v for k,v in after.items() if k not in ignored}, 'native server replacement identity')


def validate_process(name,record,boot,proc,p,shell_exe):
    need(name in ('v2.watch','v2.child','health.watch'),'PID record kind')
    try: f=record.decode('ascii').split()
    except UnicodeError: raise Refusal('PID record encoding') from None
    need(len(f)==(3 if name=='health.watch' else 7) and
         f[0].isdigit() and int(f[0])>1 and f[1].isdigit() and f[2]==boot,'PID record schema')
    base=p['base']
    if name=='v2.child':
        expected_exe=(base+'/private-adbd').encode()
        expected_cmd=b'\0'.join([(base+'/private-adbd').encode(),b'--keys',
                                  (base+'/authorized_keys').encode(),b'--serial',p['serial'].encode(),b''])
    else:
        expected_exe=shell_exe
        script='service.sh' if name=='v2.watch' else 'health-publisher.sh'
        expected_cmd=b'/system/bin/sh\0'+(base+'/'+script).encode()+b'\0watch\0'
    need(proc['starttime']==f[1] and proc['exe']==expected_exe and proc['cmd']==expected_cmd and
         proc['uid']==[2000]*4 and proc['context']==b'u:r:shell:s0','live process identity')
    if name!='health.watch':
        need(f[3:]==[proc['exe'].hex(),proc['cmd'].hex(),'2000','u:r:shell:s0'],'core process record identity')
    return {'pid':int(f[0]),'starttime':f[1],'record_sha256':sha(record),
            'exe_sha256':sha(proc['exe']),'argv_sha256':sha(proc['cmd'])}


def checked_ancestors(path, anchor, uid):
    from pathlib import PurePosixPath
    need(isinstance(path,str) and re.fullmatch(r'/[A-Za-z0-9_./-]+',path) and
         all(x not in ('','.','..') for x in path.split('/')[1:]), 'remote path')
    need(path.startswith(anchor+'/'), 'remote path anchor')
    lines=[]
    for parent in reversed(PurePosixPath(path).parents):
        s=str(parent)
        lines.append('[ -d '+q(s)+' ] && [ ! -L '+q(s)+' ] || exit 70')
        if s==anchor or s.startswith(anchor+'/'):
            lines.append('[ "$(stat -c %u '+q(s)+')" = '+str(uid)+' ] || exit 70')
            # mksh does not assume octal from a leading zero. Match permission
            # digits directly so both mksh and POSIX sh reject group/other writes.
            # Only these two Android-managed directories may be 0771, and only
            # with the expected app UID as both owner and group. No path override.
            managed=(anchor==APP and s in (APP+'/files',APP+'/shared_prefs'))
            exception=('771) [ "$(stat -c %g '+q(s)+')" = '+str(uid)+' ] || exit 70 ;; '
                       if managed else '')
            lines.append('mode=$(stat -c %a '+q(s)+'); case "$mode" in '+exception+
                         '[0-7][0145][0145]) : ;; *) exit 70 ;; esac')
    return '\n'.join(lines)


def exact_file(path, digest_value, mode, uid):
    from installer import digest
    digest(digest_value)
    return ('[ ! -L '+q(path)+' ] && [ -f '+q(path)+' ] && '
            '[ "$(stat -c \'%a %u %g %h\' '+q(path)+')" = '+q(f'{mode} {uid} {uid} 1')+' ] && '
            '[ "$(sha256sum '+q(path)+' | cut -d \' \' -f1)" = '+digest_value+' ] || exit 72')


def replace_script(path,before,after,mode,uid,token,anchor,lock,flock):
    """Cooperating-writer checked replacement, NOT a kernel atomic CAS.

    The same-directory rename is atomic; the check/rename pair is not.
    """
    from installer import digest
    digest(after)
    if before is not None: digest(before)
    need(mode in ('600','700') and type(uid) is int and uid>=0, 'replacement metadata')
    need(re.fullmatch('[0-9a-f]{32}',token) is not None,'replacement token')
    ancestors=checked_ancestors(path,anchor,uid)
    temp=path+'.upgrade-'+token
    check=(exact_file(path,before,mode,uid) if before is not None else
           '[ ! -e '+q(path)+' ] && [ ! -L '+q(path)+' ] || exit 72')
    return f'''set -eu
umask 077
{{ {q(flock)} -n 9 || exit 75
[ "$(id -u)" = {uid} ] || exit 70
{ancestors}
{check}
t={q(temp)}
(set -C; exec 7>"$t" || exit 73; base64 -d >&7) || exit 73
[ ! -L "$t" ] && [ -f "$t" ] && [ "$(stat -c '%u %g %h' "$t")" = '{uid} {uid} 1' ] || exit 74
identity=$(stat -c '%d:%i' "$t")
cleanup() {{
  {ancestors}
  if [ ! -L "$t" ] && [ -f "$t" ] && [ "$(stat -c '%d:%i' "$t")" = "$identity" ] && [ "$(stat -c '%u %g %h' "$t")" = '{uid} {uid} 1' ] && [ "$(sha256sum "$t" | cut -d ' ' -f1)" = {after} ]; then
    rm -- "$t"
  fi
}}
trap cleanup EXIT
[ "$(sha256sum "$t" | cut -d ' ' -f1)" = {after} ] || exit 74
chmod {mode} "$t"
{ancestors}
{check}
[ ! -L "$t" ] && [ "$(stat -c '%d:%i' "$t")" = "$identity" ] || exit 74
{exact_file(temp,after,mode,uid)}
mv -f -- "$t" {q(path)}
trap - EXIT
{exact_file(path,after,mode,uid)}
}} 9<{q(lock)}
'''


def parse_package(data, p):
    try: lines=data.decode('utf-8').splitlines()
    except UnicodeError: raise Refusal('package encoding') from None
    need(lines[:5] == [p['serial'],'2000','u:r:shell:s0','Enforcing',str(p['app_uid'])],
         'runtime serial/UID/context/SELinux')
    text='\n'.join(lines[5:])
    versions=re.findall(r'\bversionCode=(\d+)\b',text)
    uids={int(x) for x in re.findall(r'^\s*(?:appId|userId)=(\d+)\b',text,re.M)}
    paths=re.findall(r'^package:(/[^\r\n]+)$',text,re.M)
    need(len(versions)==1 and uids=={p['app_uid']} and len(paths)==1,'package identity or split APK')
    path=paths[0]
    need(re.fullmatch(r'/data/app/[A-Za-z0-9_./=+~-]+/base\.apk',path) is not None and
         '..' not in path.split('/'), 'installed APK path')
    return {'version':int(versions[0]),'uid':p['app_uid'],'path':path}


class Transport:
    def __init__(self, profile, event, execute=False):
        self.p = validate_profile(profile)
        self.event = event
        self.execute = execute
        self.calls = 0
        self.before_mutation = None

    def command(self, args):
        need(args and args[0] in ('status','shell','push','pull'), 'transport operation')
        t=self.p['transport']
        if t['kind']=='controller': return t['argv'] + args
        need(args[0]!='status', 'ADB status is not device identity')
        if args[0]=='shell': args=['shell','-T',*args[1:]]
        return t['argv'] + ['-s',t['serial']] + args

    def call(self,args,label,data=None,timeout=45,mutating=False):
        need(label in LABELS,'event label')
        need(not mutating or self.execute, 'explicit execute required')
        if mutating:
            need(callable(self.before_mutation),'mutation requires bound maintenance/control gate')
            self.before_mutation()
        command=self.command(args)
        self.calls += 1
        try:
            r=subprocess.run(command,input=data,capture_output=True,timeout=timeout,shell=False)
        except subprocess.TimeoutExpired as exc:
            self.event(label,'timeout-unconfirmed',exc.stdout or b'',exc.stderr or b'')
            raise Refusal('transport timeout; inspect before resume') from None
        except OSError:
            self.event(label,'unavailable',b'',b'')
            raise Refusal('transport unavailable') from None
        self.event(label,r.returncode,r.stdout,r.stderr)
        need(r.returncode==0,'transport operation failed; inspect before resume')
        return r.stdout

    def shell(self,code,label,data=None,mutating=False,timeout=45):
        return self.call(['shell',code],label,data,timeout,mutating)

    def app(self,code,label,data=None,mutating=False,timeout=45):
        return self.shell('run-as com.termux /system/bin/sh -c '+q(code),label,data,mutating,timeout)


class AndroidRemote:
    def __init__(self,inputs,out,execute=False,transport=None):
        self.inputs=inputs
        self.p=inputs.p
        self.out=out
        self.t=transport or Transport(self.p,out.event,execute)

    @property
    def calls(self): return self.t.calls

    def bind_guard(self,guard):self.t.before_mutation=guard

    def package(self):
        code=('getprop ro.serialno; id -u; id -Z; getenforce; run-as com.termux id -u; '
              "dumpsys package com.termux | grep -E 'versionCode=|userId=|appId='; pm path com.termux")
        result=parse_package(self.t.shell(code,'package'),self.p)
        raw=self.t.shell('set -eu; [ ! -L '+q(result['path'])+' ]; sha256sum '+q(result['path']),'installed-apk')
        from installer import digest
        result['sha256']=digest(raw.decode().split()[0])
        return result

    def read(self,path,app=True):
        allowed={MANAGER,BIN+'tablet',BIN+'tablet-guardian',BIN+'tablet-daemon',
                 APP+'/files/home/.bashrc',STATE+'autostart.json',STATE+'health.json',
                 STATE+'port',STATE+'device.serial',STATE+'session.lock',
                 APP+'/shared_prefs/private_adb_autostart.xml',APP+'/shared_prefs/private_adb_native_lease.xml'}
        base=self.p['base']
        need(path in allowed or path in {base+'/'+n for n in ('v2.watch','v2.child','health.watch')} or
             re.fullmatch(r'/proc/[1-9][0-9]*/(?:stat|status|cmdline|attr/current)',path), 'read scope')
        ancestors=''
        if path.startswith(APP+'/'):ancestors=checked_ancestors(path,APP,self.p['app_uid'])+'\n'
        elif path.startswith(base+'/'):ancestors=checked_ancestors(path,base,2000)+'\n'
        code='set -eu\n'+ancestors+'[ ! -L '+q(path)+' ]; base64 '+q(path)
        raw=(self.t.app if app else self.t.shell)(code,'read')
        try: return base64.b64decode(re.sub(rb'\s+',b'',raw),validate=True)
        except ValueError: raise Refusal('file transport encoding') from None

    def presence(self,path,app=True):
        code='if [ -L '+q(path)+' ]; then exit 71; elif [ -e '+q(path)+' ]; then printf yes; else printf no; fi'
        reply=(self.t.app if app else self.t.shell)(code,'presence')
        need(reply in (b'yes',b'no'),'presence response')
        return reply==b'yes'

    def metadata(self,path):
        raw=self.t.app('set -eu; '+checked_ancestors(path,APP,self.p['app_uid'])+'\n[ ! -L '+q(path)+' ] && [ -f '+q(path)+' ]; stat -c \'%a %u %g %h %s\' '+q(path),'metadata')
        f=raw.decode().split()
        need(len(f)==5 and all(x.isdigit() for x in f),'metadata format')
        need(f[1:4]==[str(self.p['app_uid']),str(self.p['app_uid']),'1'] and f[0] in ('600','700'), 'app file metadata')
        return f

    def process(self,pid,app=False):
        need(isinstance(pid,str) and pid.isdigit() and int(pid)>1,'process PID')
        root='/proc/'+pid+'/'
        raw=self.read(root+'stat',app).decode()
        try: start=raw.rsplit(') ',1)[1].split()[19]
        except IndexError: raise Refusal('process stat') from None
        status=self.read(root+'status',app)
        uid=re.findall(rb'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status,re.M)
        need(len(uid)==1,'process UID fields')
        exe=(self.t.app if app else self.t.shell)('readlink '+q(root+'exe'),'process').strip()
        # Authorized shell can observe the kernel label on OEMs where run-as
        # cannot. Keep every other app process observation in the app domain.
        return {'starttime':start,'exe':exe,'cmd':self.read(root+'cmdline',app),
                'uid':list(map(int,uid[0])),'context':self.read(root+'attr/current',False).strip(b'\x00\r\n')}

    def listeners(self):
        raw=self.t.shell('ss -H -lnt','listeners').decode().splitlines()
        scoped=[]
        for line in raw:
            parts=line.split()
            need(len(parts)>=5,'listener format')
            local=parts[3]
            if re.search(r':(?:27184|'+str(self.p['native_port'])+r')$',local): scoped.append(local)
        need(scoped.count('127.0.0.1:27184')==1,'private listener missing')
        need(all(x in ('127.0.0.1:27184','127.0.0.1:'+str(self.p['native_port'])) for x in scoped),
             'non-loopback scoped listener')
        return sorted(scoped)

    def native_launch(self):
        # Fixed independent observations, not a profile label or an inferred domain.
        raw=self.t.shell('set -eu; run-as com.termux id -u; run-as com.termux id -Z','process')
        try: lines=raw.decode('ascii').splitlines()
        except UnicodeError: raise Refusal('native launch encoding') from None
        need(len(lines)==2 and lines[0]==str(self.p['app_uid']), 'native launch UID/context')
        launch={'uid':self.p['app_uid'],'context':lines[1]}
        validate_native_launch(launch,self.p['app_uid'])
        return launch

    def native(self,listeners,allow_missing=False,launch=None):
        if launch is None:launch=self.native_launch()
        validate_native_launch(launch,self.p['app_uid'])
        ids=self.t.shell('pidof adb || true','process').decode().split()
        need(all(x.isdigit() and int(x)>1 for x in ids) and len(ids)==len(set(ids)), 'native PID list')
        servers=[]
        for pid in ids:
            proc=self.process(pid,True)
            if proc['uid'][0]!=self.p['app_uid']: continue
            need(proc['uid']==[self.p['app_uid']]*4,'native UID fields')
            if b'fork-server' not in proc['cmd']: continue
            need(proc['exe']==(BIN+'adb').encode(),'native executable path')
            cmd=proc['cmd'].split(b'\x00')
            need(len(cmd)==8 and cmd[0] in (b'adb',(BIN+'adb').encode()) and
                 cmd[1:6]==[b'-L',('tcp:localhost:'+str(self.p['native_port'])).encode(),b'fork-server',b'server',b'--reply-fd'] and
                 cmd[6].isdigit() and cmd[7]==b'', 'native server argv')
            inode=self.t.app('stat -Lc \'%d:%i\' /proc/'+pid+'/exe; stat -c \'%d:%i\' '+BIN+'adb','process').decode().splitlines()
            need(len(inode)==2 and inode[0]==inode[1] and re.fullmatch(r'\d+:\d+',inode[0]),'native executable inode')
            context=proc['context'].decode()
            validate_native_launch(launch,self.p['app_uid'],context)
            servers.append({'pid':int(pid),'starttime':int(proc['starttime']),'exe':BIN+'adb',
                            'argv_sha256':sha(proc['cmd']),'inode':inode[0],'uid':self.p['app_uid'],
                            'context':context,'listener':'127.0.0.1:'+str(self.p['native_port'])})
        native_listener='127.0.0.1:'+str(self.p['native_port'])
        if not servers:
            need(allow_missing and native_listener not in listeners,'native server absent or unknown listener')
            return None
        need(len(servers)==1 and listeners.count(native_listener)==1,'native server/listener ambiguous')
        return servers[0]

    def key_metadata(self):
        home=self.p['native_home']; uid=self.p['app_uid']
        dirs=list(dict.fromkeys([home,home+'/.android']))
        code='set -eu\n'+checked_ancestors(home+'/.android/adbkey',APP,uid)+'\n'
        for path in dirs:
            code+='[ ! -L '+q(path)+' ] && [ -d '+q(path)+' ] && [ "$(stat -c \'%a %u %g\' '+q(path)+')" = '+q(f'700 {uid} {uid}')+' ] || exit 71\n'
        for path in (home+'/.android/adbkey',home+'/.android/adbkey.pub'):
            code+='[ ! -L '+q(path)+' ] && [ -s '+q(path)+' ] && [ -f '+q(path)+' ] && [ "$(stat -c \'%a %u %g %h\' '+q(path)+')" = '+q(f'600 {uid} {uid} 1')+' ] || exit 71\n'
        # Stat only. Never cat, base64 or hash a native key, including the public key.
        code+='stat -c \'%a %u %g %h %s %n\' '+' '.join(q(x) for x in dirs+[home+'/.android/adbkey',home+'/.android/adbkey.pub'])
        return sha(self.t.app(code,'keys-stat'))

    def control(self):
        from installer import json_bytes
        prefs=self.read(APP+'/shared_prefs/private_adb_autostart.xml')
        lease=self.read(APP+'/shared_prefs/private_adb_native_lease.xml')
        health=json_bytes(self.read(STATE+'health.json'))
        clock=self.t.shell('cat /proc/sys/kernel/random/boot_id; cat /proc/uptime; settings get global adb_wifi_enabled; getenforce','clock').decode().splitlines()
        control=validate_control(prefs,lease,health,clock,self.presence(STATE+'start.pending'))
        return control,health,clock

    def late_control(self):
        return self.control()[0]

    def snapshot(self,allow_missing_native=False):
        from installer import json_bytes,digest
        control,health,clock=self.control()
        config=json_bytes(self.read(STATE+'autostart.json'))
        need(config.get('expectedSerial')==self.p['serial'] and type(config.get('enabled')) is bool and
             config.get('heartbeatPath')==STATE+'health.json','config identity/heartbeat')
        permitted={MANAGER}
        if any(x['path']==STATE+'autostart.json' for x in self.inputs.r['payloads']): permitted.add(BIN+'tablet-daemon')
        need(config.get('managerPath') in permitted,'config manager path')
        control['config_preserved']={k:config[k] for k in ('expectedSerial','enabled','heartbeatPath')}
        shell_exe=self.t.shell('readlink -f /system/bin/sh','process').strip()
        pids={}
        for name in ['v2.watch','v2.child']+(['health.watch'] if self.p['publisher']=='independent' else []):
            record=self.read(self.p['base']+'/'+name,False)
            try: pid=record.decode().split()[0]
            except (UnicodeError,IndexError): raise Refusal('PID record') from None
            pids[name]=validate_process(name,record,clock[0],self.process(pid),self.p,shell_exe)
        need(health.get('watch_pid')==pids['v2.watch']['pid'] and health.get('child_pid')==pids['v2.child']['pid'], 'heartbeat producer identity')
        inv={}
        base_meta=self.t.shell('stat -c \'%a %u %g\' '+q(self.p['base']),'metadata').decode().split()
        need(base_meta==['700','2000','2000'],'BASE directory permissions')
        names=['service.sh','private-adbd','authorized_keys','service.serial']
        if self.p['publisher']=='independent':names.append('health-publisher.sh')
        for name in names:
            path=self.p['base']+'/'+name
            raw=self.t.shell('set -eu; '+checked_ancestors(path,self.p['base'],2000)+'\n[ ! -L '+q(path)+' ] && [ -f '+q(path)+' ]; stat -c \'%a %u %g %h %s\' '+q(path)+'; sha256sum '+q(path),'invariant').decode().splitlines()
            need(len(raw)==2,'shell invariant response')
            meta=raw[0].split(); mode='600' if name in ('authorized_keys','service.serial') else '700'
            need(len(meta)==5 and meta[:4]==[mode,'2000','2000','1'],'shell invariant metadata')
            inv[name]={'metadata':meta,'sha256':digest(raw[1].split()[0])}
        state={}
        for name in ('port','device.serial','session.lock'):
            path=STATE+name;meta=self.metadata(path)
            need(meta[0]=='600','wrapper state mode')
            state[name]={'metadata':meta,'sha256':sha(self.read(path))}
        directory=self.t.app('stat -c \'%a %u %g\' '+q(STATE.rstrip('/')),'metadata').decode().split()
        need(directory==['700',str(self.p['app_uid']),str(self.p['app_uid'])],'STATE directory permissions')
        self.t.app(BIN+'flock -n 9 9<'+STATE+'session.lock','lock-probe')
        listeners=self.listeners()
        launch=self.native_launch()
        return {'control':control,'pids':pids,'shell_files':inv,'wrapper_state':state,
                'key_metadata_sha256':self.key_metadata(),'listeners':listeners,
                'native':self.native(listeners,allow_missing_native,launch),'native_launch':launch,
                'health_uptime':health['uptime_ms']}

    def backup_installed(self,pkg,name):
        need(name in ('baseline.apk','current.apk'),'APK backup filename')
        need(self.package()==pkg,'APK changed before backup')
        raw=self.t.shell('base64 '+q(pkg['path']),'installed-apk',timeout=180)
        try:data=base64.b64decode(re.sub(rb'\s+',b'',raw),validate=True)
        except ValueError:raise Refusal('APK transport encoding') from None
        need(sha(data)==pkg['sha256'] and self.package()==pkg,'APK backup integrity')
        self.out.raw(name,data)
        return self.out.path/name

    def file_state(self,path):
        if not self.presence(path):return None
        meta=self.metadata(path); data=self.read(path)
        need(len(data)==int(meta[4]),'file changed during capture')
        return {'metadata':meta,'sha256':sha(data)}

    @staticmethod
    def token(token):
        need(isinstance(token,str) and re.fullmatch('[0-9a-f]{32}',token),'deployment token')
        return token

    def stage_path(self,token):return '/data/local/tmp/private-adbd-upgrade-'+self.token(token)

    def owner_checks(self,path,token,uid):
        self.token(token)
        owner=path+'/owner'
        return (checked_ancestors(owner,path,uid)+'\n'+
                '[ ! -L '+q(path)+' ] && [ -d '+q(path)+' ] && [ "$(stat -c \'%a %u %g\' '+q(path)+')" = '+q(f'700 {uid} {uid}')+' ] || exit 71\n'+
                exact_file(owner,sha((token+'\n').encode()),'600',uid)+'\n')

    def lock_path(self):return STATE+'.private-adbd-upgrade.lock'

    def acquire_lock(self,token):
        self.token(token);path=self.lock_path();uid=self.p['app_uid']
        code='set -eu\numask 077\n'+checked_ancestors(path,APP,uid)+'\nmkdir '+q(path)+'\n(set -C; printf \'%s\\n\' '+token+' > '+q(path+'/owner')+')\n'+self.owner_checks(path,token,uid)
        self.t.app(code,'acquire-lock',mutating=True)

    def lock_owned(self,token):
        code='set -eu\n'+self.owner_checks(self.lock_path(),token,self.p['app_uid'])+'printf yes'
        return self.t.app(code,'stage-check')==b'yes'

    def lock_absent(self):return not self.presence(self.lock_path())

    def reserve_stage(self,token):
        path=self.stage_path(token)
        code='set -eu\numask 077\n[ ! -L /data ] && [ ! -L /data/local ] && [ ! -L /data/local/tmp ] || exit 71\nmkdir '+q(path)+'\n(set -C; printf \'%s\\n\' '+token+' > '+q(path+'/owner')+')\n'+self.owner_checks(path,token,2000)
        self.t.shell(code,'stage-reserve',mutating=True)

    def stage_owned(self,token,require_apk=False,allow_unsealed=False):
        path=self.stage_path(token)
        code='set -eu\n'+self.owner_checks(path,token,2000)
        if require_apk:
            if allow_unsealed:code+=self.unsealed_checks(path+'/base.apk')+'\n'
            else:code+=exact_file(path+'/base.apk',self.inputs.r['sha256'],'600',2000)+'\n'
        code+='printf yes'
        return self.t.shell(code,'stage-check')==b'yes'

    def stage_absent(self,token):return not self.presence(self.stage_path(token),False)

    def push_apk(self,token):
        need(self.stage_owned(token),'stage ownership')
        path=self.stage_path(token)+'/base.apk'
        self.t.shell('[ ! -e '+q(path)+' ] && [ ! -L '+q(path)+' ]','stage-check')
        data=self.inputs.apk.read_bytes()
        need(sha(data)==self.inputs.r['sha256'],'APK changed before push')
        source=self.out.path/'candidate.apk'
        if not source.exists():self.out.raw('candidate.apk',data)
        need(sha(source.read_bytes())==self.inputs.r['sha256'],'private candidate APK bytes')
        self.t.call(['push',str(source),path],'push',mutating=True,timeout=180)

    def install_apk(self,token):
        need(self.stage_owned(token,True),'staged APK not exact')
        reply=self.t.shell('pm install -r '+q(self.stage_path(token)+'/base.apk'),'install',mutating=True,timeout=180)
        need(reply.strip()==b'Success','package install response unconfirmed')

    def unsealed_checks(self,path):
        return ('[ ! -L '+q(path)+' ] && [ -f '+q(path)+' ] && '
                '[ "$(stat -c \'%u %g %h\' '+q(path)+')" = \'2000 2000 1\' ] && '
                '[ "$(sha256sum '+q(path)+' | cut -d \' \' -f1)" = '+self.inputs.r['sha256']+' ] || exit 72\n'+
                'case "$(stat -c %a '+q(path)+')" in 600|644|666) ;; *) exit 72;; esac')

    def seal_stage(self,token):
        path=self.stage_path(token)
        code='set -eu\n'+self.owner_checks(path,token,2000)+self.unsealed_checks(path+'/base.apk')+'\nchmod 600 '+q(path+'/base.apk')+'\n'+exact_file(path+'/base.apk',self.inputs.r['sha256'],'600',2000)
        self.t.shell(code,'stage-seal',mutating=True)

    def write_payload(self,p,token):
        code=replace_script(p['path'],p['before_sha256'],p['sha256'],p['mode'],self.p['app_uid'],
                            self.token(token),APP,STATE+'session.lock',BIN+'flock')
        self.t.app(code,'payload',base64.b64encode(self.inputs.payloads[p['path']])+b'\n',mutating=True)

    def start_native(self):
        home=self.p['native_home'];uid=self.p['app_uid'];port=self.p['native_port']
        self.key_metadata()  # stat-only: key creation is never a fallback.
        code='set -eu\numask 077\n'+checked_ancestors(APP+'/files/usr/tmp/adb.log',APP,uid)+'\n'
        code+='[ "$(id -u)" = '+str(uid)+' ] && [ "$(stat -c \'%a %u %g\' '+APP+'/files/usr/tmp)" = '+q(f'700 {uid} {uid}')+' ] || exit 71\n'
        code+='if ss -H -lnt | grep -E '+q(':'+str(port)+'( |$)')+' >/dev/null; then exit 75; fi\n'
        code+='export HOME='+q(home)+'\nexport PREFIX='+APP+'/files/usr\nexport TMPDIR='+APP+'/files/usr/tmp\nexport PATH="$PREFIX/bin:/system/bin"\n'
        code+='unset ADB_SERVER_SOCKET ANDROID_ADB_SERVER_PORT ANDROID_USER_HOME ANDROID_SDK_HOME ANDROID_SERIAL ADB_TRACE ADB_EMU ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH\n'
        code+='export ADB_VENDOR_KEYS='+q(home+'/.android/adbkey')+'\nexport ADB_MDNS_AUTO_CONNECT=0\nexport ADB_LOCAL_TRANSPORT_MAX_PORT=0\nexport LC_ALL=C\n'
        code+='{ '+BIN+'flock -n 9 || exit 75\n'+BIN+'timeout 5 '+BIN+'adb -L tcp:localhost:'+str(port)+' start-server 9>&-\n} 9<'+STATE+'session.lock\n'
        self.t.app(code,'native-start',mutating=True,timeout=15)

    def remove_legacy(self,item):
        need(item['path']==BIN+'tablet-daemon' and item['mode']=='700','legacy removal scope')
        code='set -eu\n'+checked_ancestors(item['path'],APP,self.p['app_uid'])+'\n'+exact_file(item['path'],item['sha256'],item['mode'],self.p['app_uid'])+'\nrm -- '+q(item['path'])
        self.t.app(code,'legacy-remove',mutating=True)

    def clean_stage(self,token):
        path=self.stage_path(token)
        code='set -eu\n'+self.owner_checks(path,token,2000)+exact_file(path+'/base.apk',self.inputs.r['sha256'],'600',2000)+'\nrm -- '+q(path+'/base.apk')+' '+q(path+'/owner')+'\nrmdir '+q(path)
        self.t.shell(code,'stage-clean',mutating=True)

    def release_lock(self,token):
        path=self.lock_path()
        code='set -eu\n'+self.owner_checks(path,token,self.p['app_uid'])+'rm -- '+q(path+'/owner')+'\nrmdir '+q(path)
        self.t.app(code,'lock-release',mutating=True)

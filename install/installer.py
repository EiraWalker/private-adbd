#!/usr/bin/env python3
"""Fail-closed upgrader for an already provisioned debuggable Termux fork.

No import-time subprocesses or device access. Python 3.11+, standard library.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

from common import Refusal, need, sha
from private_output import PrivateOutput

APP = '/data/data/com.termux'
BIN = APP + '/files/usr/bin/'
STATE = APP + '/files/home/.config/tablet-daemon/'
MANAGER = BIN + 'private-adbd'


def validate_maintenance(obj, profile_hash, release_hash, serial, now=None):
    fields(obj, ('schema', 'profile_sha256', 'release_sha256', 'serial', 'owner',
                 'ready', 'released', 'no_parallel', 'issued_at', 'expires_at'), ('checkpoint_sha256',))
    need(type(obj['schema']) is int and obj['schema'] == 1, 'maintenance schema')
    need(obj['profile_sha256'] == profile_hash and obj['release_sha256'] == release_hash
         and obj['serial'] == serial, 'maintenance binding')
    need(all(obj[k] is True for k in ('ready', 'released', 'no_parallel')), 'owner handoff')
    need(isinstance(obj['owner'], str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', obj['owner']), 'owner identity')
    try:
        issued = dt.datetime.fromisoformat(obj['issued_at'])
        expires = dt.datetime.fromisoformat(obj['expires_at'])
        now = now or dt.datetime.now(dt.timezone.utc)
        need(issued.tzinfo is not None and expires.tzinfo is not None, 'maintenance timezone')
        need(issued <= now < expires and 0 < (expires - issued).total_seconds() <= 1800, 'maintenance window')
    except (TypeError, ValueError):
        raise Refusal('maintenance dates') from None
    return obj


def argv(value):
    need(type(value) is list and 1 <= len(value) <= 32 and
         all(isinstance(x, str) and x and not any(c in x for c in '\x00\r\n') for x in value), 'tool argv')
    return value


class SDK:
    """Actual APK signature verification and manifest badging; no DEX claims."""
    def __init__(self, apksigner_argv, aapt_argv):
        self.signer = argv(apksigner_argv)
        self.aapt = argv(aapt_argv)
        self.calls = 0

    def call(self, args):
        self.calls += 1
        try:
            result = subprocess.run(args, capture_output=True, timeout=120, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refusal('offline SDK tool unavailable or timed out') from None
        need(result.returncode == 0, 'offline SDK verification failed')
        return result.stdout

    def verify(self, path, expected):
        need(sha(Path(path).read_bytes()) == expected['sha256'], 'APK bytes before verification')
        out = self.call(self.signer + ['verify', '--print-certs', str(path)])
        certs = re.findall(rb'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})\r?$', out, re.M)
        need(len(certs) == 1 and certs[0].decode().lower() == expected['signer_sha256'], 'APK signer')
        out = self.call(self.aapt + ['dump', 'badging', str(path)])
        packages = re.findall(rb"^package: name='([^']+)' versionCode='(\d+)'[^\r\n]*\r?$", out, re.M)
        need(packages == [(b'com.termux', str(expected['version']).encode())], 'APK package/version')
        need(re.search(rb'^application-debuggable\r?$', out, re.M) is not None, 'APK debuggable')
        need(b'split=' not in out, 'split APK unsupported')
        need(sha(Path(path).read_bytes()) == expected['sha256'], 'APK bytes after verification')
        return {k: expected[k] for k in ('sha256', 'version', 'package', 'signer_sha256', 'debuggable')}




def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'digest format')
    return value


def local_file(root, value):
    need(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_./-]+', value), 'local source path')
    p = PurePosixPath(value)
    need(not p.is_absolute() and all(x not in ('', '.', '..') for x in value.split('/')), 'relative source path')
    root = Path(root).absolute()
    path = root
    for part in p.parts:
        path = path / part
        need(not path.is_symlink(), 'local source symlink')
    from private_output import no_links
    no_links(path)
    need(path.is_file() and path.stat().st_nlink == 1, 'local source file')
    return path


def validate_release(r, root):
    fields(r, ('schema', 'apk', 'sha256', 'version', 'package', 'signer_sha256',
               'debuggable', 'baselines', 'payloads', 'remove_legacy'), ('source_revision','maintenance_api'))
    need(type(r['schema']) is int and r['schema'] == 1, 'release schema')
    if 'maintenance_api' in r:
        need(type(r['maintenance_api']) is int and r['maintenance_api']==1, 'maintenance API version')
    need(r['package'] == 'com.termux' and r['debuggable'] is True, 'release package/debuggable')
    need(integer(r['version'], 1, 2**31-1), 'release version')
    digest(r['sha256']); digest(r['signer_sha256'])
    need(sha(local_file(root, r['apk']).read_bytes()) == r['sha256'], 'APK bytes')
    need(type(r['baselines']) is list and 1 <= len(r['baselines']) <= 32, 'baselines')
    seen = set()
    for b in r['baselines']:
        fields(b, ('version', 'sha256'))
        need(integer(b['version'], 1, r['version'] - 1), 'no downgrade or same-version rewrite')
        digest(b['sha256'])
        need((b['version'], b['sha256']) not in seen, 'duplicate baseline')
        seen.add((b['version'], b['sha256']))
    allowed = {MANAGER: '700', BIN+'tablet-guardian': '700', BIN+'tablet': '700',
               APP+'/files/home/.bashrc': '600', STATE+'autostart.json': '600'}
    need(type(r['payloads']) is list and len(r['payloads']) <= len(allowed), 'payloads')
    seen = set()
    for p in r['payloads']:
        fields(p, ('path', 'source', 'sha256', 'before_sha256', 'mode', 'phase'))
        need(p['path'] in allowed and p['path'] not in seen, 'payload destination')
        seen.add(p['path'])
        need(p['mode'] == allowed[p['path']] and p['phase'] in ('before_apk', 'after_apk'), 'payload mode/phase')
        digest(p['sha256'])
        if p['before_sha256'] is not None:
            digest(p['before_sha256'])
        need(sha(local_file(root, p['source']).read_bytes()) == p['sha256'], 'payload bytes')
        if p['path'] == STATE+'autostart.json':
            need(p['before_sha256'] is not None, 'config requires existing baseline')
    need(type(r['remove_legacy']) is list and len(r['remove_legacy']) <= 1, 'legacy cleanup')
    for old in r['remove_legacy']:
        fields(old, ('path', 'sha256', 'mode'))
        need(old['path'] == BIN+'tablet-daemon' and old['mode'] == '700', 'legacy command scope')
        digest(old['sha256'])
    if 'source_revision' in r:
        need(isinstance(r['source_revision'], str) and len(r['source_revision']) <= 200 and
             not any(c in r['source_revision'] for c in '\r\n\x00'), 'source metadata')
    return r


def fields(obj, required, optional=()):
    need(type(obj) is dict and set(required) <= set(obj) <= set(required) | set(optional), 'schema fields')


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def safe_path(value, root):
    need(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_./-]+', value) is not None,
         'path characters')
    need(value.startswith(root + '/') and all(x not in ('', '.', '..') for x in value.split('/')[1:]),
         'path scope')
    return value


def validate_profile(p):
    fields(p, ('schema', 'serial', 'app_uid', 'package', 'base', 'native_port',
               'native_home', 'publisher', 'transport'))
    need(type(p['schema']) is int and p['schema'] == 1, 'profile schema')
    need(isinstance(p['serial'], str) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', p['serial']), 'serial')
    need(integer(p['app_uid'], 10000, 199999), 'app UID')
    need(p['package'] == 'com.termux', 'package')
    safe_path(p['base'], '/data/local/tmp')
    need(p['base'].count('/') == 4, 'base must be a single private directory')
    need(integer(p['native_port'], 1024, 65535) and p['native_port'] != 27184, 'native port')
    need(p['native_home'] in (APP + '/files/home', STATE + 'native-home'), 'native HOME')
    need(p['publisher'] in ('embedded', 'independent'), 'publisher mode')
    from discovery import validate_transport
    validate_transport(p['transport'])
    return p


def json_bytes(data):
    def unique(pairs):
        result={}
        for key,value in pairs:
            need(key not in result,'duplicate JSON field')
            result[key]=value
        return result
    try: return json.loads(data.decode('utf-8-sig'),object_pairs_hook=unique)
    except (UnicodeError, ValueError): raise Refusal('JSON encoding/syntax') from None


class Inputs:
    def __init__(self, profile_path, release_path, sdk):
        self.profile_path=Path(profile_path).absolute()
        self.release_path=Path(release_path).absolute()
        from private_output import no_links
        no_links(self.profile_path); no_links(self.release_path)
        self.profile_bytes=self.profile_path.read_bytes()
        self.release_bytes=self.release_path.read_bytes()
        self.p=validate_profile(json_bytes(self.profile_bytes))
        self.r=validate_release(json_bytes(self.release_bytes),self.release_path.parent)
        self.apk=local_file(self.release_path.parent,self.r['apk'])
        self.sdk=sdk
        self.sdk.verify(self.apk,self.r)
        self.bindings={'profile_sha256':sha(self.profile_bytes),'release_sha256':sha(self.release_bytes)}
        self.payloads={p['path']:local_file(self.release_path.parent,p['source']).read_bytes() for p in self.r['payloads']}

    def unchanged(self):
        from private_output import no_links
        no_links(self.profile_path); no_links(self.release_path)
        need(self.profile_path.read_bytes()==self.profile_bytes and
             self.release_path.read_bytes()==self.release_bytes,'input manifest changed')
        validate_release(self.r,self.release_path.parent)


def run(args,remote_factory=None,sdk=None):
    if args.command == 'probe':
        need(not getattr(args, 'execute', False), 'probe is read-only')
        from discovery import probe
        transport = {'kind': args.transport_kind, 'argv': json_bytes(args.transport_argv.encode())}
        if args.transport_serial is not None: transport['serial'] = args.transport_serial
        return probe(transport, args.output, args.expected_serial)
    need(not args.execute or args.command in ('apply','resume'),'execute command scope')
    if args.command == 'verify':
        need(args.maintenance is None and args.checkpoint_sha256 is None,
             'verify does not accept upgrade authorization')
    sdk=sdk or SDK(json_bytes(args.apksigner_argv.encode()),json_bytes(args.aapt_argv.encode()))
    inputs=Inputs(args.profile,args.release,sdk)
    if args.command in ('plan','apply','resume') and not args.execute:
        out=PrivateOutput(args.output,create=True)
        result={'result':'dry-run','device_calls':0,'bindings':inputs.bindings,
                'operations':['readonly-preflight','private-backups','owned-lock','before-apk-payloads',
                              'owned-stage','install-r-once','after-apk-payloads','bounded-native-rebuild',
                              'full-readback','exact-legacy-cleanup','owned-cleanup','complete-readback'],
                'source_metadata_verified':False}
        if inputs.r.get('maintenance_api')==1:
            result['operations'].insert(result['operations'].index('owned-lock'),'maintenance-acquire')
            result['operations'].insert(result['operations'].index('install-r-once')+1,'maintenance-reack')
            result['operations'].append('maintenance-release')
        out.write('plan.json',result)
        return result
    # Only an explicit device command reaches the live construction boundary.
    from android import AndroidRemote
    from upgrade import Engine, Authorization
    out=PrivateOutput(args.output,create=args.command!='resume')
    remote=(remote_factory or AndroidRemote)(inputs,out,args.execute)
    if args.command=='verify':
        from stability import verify_stability
        return verify_stability(remote,inputs,out)
    if args.command=='inspect':
        package=remote.package()
        snapshot=remote.snapshot(allow_missing_native=True)
        out.write('inspect.json',{'schema':1,'package':package,'runtime':snapshot,'bindings':inputs.bindings})
        return {'result':'inspected','device_calls':remote.calls,'evidence_private':True}
    authorization=Authorization(args.maintenance,inputs,args.checkpoint_sha256 if args.command=='resume' else None)
    return Engine(inputs,remote,out,authorization).run(resume=args.command=='resume',checkpoint_hash=args.checkpoint_sha256)


class CommandParser(argparse.ArgumentParser):
    """Keep legacy option ordering, but never ignore command-specific options."""
    def parse_args(self, args=None, namespace=None):
        result=super().parse_args(args, namespace)
        probe_fields=('transport_kind','transport_argv','transport_serial','expected_serial')
        upgrade_fields=('profile','release','execute','maintenance','checkpoint_sha256','apksigner_argv','aapt_argv')
        forbidden=upgrade_fields if result.command=='probe' else probe_fields
        if any(getattr(result, name) is not None for name in forbidden):
            self.error('options outside selected command scope')
        required=('transport_kind','transport_argv') if result.command=='probe' else ('profile','release')
        if any(getattr(result, name) is None for name in required):
            self.error('probe requires --transport-kind/--transport-argv; other commands require --profile/--release')
        if result.command=='verify' and (result.maintenance is not None or result.checkpoint_sha256 is not None):
            self.error('verify does not accept upgrade authorization')
        if result.command!='probe':
            result.execute=bool(result.execute)
            if result.apksigner_argv is None: result.apksigner_argv='["apksigner"]'
            if result.aapt_argv is None: result.aapt_argv='["aapt"]'
        return result


def parser():
    p=CommandParser(description=__doc__, epilog='probe is read-only; apply/resume --execute requires actual owner handoff.')
    p.add_argument('command',choices=('probe','plan','inspect','verify','apply','resume'))
    p.add_argument('--profile',type=Path,help='required except probe: actual existing-deployment profile')
    p.add_argument('--release',type=Path,help='required except probe: pinned release manifest')
    p.add_argument('--output',type=Path,required=True,help='new private output directory outside repository; resume reuses it')
    p.add_argument('--execute',action='store_true',default=None,help='upgrade only: explicitly authorize mutation; owner handoff still required')
    p.add_argument('--maintenance',type=Path,help='upgrade only: actual owner-issued short-lived local handoff JSON')
    p.add_argument('--checkpoint-sha256',help='upgrade only: exact private checkpoint hash for explicit resume')
    p.add_argument('--apksigner-argv',help='upgrade only: trusted JSON SDK argv prefix (default ["apksigner"])')
    p.add_argument('--aapt-argv',help='upgrade only: trusted JSON SDK argv prefix (default ["aapt"])')
    p.add_argument('--transport-kind',choices=('adb','controller'),help='probe only, required: already-authorized transport kind')
    p.add_argument('--transport-argv',help='probe only, required: trusted JSON argv; adb requires exactly one executable')
    p.add_argument('--transport-serial',help='probe only: exact selector required for adb, forbidden for controller')
    p.add_argument('--expected-serial',help='probe only: optional exact ro.serialno binding, independent of transport selector')
    return p


def main():
    try:
        args=parser().parse_args()
        result=run(args)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except Refusal as exc:
        print('REFUSED: '+str(exc),file=sys.stderr)
        return 2
    except Exception as exc:
        print('FAILED: '+type(exc).__name__+'; inspect private output, no automatic replay',file=sys.stderr)
        return 3


if __name__=='__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Explicit-authority, fresh-only core bootstrap. Python 3.11+, stdlib only.

No import-time or planning device access. Never reads a controller private key.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import shlex
import uuid
import sys

from common import Refusal, need, sha
from installer import digest, fields, json_bytes, local_file, validate_maintenance
from private_output import PrivateOutput, no_links

# Header agreement is not certification of an OEM/runtime or artifact provenance.
ABIS = {'arm64-v8a': (2, 183), 'armeabi-v7a': (1, 40),
        'x86_64': (2, 62), 'x86': (1, 3)}
DEFAULT_BASE_LINE = b'BASE=/data/local/tmp/private-adbd\n'


def profile(obj):
    fields(obj, ('schema', 'serial', 'base', 'transport'))
    need(type(obj['schema']) is int and obj['schema'] == 1, 'core profile schema')
    need(isinstance(obj['serial'], str) and
         re.fullmatch(r'[A-Za-z0-9._-]{1,128}', obj['serial']), 'serial token')
    need(isinstance(obj['base'], str) and
         re.fullmatch(r'/data/local/tmp/[A-Za-z0-9][A-Za-z0-9_-]{0,63}', obj['base']), 'single safe base')
    t = obj['transport']
    fields(t, ('kind', 'argv', 'serial'))
    need(t['kind'] == 'adb', 'official authorized ADB transport required')
    need(type(t['argv']) is list and len(t['argv']) == 1 and
         all(isinstance(x, str) and x and not any(c in x for c in '\x00\r\n') for x in t['argv']), 'trusted ADB argv')
    need(Path(t['argv'][0]).is_absolute(), 'explicit absolute trusted ADB executable required')
    need(isinstance(t['serial'], str) and
         re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:\[\]-]{0,254}', t['serial']), 'exact ADB selector')
    return obj


def keys(data):
    need(0 < len(data) <= 8192, 'public-key policy size')
    result = set()
    for line in data.split(b'\n'):
        parts = line.split()
        if not parts:
            continue
        try:
            raw = base64.b64decode(parts[0], validate=True)
        except (ValueError, binascii.Error):
            raise Refusal('Android public-key encoding') from None
        need(len(raw) == 524 and struct.unpack_from('<I', raw)[0] == 64, 'Android public-key layout')
        n = int.from_bytes(raw[8:264], 'little')
        e = struct.unpack_from('<I', raw, 520)[0]
        need(n.bit_length() == 2048 and n & 1 and e == 65537, 'Android RSA public numbers')
        identity = (n, e)
        need(identity not in result, 'duplicate controller key')
        result.add(identity)
    need(1 <= len(result) <= 2, 'one or two controller keys required')
    return result


def elf_header(data, abi):
    need(abi in ABIS, 'unsupported artifact ABI')
    need(len(data) >= 64 and data[:4] == b'\x7fELF' and
         data[4:7] == bytes((ABIS[abi][0], 1, 1)), 'ELF class/endianness/version')
    typ, machine, version = struct.unpack_from('<HHI', data, 16)
    need(typ in (2, 3) and machine == ABIS[abi][1] and version == 1, 'ELF machine/type/version')


class CoreInputs:
    def __init__(self, profile_path, bundle_path):
        self.profile_path = no_links(profile_path)
        self.bundle_path = no_links(bundle_path)
        self.profile_bytes = self.profile_path.read_bytes()
        self.bundle_bytes = self.bundle_path.read_bytes()
        self.p = profile(json_bytes(self.profile_bytes))
        self.b = json_bytes(self.bundle_bytes)
        fields(self.b, ('schema', 'artifacts', 'service', 'keys', 'controller'))
        need(type(self.b['schema']) is int and self.b['schema'] == 1, 'core bundle schema')
        self.root = self.bundle_path.parent
        self.assets = {}
        need(type(self.b['artifacts']) is list and 1 <= len(self.b['artifacts']) <= len(ABIS), 'ABI assets')
        self.artifacts = {}
        for item in self.b['artifacts']:
            fields(item, ('abi', 'source', 'sha256'))
            need(isinstance(item['abi'], str) and item['abi'] not in self.artifacts, 'duplicate artifact ABI')
            data = self.read_asset(item)
            elf_header(data, item['abi'])
            self.artifacts[item['abi']] = data
        for name in ('service', 'keys', 'controller'):
            fields(self.b[name], ('source', 'sha256'))
            self.assets[name] = self.read_asset(self.b[name])
        allow = keys(self.assets['keys'])
        controller = keys(self.assets['controller'])
        need(len(controller) == 1 and controller == allow, 'fresh bootstrap requires exactly the selected controller key')
        service = self.assets['service']
        # The manifest binds the reviewed source, not an invented shell template.
        reviewed = no_links(Path(__file__).resolve().parents[1]/'lifecycle/service.sh').read_bytes()
        need(service == reviewed and service.count(DEFAULT_BASE_LINE) == 1, 'reviewed lifecycle source required')
        self.assets['service'] = service.replace(DEFAULT_BASE_LINE, ('BASE='+self.p['base']+'\n').encode(), 1)
        self.bindings = {'profile_sha256': sha(self.profile_bytes), 'release_sha256': sha(self.bundle_bytes)}

    def read_asset(self, item):
        digest(item['sha256'])
        data = local_file(self.root, item['source']).read_bytes()
        need(sha(data) == item['sha256'], 'asset hash')
        return data

    def unchanged(self):
        other = CoreInputs(self.profile_path, self.bundle_path)
        need(self.profile_bytes == other.profile_bytes and self.bundle_bytes == other.bundle_bytes,
             'input manifests changed')
        need(self.assets == other.assets and self.artifacts == other.artifacts, 'asset changed')

    def payload(self, abi):
        need(abi in self.artifacts, 'no pinned artifact for ABI')
        return {'private-adbd': (self.artifacts[abi], '700'),
                'service.sh': (self.assets['service'], '700'),
                'authorized_keys': (self.assets['keys'], '600'),
                'service.serial': ((self.p['serial']+'\n').encode(), '600')}

    def file_policy(self, abi):
        return {name: {'sha256': sha(data), 'mode': mode}
                for name, (data, mode) in self.payload(abi).items()}

    def plan(self):
        return {'schema': 1, 'operation': 'fresh-core-only', 'ready': False, 'device_calls': 0,
                'supported_abis': sorted(self.artifacts), 'bindings': self.bindings,
                'requires': ['explicit-execute', 'owner-handoff', 'authorized-shell-ADB',
                             'empty-or-absent-base', 'already-loaded-controller-key',
                             'owned-loopback-forward-acceptance'],
                'termux_required': False}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('plan', 'apply', 'verify'))
    p.add_argument('--profile', required=True)
    p.add_argument('--bundle', required=True)
    p.add_argument('--output', help='Private evidence directory outside checkout (new for apply)')
    p.add_argument('--maintenance', help='Short-lived owner handoff bound to both input hashes')
    p.add_argument('--execute', action='store_true', help='Authorize mutation and owned loopback acceptance; otherwise offline plan')
    return p


def loopback_addresses(addresses):
    return bool(addresses) and all(a in ('127.0.0.1', '::1') for a in addresses)


def host_listener_addresses(port):
    """Inspect only our allocated port; shared ADB -a must not expose the forward."""
    need(type(port) is int and 1024 <= port <= 65535, 'host inspection port')
    if os.name == 'nt':
        code = ("$ErrorActionPreference='Stop'; @(Get-NetTCPConnection -State Listen -LocalPort "+
                str(port)+" | Select-Object -ExpandProperty LocalAddress) | ConvertTo-Json -Compress")
        try:
            r = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', code],
                               capture_output=True, timeout=30, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refusal('host loopback listener inspection unavailable') from None
        need(r.returncode == 0 and len(r.stdout) <= 16384, 'host listener query failed')
        data = json_bytes(r.stdout)
        addresses = [data] if isinstance(data, str) else data
        need(type(addresses) is list and all(isinstance(a, str) for a in addresses), 'host listener schema')
        return addresses
    need(sys.platform.startswith('linux') and sys.byteorder == 'little', 'host listener inspection unsupported on this host')
    addresses = []
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        with open(path, 'rb') as f:
            raw = f.read(2097153)
        need(len(raw) <= 2097152, 'host socket table bound')
        for line in raw.splitlines()[1:]:
            cols = line.split()
            need(len(cols) >= 4, 'host socket table schema')
            address, rawport = cols[1].rsplit(b':', 1)
            if cols[3] == b'0A' and int(rawport, 16) == port:
                addresses.append({b'0100007F': '127.0.0.1',
                                  b'00000000000000000000000001000000': '::1'}.get(address, 'non-loopback'))
    return addresses


def q(value):
    return shlex.quote(value)


def shell_script(label, body):
    # Labels are fixed program text, also used by the synthetic subprocess fixture.
    return '# core-bootstrap:'+label+'\nPATH=/system/bin:/system/xbin\nexport PATH\nunset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH\numask 077\nset -eu\n'+body


def identity_script():
    return shell_script('identity', "printf '%s\\n' \"$(id -u)\" \"$(cat /proc/$$/attr/current)\" \"$(getenforce)\" \"$(getprop ro.serialno)\" \"$(getprop ro.product.cpu.abi)\"\n")


def ancestor_checks(base):
    return '\n'.join('[ ! -L '+q(p)+' ]\n[ -d '+q(p)+' ]' for p in
                     ('/', '/data', '/data/local', '/data/local/tmp'))+'\n[ ! -L '+q(base)+' ]\n'


def fresh_checks(base):
    b = q(base)
    return (ancestor_checks(base)+'if [ -e '+b+' ]; then\n'
            '[ -d '+b+' ]\n[ "$(stat -c \'%u:%a\' '+b+')" = 2000:700 ]\n'
            'for f in '+b+'/* '+b+'/.[!.]* '+b+'/..?*; do\n'
            ' [ ! -e "$f" ] && [ ! -L "$f" ] || exit 2\ndone\nfi\n')


def owned_directory(path, token):
    p = q(path)
    return (ancestor_checks(path)+'[ -d '+p+' ]\n[ "$(stat -c \'%u:%a\' '+p+')" = 2000:700 ]\n'
            '[ ! -L '+p+'/.core-bootstrap ]\n[ -f '+p+'/.core-bootstrap ]\n'
            '[ "$(stat -c \'%u:%a:%h\' '+p+'/.core-bootstrap)" = 2000:600:1 ]\n'
            '[ "$(sha256sum '+p+'/.core-bootstrap | cut -d \' \' -f 1)" = '+q(sha((token+'\n').encode()))+' ]\n')


def file_checks(path, files, sealed, exact=False):
    lines = []
    if exact:
        lines += ['count=0', 'for f in '+q(path)+'/* '+q(path)+'/.[!.]* '+q(path)+'/..?*; do',
                  ' if [ -e "$f" ] || [ -L "$f" ]; then count=$((count+1)); fi', 'done',
                  '[ "$count" = '+str(len(files)+1)+' ]']
    for name, item in files.items():
        f = q(path+'/'+name)
        lines += ['[ ! -L '+f+' ]', '[ -f '+f+' ]',
                  '[ "$(stat -c \'%u:%h\' '+f+')" = 2000:1 ]',
                  '[ "$(sha256sum '+f+' | cut -d \' \' -f 1)" = '+q(item['sha256'])+' ]']
        if sealed:
            lines += ['[ "$(stat -c %a '+f+')" = '+q(item['mode'])+' ]']
    return '\n'.join(lines)+'\n'


class CoreTransport:
    """Thin, explicitly selected official ADB subprocess chain. No shell=True."""
    def __init__(self, inputs, output, state):
        self.inputs, self.output, self.state = inputs, output, state
        self.argv = inputs.p['transport']['argv']
        self.selector = inputs.p['transport']['serial']

    def persist(self):
        self.output.write('core-state.json', self.state)

    def call(self, label, args, mutate=False, selector=None, expected=None):
        record = {'operation': label, 'mutation': mutate, 'outcome': 'intent'}
        self.state['events'].append(record)
        self.persist()                 # Intent is durable BEFORE any dispatch.
        try:
            r = subprocess.run(self.argv+['-s', selector or self.selector]+args,
                               capture_output=True, timeout=150, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            record['outcome'] = 'unknown' if mutate else 'unavailable'
            self.persist()
            raise Refusal('ADB outcome unknown; inspect receipt and use verify, never replay') from None
        record.update(outcome='response', exit=r.returncode, stdout_sha256=sha(r.stdout),
                      stderr_sha256=sha(r.stderr), stdout_bytes=len(r.stdout), stderr_bytes=len(r.stderr))
        self.persist()
        need(len(r.stdout) <= 131072 and len(r.stderr) <= 131072, 'bounded ADB response')
        need(r.returncode == 0, 'ADB operation failed; inspect receipt and use verify')
        if expected is not None:
            # Compare only exact text representations; never normalize returned bytes.
            need(r.stdout == expected or
                 (expected.endswith(b'\n') and b'\r' not in expected and
                  r.stdout == expected.replace(b'\n', b'\r\n')),
                 'exact ADB postcondition response missing')
        return r.stdout

    def shell(self, label, body, mutate=False, expected=None, selector=None):
        gate = ('[ "$(id -u)" = 2000 ]\n'
                '[ "$(cat /proc/$$/attr/current)" = u:r:shell:s0 ]\n'
                '[ "$(getenforce)" = Enforcing ]\n'
                '[ "$(getprop ro.serialno)" = '+q(self.inputs.p['serial'])+' ]\n')
        return self.call(label, ['shell', '-T', shell_script(label, gate+body)], mutate, selector, expected)

    def identity(self, selector=None):
        raw = self.call('identity', ['shell', '-T', identity_script()], selector=selector)
        # Do not strip/fix tokens; accept only consistent LF or CRLF field framing.
        parts = raw.split(b'\r\n' if raw.endswith(b'\r\n') else b'\n')
        need(len(parts) == 6 and parts[-1] == b'', 'identity framing')
        need(parts[:4] == [b'2000', b'u:r:shell:s0', b'Enforcing', self.inputs.p['serial'].encode()],
             'UID/context/Enforcing/independent serial identity')
        try:
            abi = parts[4].decode('ascii')
        except UnicodeError:
            raise Refusal('ABI encoding') from None
        need(abi in self.inputs.artifacts, 'no pinned artifact for actual device ABI')
        return abi

    def listener_check(self, fresh=False):
        base = self.inputs.p['base']
        # Fixed listener inspection, not a port scan. Fail if proc visibility is denied.
        port = format(27184, '04X')
        body = ("rows=$(awk '$4 == \"0A\" && $2 ~ /:"+port+"$/ {print $2 \" \" $8 \" \" $10}' /proc/net/tcp)\n"
                "rows6=$(awk '$4 == \"0A\" && $2 ~ /:"+port+"$/ {print $2}' /proc/net/tcp6)\n"
                '[ -z "$rows6" ]\n')
        if fresh:
            body += '[ -z "$rows" ]\nprintf \'NO-LISTENER\\n\'\n'
            self.shell('listener-absent', body, expected=b'NO-LISTENER\n')
            return
        record = q(base+'/v2.child')
        expected_cmd = b'\0'.join(x.encode() for x in
                                 (base+'/private-adbd', '--keys', base+'/authorized_keys',
                                  '--serial', self.inputs.p['serial']))+b'\0'
        body += ('[ ! -L '+record+' ]\n[ -f '+record+' ]\n'
                 '[ "$(stat -c \'%u:%a:%h\' '+record+')" = 2000:600:1 ]\n'
                 'record_hash=$(sha256sum '+record+' | cut -d \' \' -f 1)\n'
                 '[ "$(wc -l <'+record+')" = 1 ]\n'
                 'IFS=\' \' read -r p st boot exe cmd uid ctx extra <'+record+'\n'
                 'case "$p:$st" in *[!0-9:]*|:*|*:) exit 2 ;; esac\n'
                 '[ "$p" -gt 1 ]\n[ -z "$extra" ]\n[ "$uid" = 2000 ]\n[ "$ctx" = u:r:shell:s0 ]\n'
                 '[ "$boot" = "$(cat /proc/sys/kernel/random/boot_id)" ]\n'
                 '[ "$exe" = '+q((base+'/private-adbd').encode().hex())+' ]\n'
                 '[ "$cmd" = '+q(expected_cmd.hex())+' ]\n'
                 'stamp() { IFS= read -r row <"/proc/$p/stat"; rest=${row##*) }; set -- $rest; '
                 '[ "$#" -ge 20 ]; [ "$1" != Z ]; [ "$1" != X ]; shift 19; printf \'%s\' "$1"; }\n'
                 '[ "$(stamp)" = "$st" ]\n'
                 '[ "$(readlink /proc/$p/exe)" = '+q(base+'/private-adbd')+' ]\n'
                 '[ "$(stat -L -c \'%d:%i\' /proc/$p/exe)" = "$(stat -c \'%d:%i\' '+q(base+'/private-adbd')+')" ]\n'
                 '[ "$(sha256sum /proc/$p/exe | cut -d \' \' -f 1)" = '+q(self.state['files']['private-adbd']['sha256'])+' ]\n'
                 '[ "$(od -An -v -tx1 /proc/$p/cmdline | tr -d \' \\n\')" = "$cmd" ]\n'
                 '[ "$(awk \'/^Uid:/ {print $2 \":\" $3 \":\" $4 \":\" $5}\' /proc/$p/status)" = 2000:2000:2000:2000 ]\n'
                 '[ "$(cat /proc/$p/attr/current)" = u:r:shell:s0 ]\n'
                 # Only one IPv4 fixed-port listener, owned by this exact child PID.
                 'case "$rows" in *\'\n\'*) exit 2 ;; esac\n'
                 'IFS=\' \' read -r address listener_uid inode extra <<EOF\n$rows\nEOF\n'
                 '[ "$address" = 0100007F:'+port+' ]\n[ "$listener_uid" = 2000 ]\n[ -z "$extra" ]\n'
                 'case "$inode" in \'\'|*[!0-9]*) exit 2 ;; esac\n'
                 'fds=$(readlink /proc/$p/fd/*)\n'
                 'printf \'%s\\n\' "$fds" | grep -Fx "socket:[$inode]" >/dev/null\n'
                 '[ "$(stamp)" = "$st" ]\n'
                 '[ "$(sha256sum '+record+' | cut -d \' \' -f 1)" = "$record_hash" ]\n'
                 '/system/bin/sh '+q(base+'/service.sh')+' status >/dev/null 2>&1\n'
                 "printf 'BOUND-LISTENER\\n'\n")
        self.shell('listener-bound', body, expected=b'BOUND-LISTENER\n')

    def forward_rows(self):
        raw = self.call('forward-list', ['forward', '--list'])
        try:
            rows = [tuple(line.split()) for line in raw.decode('ascii').splitlines()]
        except UnicodeError:
            raise Refusal('forward list encoding') from None
        # ADB adds one list terminator, even for an empty list. Remove only that
        # exact LF/CRLF blank line; all other empty/noisy rows remain invalid.
        if raw in (b'\n', b'\r\n') or raw.endswith((b'\n\n', b'\r\n\r\n')):
            rows.pop()
        need(all(len(row) == 3 for row in rows), 'forward list schema')
        return rows

    def owns_forward(self, endpoint):
        local = 'tcp:'+endpoint.rsplit(':', 1)[1]
        matching = [row for row in self.forward_rows() if row[1] == local]
        return matching == [(self.selector, local, 'tcp:27184')]

    def acceptance(self):
        before = self.forward_rows()
        raw = self.call('forward-create', ['forward', 'tcp:0', 'tcp:27184'], mutate=True)
        need(re.fullmatch(rb'[1-9][0-9]{0,4}\r?\n', raw), 'allocated forward port framing')
        port = int(raw)
        need(1024 <= port <= 65535 and not any(r[1] == 'tcp:'+str(port) for r in before), 'new ephemeral forward')
        endpoint = '127.0.0.1:'+str(port)
        self.state['forward'] = {'endpoint': endpoint, 'local': 'tcp:'+str(port), 'remote': 'tcp:27184',
                                 'selector': self.selector, 'outcome': 'created'}
        self.persist()
        connected = False
        accepted = False
        try:
            need(self.owns_forward(endpoint), 'forward ownership not exact; left untouched')
            host_record = {'operation': 'host-loopback-check', 'mutation': False, 'outcome': 'intent'}
            self.state['events'].append(host_record)
            self.persist()
            need(loopback_addresses(host_listener_addresses(port)), 'allocated forward is not exclusively host loopback')
            host_record['outcome'] = 'loopback-only'
            self.persist()
            # Refuse an existing ADB transport: never disconnect somebody else's session.
            devices = self.call('devices', ['devices'])
            need(not any(line.split() and line.split()[0] == endpoint.encode()
                         for line in devices.splitlines()[1:]), 'ephemeral endpoint already connected')
            connected = True  # Once dispatched, a lost response is still our connect intent.
            out = self.call('connect', ['connect', endpoint], mutate=True)
            need(out in tuple((prefix+endpoint+newline).encode()
                              for prefix in ('connected to ', 'already connected to ')
                              for newline in ('\n', '\r\n')),
                 'private authentication not confirmed; matching public key must already be loaded in shared ADB server')
            need(self.identity(endpoint) == self.state['abi'], 'private channel ABI changed')
            accepted = True
        finally:
            # An unknown/replaced tuple is NEVER removed or disconnected automatically.
            if self.owns_forward(endpoint):
                if connected:
                    self.call('disconnect', ['disconnect', endpoint], mutate=True)
                    devices = self.call('devices', ['devices'])
                    need(not any(line.split() and line.split()[0] == endpoint.encode()
                                 for line in devices.splitlines()[1:]), 'owned endpoint disconnect readback')
                need(self.owns_forward(endpoint), 'forward changed before removal; left untouched')
                self.call('forward-remove', ['forward', '--remove', 'tcp:'+str(port)], mutate=True)
                need(not any(r[1] == 'tcp:'+str(port) for r in self.forward_rows()), 'forward removal readback')
                self.state['forward']['outcome'] = 'removed'
                self.persist()
            else:
                accepted = False
                self.state['forward']['outcome'] = 'ownership-unknown-left-untouched'
                self.persist()
        need(accepted, 'private authentication/identity/owned cleanup not verified')


def authorized_handoff(path, inputs):
    need(path is not None, 'owner handoff required')
    obj = json_bytes(no_links(path).read_bytes())
    return validate_maintenance(obj, inputs.bindings['profile_sha256'],
                                inputs.bindings['release_sha256'], inputs.p['serial'])


def run(args):
    inputs = CoreInputs(args.profile, args.bundle)
    if args.command == 'plan' or not args.execute:
        need(not args.execute, 'plan does not execute')
        return inputs.plan()
    need(args.output is not None, 'private evidence output required')
    authorized_handoff(args.maintenance, inputs)
    output = PrivateOutput(args.output, create=args.command == 'apply')
    with output.session():
        if args.command == 'apply':
            state = {'schema': 1, 'bindings': inputs.bindings, 'token': uuid.uuid4().hex,
                     'phase': 'preflight', 'events': []}
        else:
            state = json_bytes(output.target('core-state.json').read_bytes())
            need(state.get('schema') == 1 and state.get('bindings') == inputs.bindings and
                 isinstance(state.get('token'), str) and re.fullmatch('[0-9a-f]{32}', state['token']),
                 'existing receipt binding')
            # Never infer/replay a lost mutation, including start or publication.
            need('files' in state and 'abi' in state, 'no deployment manifest to verify')
            need(isinstance(state['abi'], str) and state['files'] == inputs.file_policy(state['abi']),
                 'receipt cannot replace bound payload policy')
            need(type(state.get('events')) is list and all(type(e) is dict for e in state['events']),
                 'receipt event schema')
            if any(e.get('operation') == 'forward-create' for e in state['events']):
                need(type(state.get('forward')) is dict and state['forward'].get('outcome') == 'removed',
                     'previous forward outcome unresolved; owner inspection required before new acceptance')
            state['phase'] = 'verifying'
        remote = CoreTransport(inputs, output, state)
        remote.persist()
        abi = remote.identity()
        base = inputs.p['base']
        token = state['token']
        stage = base+'.bootstrap-'+token
        lock = base+'.bootstrap-lock'
        if args.command == 'apply':
            tools = ('id cat getenforce getprop stat sha256sum cut mkdir chmod mv rmdir rm '
                     'wc od tr readlink awk grep ps sleep date toybox').split()
            body = '\n'.join('command -v '+tool+' >/dev/null' for tool in tools)+'\n'
            body += 'toybox flock --help >/dev/null 2>&1\ntoybox setsid --help >/dev/null 2>&1\n'
            body += fresh_checks(base)+"printf 'FRESH\\n'\n"
            remote.shell('preflight', body, expected=b'FRESH\n')
            remote.listener_check(fresh=True)
            inputs.unchanged()
            authorized_handoff(args.maintenance, inputs)
            state['abi'] = abi
            payload = inputs.payload(abi)
            state['files'] = inputs.file_policy(abi)
            state['phase'] = 'reserving'
            body = fresh_checks(base)
            body += '[ ! -e '+q(lock)+' ]\n[ ! -L '+q(lock)+' ]\n'
            body += '[ ! -e '+q(stage)+' ]\n[ ! -L '+q(stage)+' ]\n'
            # Exclusive mkdir, no -p; unknown outcome leaves the owned footprint.
            for path in (lock, stage):
                body += 'mkdir -m 700 '+q(path)+'\n'
                body += "(set -C; printf '%s\\n' "+q(token)+' >'+q(path+'/.core-bootstrap')+')\n'
                body += owned_directory(path, token)
            body += "printf 'RESERVED\\n'\n"
            remote.shell('reserve', body, True, b'RESERVED\n')
            state['phase'] = 'pushing'
            for name, (data, _mode) in payload.items():
                authorized_handoff(args.maintenance, inputs)
                # Check the token-owned namespace and refuse any pre-existing push target.
                guard = owned_directory(lock, token)+owned_directory(stage, token)
                guard += '[ ! -e '+q(stage+'/'+name)+' ]\n[ ! -L '+q(stage+'/'+name)+' ]\n'
                remote.shell('push-target', guard+"printf 'PUSH-TARGET\\n'\n", expected=b'PUSH-TARGET\n')
                snapshot = 'payload-'+name.replace('_', '-')
                output.raw(snapshot, data)
                remote.call('push-'+name, ['push', '-Z', str(output.target(snapshot)), stage+'/'+name], True)
            body = owned_directory(lock, token)+owned_directory(stage, token)
            body += file_checks(stage, state['files'], False, exact=True)
            for name, item in state['files'].items():
                body += 'chmod '+item['mode']+' '+q(stage+'/'+name)+'\n'
            body += file_checks(stage, state['files'], True, exact=True)+"printf 'SEALED\\n'\n"
            remote.shell('seal', body, True, b'SEALED\n')
            inputs.unchanged()
            authorized_handoff(args.maintenance, inputs)
            state['phase'] = 'publishing'
            body = owned_directory(lock, token)+owned_directory(stage, token)
            body += file_checks(stage, state['files'], True, exact=True)+fresh_checks(base)
            body += 'if [ -e '+q(base)+' ]; then rmdir '+q(base)+'; fi\n'
            # -n prevents clobber; -T prevents accidental directory nesting.
            body += 'mv -n -T '+q(stage)+' '+q(base)+'\n'
            body += owned_directory(base, token)+file_checks(base, state['files'], True, exact=True)
            body += '[ ! -e '+q(stage)+' ]\n[ ! -L '+q(stage)+' ]\n'
            body += "printf 'PUBLISHED\\n'\n"
            remote.shell('publish', body, True, b'PUBLISHED\n')
        need(state['abi'] == abi, 'receipt ABI identity')
        files_body = owned_directory(base, token)+file_checks(base, state['files'], True)
        remote.shell('files', files_body+"printf 'FILES\\n'\n", expected=b'FILES\n')
        if args.command == 'apply':
            state['phase'] = 'starting'
            authorized_handoff(args.maintenance, inputs)
            remote.shell('start', files_body+'/system/bin/sh '+q(base+'/service.sh')+' start >/dev/null 2>&1\n'+
                         "printf 'STARTED\\n'\n", True, b'STARTED\n')
        state['phase'] = 'authentication-unverified'
        remote.persist()
        remote.listener_check()
        remote.acceptance()
        remote.listener_check()
        # Acceptance is independent of launch exit/listener existence. Never stop it.
        remote.shell('files', files_body+"printf 'FILES\\n'\n", expected=b'FILES\n')
        # Verify may finish exact token-owned cleanup, but never repeats deployment/start.
        body = '[ ! -e '+q(stage)+' ]\n[ ! -L '+q(stage)+' ]\n'
        body += 'if [ -e '+q(lock)+' ] || [ -L '+q(lock)+' ]; then\n'
        body += owned_directory(lock, token)
        body += 'count=0\nfor f in '+q(lock)+'/* '+q(lock)+'/.[!.]* '+q(lock)+'/..?*; do\n'
        body += ' if [ -e "$f" ] || [ -L "$f" ]; then count=$((count+1)); fi\ndone\n[ "$count" = 1 ]\n'
        body += 'rm '+q(lock+'/.core-bootstrap')+'\nrmdir '+q(lock)+'\nfi\n'
        body += '[ ! -e '+q(lock)+' ]\n[ ! -L '+q(lock)+' ]\n'
        body += "printf 'CLEAN\\n'\n"
        remote.shell('cleanup', body, True, b'CLEAN\n')
        state['phase'] = 'ready'
        remote.persist()
        return {'schema': 1, 'ready': True, 'authentication': 'allowlisted-private-channel-identity-verified',
                'fresh_only': True, 'abi': abi, 'bindings': inputs.bindings,
                'device_acceptance': 'executed-on-explicit-selected-ADB-not-an-OEM-certification'}


def main():
    try:
        result = run(parser().parse_args())
        print(json.dumps(result, sort_keys=True))
        return 0
    except Refusal as exc:
        print('core bootstrap refused; no readiness claim: '+str(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, struct.error):
        print('core bootstrap refused; no readiness claim', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

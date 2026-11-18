"""Fixed, read-only capability discovery; not provisioning or upgrade authority."""
from __future__ import annotations

import re
import subprocess

from common import Refusal, need
from private_output import PrivateOutput

IDENTITY = '''set -eu
getprop ro.serialno
id -u
id -Z
getenforce
cat /proc/sys/kernel/random/boot_id
getprop ro.build.version.sdk
getprop ro.product.cpu.abilist
getprop ro.product.cpu.abi
am get-current-user
getconf PAGE_SIZE'''
TOOLS = '''set -eu
for tool in sh getprop id getenforce cat am pm dumpsys run-as stat sha256sum readlink base64 cut grep flock getconf; do
  value=$(command -v "$tool" || :)
  printf '%s=%s\\n' "$tool" "$value"
done'''
PACKAGES = '''set -eu
set -o pipefail
pm list packages -U --user 0 com.termux | {
  LC_ALL=C grep -a -E -v '^package:com[.]termux[.][A-Za-z_][A-Za-z0-9_]*([.][A-Za-z_][A-Za-z0-9_]*)* uid:1[0-9]{4}$' || [ "$?" = 1 ]
}'''
METADATA = '''set -eu
set -o pipefail
dumpsys package com.termux | LC_ALL=C grep -a -E '^[[:space:]]*(versionCode=|userId=|appId=|flags=|pkgFlags=)|[^[:print:][:space:]]'
pm path --user 0 com.termux'''
# Keep the shell as the transport's child across the UID transition. Preserve
# run-as failure exactly; a matching UID printed with nonzero exit is not proof.
RUN_AS = 'run-as com.termux id -u; result=$?; exit "$result"'
SCRIPTS = frozenset((IDENTITY, TOOLS, PACKAGES, METADATA, RUN_AS))
TOOL_NAMES = 'sh getprop id getenforce cat am pm dumpsys run-as stat sha256sum readlink base64 cut grep flock getconf'.split()
GOARCH = {'arm64-v8a': 'arm64', 'armeabi-v7a': 'arm', 'x86': '386', 'x86_64': 'amd64'}


def validate_transport(t):
    need(type(t) is dict and {'kind', 'argv'} <= set(t) <= {'kind', 'argv', 'serial'}, 'transport fields')
    need(t['kind'] in ('controller', 'adb'), 'transport kind')
    need(type(t['argv']) is list and 1 <= len(t['argv']) <= 16 and
         all(isinstance(x, str) and x and not any(c in x for c in '\r\n\x00') for x in t['argv']),
         'transport argv')
    if t['kind'] == 'adb':
        need(set(t) == {'kind', 'argv', 'serial'} and len(t['argv']) == 1, 'explicit adb selector')
        need(isinstance(t['serial'], str) and re.fullmatch(r'[A-Za-z0-9_.:\[\]-]{1,200}', t['serial']),
             'transport serial')
    else:
        need(set(t) == {'kind', 'argv'}, 'controller selector')
    return t


def serial(value):
    need(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', value), 'serial')
    return value


def lines(data):
    need(type(data) is bytes and len(data) <= 65536 and b'\x00' not in data, 'probe output size/NUL')
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        raise Refusal('probe output encoding') from None
    text = text.replace('\r\n', '\n')
    need('\r' not in text and not any(ord(c) < 32 and c not in '\n\t' for c in text), 'probe output controls')
    # Only the final line terminator is optional. Never trim identity tokens.
    return (text[:-1] if text.endswith('\n') else text).split('\n') if text else []


class ProbeTransport:
    def __init__(self, transport, out):
        self.transport = validate_transport(transport)
        self.out = out
        self.calls = 0

    def read(self, code, allow_failure=False):
        need(code in SCRIPTS, 'probe fixed read allowlist')
        t = self.transport
        command = (t['argv'] + ['-s', t['serial'], 'shell', '-T', code] if t['kind'] == 'adb'
                   else t['argv'] + ['shell', code])
        self.calls += 1
        try:
            r = subprocess.run(command, input=None, capture_output=True, timeout=15, shell=False)
        except subprocess.TimeoutExpired as exc:
            self.out.event('identity', 'timeout-unconfirmed', exc.stdout or b'', exc.stderr or b'')
            raise Refusal('probe transport timeout') from None
        except OSError:
            self.out.event('identity', 'unavailable', b'', b'')
            raise Refusal('probe transport unavailable') from None
        self.out.event('identity' if code == IDENTITY else 'package' if code in (PACKAGES, METADATA, RUN_AS) else 'metadata',
                       r.returncode, r.stdout, r.stderr)
        parsed = lines(r.stdout)
        errors = lines(r.stderr)
        need(allow_failure or (r.returncode == 0 and not errors), 'probe read failed or ambiguous stderr')
        return r.returncode, parsed, errors


def identity(values, expected):
    need(len(values) == 10, 'probe identity field count')
    observed, uid, context, selinux, boot, sdk, abilist, primary, user, page_size = values
    serial(observed)
    need(expected is None or observed == expected, 'probe expected serial')
    need((uid, context, selinux) == ('2000', 'u:r:shell:s0', 'Enforcing'), 'probe shell identity/SELinux')
    need(re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', boot), 'probe boot ID')
    need(re.fullmatch(r'[1-9][0-9]{0,2}', sdk), 'probe Android SDK')
    need(re.fullmatch(r'0|[1-9][0-9]{0,4}', user), 'probe Android user')
    need(page_size in ('4096', '16384', '65536'), 'probe kernel page-size observation')
    abis = abilist.split(',')
    need(abis and len(abis) <= 16 and len(set(abis)) == len(abis) and
         all(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', a) for a in abis) and primary in abis,
         'probe ABI declarations')
    return {'serial': observed, 'shell_uid': 2000, 'shell_context': context, 'selinux': selinux,
            'boot_id': boot, 'android_sdk': int(sdk), 'cpu_abis': abis, 'primary_abi': primary,
            'current_user': int(user), 'page_size': int(page_size)}


def tools(values):
    need(len(values) == len(TOOL_NAMES), 'probe command capability count')
    result = {}
    for name, line in zip(TOOL_NAMES, values):
        key, sep, path = line.partition('=')
        need(key == name and sep == '=' and (not path or re.fullmatch(r'/[A-Za-z0-9_./+-]+', path)),
             'probe command capability')
        need(not path or '..' not in path.split('/'), 'probe command path')
        result[name] = {'available': bool(path), 'path': path or None}
    return result


def package_inventory(values):
    if not values:
        return {'package': 'com.termux', 'queried_user': 0, 'installed': False}
    uids = []
    for value in values:
        found = re.fullmatch(r'package:com\.termux uid:([1-9][0-9]{4,9})', value)
        need(found is not None, 'probe package inventory')
        uids.append(int(found[1]))
    need(len(set(uids)) == 1 and 10000 <= uids[0] <= 19999, 'probe primary-user app UID')
    return {'package': 'com.termux', 'queried_user': 0, 'installed': True, 'uid': uids[0]}


def package_metadata(values, package):
    uids, versions, flags, paths = [], [], [], []
    for value in values:
        uid = re.fullmatch(r'[ \t]*(?:userId|appId)=([1-9][0-9]*)', value)
        version = re.fullmatch(r'[ \t]*versionCode=([1-9][0-9]*)(?: [A-Za-z0-9_.= -]*)?', value)
        flag = re.fullmatch(r'[ \t]*(?:flags|pkgFlags)=\[([ A-Z0-9_]*)\]', value)
        path = re.fullmatch(r'package:(/data/app/[A-Za-z0-9_./=+~-]+\.apk)', value)
        if uid: uids.append(int(uid[1]))
        elif version: versions.append(int(version[1]))
        elif flag: flags.append('DEBUGGABLE' in flag[1].split())
        # The contextless dumpsys filter also sees zero-valued flags in other
        # sections on Android 15. This exact observation is not package flag
        # evidence: canonical flags/pkgFlags lists remain mandatory below.
        elif re.fullmatch(r'[ \t]*flags=0x0', value): continue
        elif path:
            need('..' not in path[1].split('/') and '//' not in path[1], 'probe APK path')
            paths.append(path[1])
        else: raise Refusal('probe package metadata line')
    need(set(uids) == {package['uid']} and len(versions) == 1 and 0 < versions[0] < 2**31 and
         flags and len(set(flags)) == 1 and paths and len(set(paths)) == len(paths),
         'probe package metadata identity')
    package.update(version=versions[0], debuggable=flags[0], paths=paths, split=len(paths) != 1)


def probe(transport, output, expected_serial=None):
    validate_transport(transport)
    if expected_serial is not None: serial(expected_serial)
    out = PrivateOutput(output, create=True)
    remote = ProbeTransport(transport, out)
    device = identity(remote.read(IDENTITY)[1], expected_serial)
    commands = tools(remote.read(TOOLS)[1])
    unsupported = ['command-missing:' + name for name in TOOL_NAMES if not commands[name]['available']]
    if device['page_size'] != 4096:
        unsupported.append('termux-apk-page-size:requires-4096:observed-' + str(device['page_size']))
    if device['current_user'] != 0: unsupported.append('non-primary-current-user:fixed-termux-prefix')
    goarch = GOARCH.get(device['primary_abi'])
    if goarch is None: unsupported.append('unknown-primary-abi')
    if commands['pm']['available'] and commands['grep']['available']:
        package = package_inventory(remote.read(PACKAGES)[1])
        if not package['installed']:
            unsupported.append('termux-not-installed')
        elif commands['dumpsys']['available'] and commands['grep']['available']:
            package_metadata(remote.read(METADATA)[1], package)
            if not package['debuggable']: unsupported.append('termux-not-debuggable')
            if package['split']: unsupported.append('termux-split-apk')
            if commands['run-as']['available'] and device['current_user'] == 0:
                code, values, errors = remote.read(RUN_AS, allow_failure=True)
                if code == 0:
                    need(not errors and values == [str(package['uid'])] and package['debuggable'],
                         'probe run-as UID/debuggable conflict')
                    package['run_as'] = 'available'
                else:
                    need(code == 1 and not values and len(errors) == 1 and errors[0].startswith('run-as: '),
                         'probe unrecognized run-as failure')
                    package['run_as'] = 'denied'
                    unsupported.append('termux-run-as-denied')
            else: package['run_as'] = 'not-probed'
        else: package['run_as'] = 'not-probed'
    else:
        package = {'package': 'com.termux', 'queried_user': 0, 'installed': None, 'run_as': 'not-probed'}
    device['termux'] = package
    device['transport'] = transport
    capability = {'schema': 1, 'read_only': True, 'device_calls': remote.calls,
                  'compatibility_verified': False, 'commands': commands,
                  'selection': {'goarch': goarch, 'android_sdk': device['android_sdk']},
                  'unsupported': unsupported,
                  'not_verified': ['release-signature-and-manifest', 'existing-runtime', 'maintenance-authorization',
                                   'android-oem-abi-compatibility', 'initial-provisioning']}
    out.write('device.json', {'schema': 1, **device})
    out.write('capability.json', capability)
    out.verify()
    return {'result': 'probed', 'read_only': True, 'device_calls': remote.calls,
            'evidence_private': True, 'unsupported_count': len(unsupported), 'compatibility_verified': False}

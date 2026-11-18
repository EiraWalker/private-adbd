"""Explicit-execute, same-UID maintenance lifecycle IPC (NOT read-only status).

The caller owns durable intent/checkpoint publication. Never use this module from
probe/inspect/verify or regard a successful transport as an active lease.
"""
from __future__ import annotations

import copy
from decimal import Decimal
import json
import math
import re
import secrets
import shlex
import time

from common import Refusal, need, sha


def _integer(value, low=1, high=(1 << 63)-1):
    return type(value) is int and low <= value <= high


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _request(obj):
    need(type(obj) is dict and set(obj) == REQUEST_FIELDS, 'maintenance request fields')
    need(type(obj['version']) is int and obj['version'] == 1, 'maintenance version')
    for key in ('token', 'profileSha256', 'releaseSha256'):
        need(type(obj[key]) is str and re.fullmatch(HEX, obj[key]) is not None,
             'maintenance digest/token format')
    need(type(obj['boot']) is str and re.fullmatch(BOOT, obj['boot']) is not None,
         'maintenance boot format')
    need(all(_integer(obj[k]) for k in ('deadlineElapsedMs', 'baselineVersion', 'targetVersion'))
         and obj['targetVersion'] >= obj['baselineVersion'], 'maintenance integer/version range')
    return obj


def _control(obj):
    need(type(obj) is dict and set(obj) == {'flags', 'lease_sha256', 'boot'} and
         type(obj['flags']) is dict and
         obj['flags'] == {'userStopped': 'false', 'safetyPaused': 'false'} and
         type(obj['lease_sha256']) is str and re.fullmatch(HEX, obj['lease_sha256']) and
         type(obj['boot']) is str and re.fullmatch(BOOT, obj['boot']),
         'maintenance Stop/safety/lease/boot control')
    return obj


def _decode(raw):
    need(type(raw) is bytes and len(raw) <= 2048, 'maintenance response size/type')
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            need(key not in obj, 'maintenance duplicate response field')
            obj[key] = value
        return obj
    def invalid(_):
        raise Refusal('maintenance response number type')
    def integer(text):
        value = int(text)
        need(-(1 << 63) <= value <= MAX_INT, 'maintenance response integer range')
        return value
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_int=integer, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('maintenance response encoding/schema') from None


class MaintenanceUncertain(Refusal):
    """A lifecycle IPC has no usable outcome; never a read-only retry signal."""


class MaintenanceUnsupported(Refusal):
    """No verified same-UID CLI path; no privilege/bootstrap fallback."""


class MaintenanceRejected(Refusal):
    """Credential-free terminal phase for explicit parent reconciliation only.

    bound means all ten fields/owner matched, not permission for any mutation.
    """
    def __init__(self, phase, *, bound):
        super().__init__('maintenance coordinator terminal phase')
        self.phase = phase
        self.bound = bound


NEGATIVE_PHASES = frozenset(('revoked', 'expired', 'version_mismatch', 'not_owner', 'busy',
    'payload_mismatch', 'token_reused', 'capacity', 'store_error',
    'expired_or_invalid_deadline', 'blocked_unknown_dispatch', 'cleanup_pending', 'released'))

CLASS = 'com.termux.app.privateadb.MaintenanceCli'
MAX_MS = 600000
MAX_INT = (1 << 63) - 1
HEX = r'[0-9a-f]{64}'
BOOT = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
REQUEST_FIELDS = frozenset(('version', 'token', 'boot', 'deadlineElapsedMs',
                            'profileSha256', 'releaseSha256', 'baselineVersion', 'targetVersion'))


class MaintenanceClient:
    """Construct with real AndroidRemote/Inputs and Authorization public seams.

    prepare() returns private checkpoint material; persist it AND the request
    intent before request_once(). This client does not pretend to persist them.
    """
    def __init__(self, remote, authorization, *, checkpoint=None):
        self.r = remote
        self.i = remote.inputs
        self.auth = authorization
        self._pinned = _canonical([self.i.p, self.i.r, self.i.bindings])
        self._record = copy.deepcopy(checkpoint)
        self._restored = checkpoint is not None
        self.request_attempted = checkpoint is not None  # Resume is status-only, never re-request.
        self.release_attempted = False
        self._release_reconciliation_attempted = False
        if checkpoint is not None:
            self._record_valid()

    def _record_valid(self):
        need(type(self._record) is dict and set(self._record) == {'request', 'control'},
             'maintenance checkpoint fields')
        req = _request(self._record['request'])
        control = _control(self._record['control'])
        need(req['profileSha256'] == self.i.bindings['profile_sha256'] and
             req['releaseSha256'] == self.i.bindings['release_sha256'] and
             req['targetVersion'] == self.i.r['version'] and
             req['baselineVersion'] in [b['version'] for b in self.i.r['baselines']]+[self.i.r['version']]
             and req['boot'] == control['boot'], 'maintenance checkpoint input binding')

    def checkpoint(self):
        """Private defensive-copy data only; does not persist or authorize an IPC."""
        need(self._record is not None, 'maintenance preparation required')
        self._record_valid()
        return copy.deepcopy(self._record)

    def _authority(self):
        need(self.r.t.execute is True, 'maintenance requires explicit execute')
        need(self.auth.inputs is self.i and self.r.inputs is self.i,
             'maintenance authorization inputs')
        self.auth.check()
        self.i.unchanged()
        need(_canonical([self.i.p, self.i.r, self.i.bindings]) == self._pinned and
             _canonical(self.r.p) == _canonical(self.i.p) and
             _canonical(self.r.t.p) == _canonical(self.i.p) and
             sha(self.i.profile_bytes) == self.i.bindings['profile_sha256'] and
             sha(self.i.release_bytes) == self.i.bindings['release_sha256'],
             'maintenance in-memory inputs/transport changed')
        if self._record is not None:
            self._record_valid()

    def _package(self):
        pkg = self.r.package()
        approved = [(b['version'], b['sha256']) for b in self.i.r['baselines']]
        approved.append((self.i.r['version'], self.i.r['sha256']))
        need(type(pkg) is dict and set(pkg) == {'uid', 'version', 'sha256', 'path'} and
             type(pkg['uid']) is int and pkg['uid'] == self.i.p['app_uid'] and
             _integer(pkg['version']) and type(pkg['sha256']) is str and
             (pkg['version'], pkg['sha256']) in approved, 'maintenance installed APK binding')
        need(isinstance(pkg['path'], str) and
             re.fullmatch(r'/data/app/[A-Za-z0-9_./=+~-]+/base\.apk', pkg['path']) and
             all(part not in ('', '.', '..') for part in pkg['path'].split('/')[1:]),
             'maintenance installed APK path')
        return pkg

    def _clock(self):
        start = time.monotonic()
        raw = self.r.t.shell('set -eu; cat /proc/sys/kernel/random/boot_id; '
                             'cat /proc/uptime; cat /proc/sys/kernel/random/boot_id',
                             'clock', timeout=5)
        try:
            # Metadata record terminators may be LF or CRLF. Do not trim boot
            # or uptime tokens, accept bare CR, or normalize binary payloads.
            text = raw.decode('ascii').replace('\r\n', '\n')
            need('\r' not in text and text.count('\n') == 3 and text.endswith('\n'),
                 'maintenance clock LF/CRLF framing')
            boot, uptime, again, tail = text.split('\n')
            need(tail == '', 'maintenance clock framing')
            need(re.fullmatch(BOOT, boot) is not None and boot == again,
                 'maintenance device boot')
            need(re.fullmatch(r'[0-9]{1,16}\.[0-9]{2} [0-9]{1,20}\.[0-9]{2}', uptime) is not None,
                 'maintenance device uptime')
            now = int(Decimal(uptime.split(' ')[0])*1000)
            need(0 <= now <= MAX_INT, 'maintenance device uptime range')
        except (ValueError, UnicodeError):
            raise Refusal('maintenance device clock schema') from None
        return boot, now, start

    def _release_authority(self, checkpoint_hash):
        # This is a terminal journal observation, never an active-lease bypass.
        from upgrade import Authorization
        from installer import json_bytes
        from private_output import PrivateOutput
        need(type(checkpoint_hash) is str and re.fullmatch(HEX, checkpoint_hash) is not None,
             'maintenance release checkpoint hash')
        need(self._restored and isinstance(self.auth, Authorization) and
             self.auth.checkpoint_hash == checkpoint_hash,
             'maintenance release requires checkpoint-bound resume authorization')
        self._authority()
        out = getattr(self.i, 'out', None)
        need(isinstance(out, PrivateOutput), 'maintenance release private checkpoint required')
        out.verify()
        raw = out.target('checkpoint.json').read_bytes()
        need(sha(raw) == checkpoint_hash, 'maintenance release checkpoint changed')
        cp = json_bytes(raw)
        need(type(cp) is dict and cp.get('intent') == 'maintenance-release' and
             cp.get('phase') == 'maintenance-release' and
             _canonical(cp.get('maintenance')) == _canonical(self._record),
             'maintenance release original intent/record binding')
        # Private ACL/checkpoint reads can be slow; authority must still be
        # fresh after them, immediately before the fixed terminal IPC/acceptance.
        self._authority()

    def _preflight(self, minimum_remaining_ms=1, *, _terminal_release_hash=None):
        self._authority()
        if _terminal_release_hash is not None:
            self._release_authority(_terminal_release_hash)
        need(_integer(minimum_remaining_ms, high=MAX_MS), 'maintenance minimum operation budget')
        pkg = self._package()
        if _terminal_release_hash is not None:
            need((pkg['version'], pkg['sha256']) == (self.i.r['version'], self.i.r['sha256']),
                 'maintenance release requires exact target APK')
        control = _control(self.r.late_control())
        boot, now, start = self._clock()
        need(_control(self.r.late_control()) == control, 'maintenance late control changed')
        self._authority()
        if self._record is not None:
            req = self._record['request']
            need(control == self._record['control'] and boot == req['boot'],
                 'maintenance Stop/lease/boot changed')
            need(pkg['version'] in (req['baselineVersion'], req['targetVersion']),
                 'maintenance installed version changed')
            # /proc/uptime truncates to centiseconds. Subtract the whole host
            # round-trip and late checks plus its ten-ms quantization uncertainty.
            remaining = req['deadlineElapsedMs'] - now - 10 - (time.monotonic()-start)*1000
            if _terminal_release_hash is None:
                need(remaining >= minimum_remaining_ms, 'maintenance remaining deadline budget')
        else:
            need(control['boot'] == boot, 'maintenance control boot')
            remaining = MAX_MS
        return pkg, control, boot, now, remaining

    def prepare(self, ttl_ms=MAX_MS):
        self._authority()
        need(self._record is None, 'maintenance already prepared')
        need(type(ttl_ms) is int and 1 <= ttl_ms <= MAX_MS, 'maintenance TTL')
        pkg, control, boot, now, _ = self._preflight()
        req = {'version': 1, 'token': secrets.token_hex(32), 'boot': boot,
               'deadlineElapsedMs': now+ttl_ms,
               'profileSha256': self.i.bindings['profile_sha256'],
               'releaseSha256': self.i.bindings['release_sha256'],
               'baselineVersion': pkg['version'], 'targetVersion': self.i.r['version']}
        self._record = {'request': _request(req), 'control': copy.deepcopy(control)}
        self._record_valid()
        return self.checkpoint()

    def _reply(self, raw, verb):
        reply = _decode(raw)
        need(type(reply) is dict and type(reply.get('version')) is int and
             reply['version'] == 1, 'maintenance response version')
        if set(reply) == {'version', 'error'}:
            if reply['error'] == 'unsupported':
                raise MaintenanceUnsupported('maintenance unsupported; no fallback')
            raise Refusal('maintenance CLI rejected or failed')
        if set(reply) == {'version', 'phase'}:
            need(type(reply['phase']) is str and reply['phase'] in NEGATIVE_PHASES,
                 'maintenance coordinator negative/unknown phase')
            raise MaintenanceRejected(reply['phase'], bound=False)
        need(set(reply) == REQUEST_FIELDS | {'phase', 'ownerUid'}, 'maintenance response fields')
        request = _request({k: reply[k] for k in REQUEST_FIELDS})
        need(request == self._record['request'] and type(reply['ownerUid']) is int and
             reply['ownerUid'] == self.i.p['app_uid'], 'maintenance response binding/owner')
        need(type(reply['phase']) is str, 'maintenance response phase type')
        if reply['phase'] in NEGATIVE_PHASES and not (verb == 'release' and reply['phase'] == 'released'):
            raise MaintenanceRejected(reply['phase'], bound=True)
        need(reply['phase'] in (('released',) if verb == 'release' else ('pending', 'active')),
             'maintenance coordinator negative/unknown phase')
        return reply

    def _script(self, pkg, verb):
        # Use the observed AND hash-approved installed APK, not a helper path or
        # arbitrary new APK. Shell errors are fixed envelopes, never diagnostics.
        q = shlex.quote
        return f'''set -u
unsupported() {{ printf '%s\\n' '{{"version":1,"error":"unsupported"}}'; exit 0; }}
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
[ "$(id -u)" = {self.i.p['app_uid']} ] || unsupported
[ -x /system/bin/app_process ] || unsupported
current=$(/system/bin/pm path com.termux 2>/dev/null) || unsupported
[ "$current" = {q('package:'+pkg['path'])} ] || unsupported
[ ! -L {q(pkg['path'])} ] && [ -f {q(pkg['path'])} ] && [ -r {q(pkg['path'])} ] || unsupported
actual=$(sha256sum {q(pkg['path'])} 2>/dev/null) || unsupported
[ "$actual" = {q(pkg['sha256']+'  '+pkg['path'])} ] || unsupported
result=$(CLASSPATH={q(pkg['path'])} /system/bin/app_process /system/bin {CLASS} {verb} 2>/dev/null)
code=$?
case "$code" in
  0) [ -n "$result" ] || unsupported; printf '%s\\n' "$result" ;;
  2) printf '%s\\n' '{{"version":1,"error":"invalid_request"}}' ;;
  3) unsupported ;;
  *) if [ "$code" = 1 ] && [ "$result" = '{{"version":1,"error":"failed"}}' ]; then
       printf '%s\\n' '{{"version":1,"error":"failed"}}'
     else unsupported; fi ;;
esac
'''

    def _dispatch(self, verb, minimum_remaining_ms=1, *, until=None):
        need(self._record is not None, 'maintenance preparation required')
        started = time.monotonic()
        pkg, _, _, _, remaining = self._preflight(minimum_remaining_ms)
        req = self._record['request']
        payload = req if verb == 'request' else {'version': 1, 'token': req['token']}
        data = (json.dumps(payload, separators=(',', ':'))+'\n').encode('ascii')
        need(len(data) <= 2048, 'maintenance payload size')
        if verb == 'request':
            need(pkg['version'] == req['baselineVersion'], 'maintenance request baseline changed')
        script = self._script(pkg, verb)
        # A fixed lifecycle IPC, intentionally NOT generic mutating=True: doing
        # so would re-enter Engine.guard -> assert_active -> Engine.guard.
        # No transport guard is removed or monkeypatched. Recheck original host
        # bytes immediately before dispatch after all potentially slow reads.
        self._authority()
        now = time.monotonic()
        elapsed = now-started
        need(math.isfinite(elapsed) and elapsed >= 0, 'maintenance host elapsed clock')
        # Anchor before preflight, never pair its stale remaining with a later
        # fresh start. Conservatively charge preflight again, including the
        # clock round-trip already deducted there; neither deadline is renewed.
        remaining -= elapsed*1000
        need(remaining >= minimum_remaining_ms, 'maintenance remaining deadline budget')
        timeout = min(5, remaining/1000)
        if until is not None:
            need(math.isfinite(until), 'maintenance polling deadline')
            timeout = min(timeout, until-now)
        need(timeout > 0, 'maintenance polling budget exhausted')
        try:
            raw = self.r.t.app(script, 'control', data=data,
                               mutating=False, timeout=timeout)
        except Exception:
            raise MaintenanceUncertain('maintenance outcome unknown; explicit reconciliation required') from None
        self._authority()
        reply = self._reply(raw, verb)
        after, _, _, _, _ = self._preflight(minimum_remaining_ms)
        need(after == pkg, 'maintenance APK changed across acknowledgement')
        if until is not None:
            need(time.monotonic() < until, 'maintenance polling budget exhausted')
        return reply

    def request_once(self):
        self._authority()
        need(not self.request_attempted, 'maintenance request cannot be replayed')
        self.request_attempted = True
        return self._dispatch('request')

    def status(self):
        return self._dispatch('status')

    def reconcile_release(self, *, checkpoint_hash):
        """One terminal-only status for an original uncertain release intent.

        A fresh real checkpoint-bound handoff and exact target are mandatory.
        Only full bound released is returned, even beyond the original deadline.
        This is lifecycle IPC, not a probe, renewal or mutation authorization.
        """
        self._release_authority(checkpoint_hash)
        need(not self._release_reconciliation_attempted, 'maintenance release reconciliation is one-shot')
        self._release_reconciliation_attempted = True
        self.release_attempted = True  # A terminal observation can never enable release replay.
        pkg, _, _, _, _ = self._preflight(_terminal_release_hash=checkpoint_hash)
        req = self._record['request']
        data = (json.dumps({'version': 1, 'token': req['token']}, separators=(',', ':'))+'\n').encode('ascii')
        self._release_authority(checkpoint_hash)
        try:
            raw = self.r.t.app(self._script(pkg, 'status'), 'control', data=data,
                               mutating=False, timeout=5)
        except Exception:
            raise MaintenanceUncertain('maintenance release outcome unknown; explicit reconciliation required') from None
        self._release_authority(checkpoint_hash)
        # Reuse only the strict ten-field released parser, not status acceptance.
        reply = self._reply(raw, 'release')
        after, _, _, _, _ = self._preflight(_terminal_release_hash=checkpoint_hash)
        need(after == pkg, 'maintenance APK changed across terminal release observation')
        self._release_authority(checkpoint_hash)
        return reply

    def wait_active(self, *, max_attempts=3, poll_ms=250, timeout_ms=10000):
        """Poll ONLY valid pending; every other failure is terminal.

        Existing late_control has its own finite transport timeouts. The local
        polling deadline forbids further IPC/acceptance after it, but cannot
        interrupt that compound preflight; this is not a hard wall-time SLA.
        """
        self._authority()
        need(_integer(max_attempts, high=16) and _integer(poll_ms, high=1000) and
             _integer(timeout_ms, high=MAX_MS), 'maintenance polling bounds')
        until = time.monotonic()+timeout_ms/1000
        for attempt in range(max_attempts):
            need(time.monotonic() < until, 'maintenance polling budget exhausted')
            reply = self._dispatch('status', until=until)
            if reply['phase'] == 'active': return reply
            if attempt+1 < max_attempts:
                time.sleep(min(poll_ms/1000, max(0, until-time.monotonic())))
        raise Refusal('maintenance pending; explicit reconciliation required')

    def assert_active(self, minimum_remaining_ms=30000):
        reply = self._dispatch('status', minimum_remaining_ms)
        need(reply['phase'] == 'active', 'maintenance fresh active acknowledgement required')
        return reply

    def release_once(self):
        self._authority()
        need(not self.release_attempted, 'maintenance release cannot be replayed')
        self.release_attempted = True
        return self._dispatch('release')

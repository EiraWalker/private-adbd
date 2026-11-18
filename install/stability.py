"""Read-only, bounded sampled runtime stability; never adopts a new epoch."""
from __future__ import annotations

import json
import math
import time

from common import Refusal, need, sha


LATE_CONTROL_FIELDS = ('flags', 'lease_sha256', 'boot')
FOREGROUND_COMMAND = 'dumpsys activity services com.termux/.app.privateadb.PrivateAdbService'


def canonical(value):
    """JSON encoding preserves bool/number distinctions and array order."""
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError):
        raise Refusal('stability observation JSON schema') from None


def guardian_foreground(remote):
    raw = remote.t.shell(FOREGROUND_COMMAND, 'process')
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise Refusal('foreground service observation encoding') from None
    records = text.split('* ServiceRecord')
    expected = 'com.termux/.app.privateadb.PrivateAdbService'
    matches = [record for record in records if record.splitlines()
               and expected in record.splitlines()[0]]
    need(len(matches) == 1 and 'isForeground=true' in matches[0],
         'guardian is not an unambiguous foreground service')


def verify_stability(remote, inputs, out, *, stable_seconds=120,
                     interval_seconds=15, minimum_samples=3,
                     clock=time.monotonic, sleep=time.sleep):
    """Require unchanged validated snapshots over an actual measured interval.

    AndroidRemote supplies device validation, including fresh health and UID/
    SELinux/file/key/listener checks. Test substitutes are explicitly synthetic.
    Only health_uptime is excluded from equality; it must actually advance.
    Every iteration ends with a fresh late-control projection, not equality of
    deliberately different snapshot-control and late-control schemas.
    """
    need(type(stable_seconds) in (int, float) and math.isfinite(stable_seconds)
         and 1 <= stable_seconds <= 600, 'stability observation duration')
    need(type(interval_seconds) in (int, float) and math.isfinite(interval_seconds)
         and 1 <= interval_seconds <= stable_seconds, 'stability observation interval')
    need(type(minimum_samples) is int and 3 <= minimum_samples <= 100,
         'stability minimum sample count')
    maximum_samples = math.ceil(stable_seconds / interval_seconds) + minimum_samples + 1
    first_time = None
    previous_time = None
    first_health = None
    previous_health = None
    baseline = None
    for index in range(maximum_samples):
        inputs.unchanged()
        package = remote.package()
        need(type(package) is dict and package.get('version') == inputs.r['version']
             and package.get('sha256') == inputs.r['sha256']
             and package.get('uid') == inputs.p['app_uid'],
             'stability target package identity changed')
        snapshot = remote.snapshot()
        if type(snapshot) is not dict:
            raise Refusal('stability runtime observation schema')
        control = snapshot.get('control')
        health = snapshot.get('health_uptime')
        if type(control) is not dict or type(health) is not int:
            raise Refusal('stability runtime observation schema')
        need(all(k in control for k in LATE_CONTROL_FIELDS),
             'stability control observation schema')
        guardian_foreground(remote)
        late = remote.late_control()
        projected = {key: control[key] for key in LATE_CONTROL_FIELDS}
        need(canonical(late) == canonical(projected), 'stability late control changed')
        identity = canonical({'package': package, 'runtime': {
            key: value for key, value in snapshot.items() if key != 'health_uptime'}})
        now = clock()
        need(type(now) in (int, float) and math.isfinite(now)
             and (previous_time is None or now >= previous_time),
             'stability monotonic clock regressed')
        if first_time is None:
            first_time = now
            first_health = health
            baseline = identity
        else:
            need(identity == baseline, 'stability runtime epoch changed; no baseline reset')
            need(previous_health is not None and health >= previous_health,
                 'stability heartbeat regressed')
        previous_time = now
        previous_health = health
        span = now - first_time
        out.write('stability-sample-' + str(index).zfill(4) + '.json', {
            'package': package, 'runtime': snapshot, 'late_control': late,
            'measured_offset_seconds': span, 'guardian_foreground': True})
        if index + 1 >= minimum_samples and span >= stable_seconds:
            need(first_health is not None and health > first_health,
                 'stability heartbeat did not advance')
            inputs.unchanged()
            result = {'result': 'stable', 'samples': index + 1,
                      'observed_span_seconds': span, 'heartbeat_advanced': True,
                      'guardian_foreground': True, 'target_version': inputs.r['version'],
                      'runtime_signature_sha256': sha(identity), 'device_writes': 0,
                      'scope': 'bounded sampled stability, not reboot or unattended acceptance'}
            out.write('stability.json', result)
            return result
        sleep(interval_seconds)
    raise Refusal('stability observation clock/sample budget exhausted')

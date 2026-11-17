#!/usr/bin/env python3
"""Focused public-interface regression; production clocks alone are fixture-mapped.

Run directly after the main fixture; only the monotonic clock is mapped.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import unittest
import test_service as fixture

ARTIFACTS = Path(os.environ['FIXTURE_EVIDENCE'])


class BudgetFocus(fixture.ServiceTests):
    def setUp(self):
        super().setUp()
        self.clock = self.base / 'fixture-uptime'
        self.set_clock('1000.25')
        # Read the real watcher/child identities, locks, wait status and controls.
        # Only Android policy mapping (in the existing fixture) and /proc clock
        # input change; STABLE_SECONDS, retries, backoff and polling are untouched.
        text = self.script.read_text()
        self.script.write_text(text.replace('/proc/uptime', str(self.clock)))
        (self.base / 'fixture.py').write_text('''import os,time,sys
from pathlib import Path
p=Path(__file__).parent
with (p/'launches').open('a') as out: out.write(str(os.getpid())+'\\n')
mode=(p/'mode').read_text().strip()
if mode.startswith('exit'):
 time.sleep(.3); sys.exit(int(mode[4:]))
end=time.monotonic()+180
while time.monotonic()<end:
 request=p/'exit-request'
 if request.exists():
  code=int(request.read_text()); request.unlink(); sys.exit(code)
 time.sleep(.05)
sys.exit(9)
''')

    def tearDown(self):
        snapshot = {'test': self.id(), 'shell': fixture.SHELL, 'files': {}}
        for f in self.base.iterdir():
            if f.is_file() and not f.is_symlink() and (f.name.startswith('v2.') or f.name in ('launches', 'watch-debug.log')):
                snapshot['files'][f.name] = f.read_text()
        with (ARTIFACTS / ('diagnostics-' + Path(fixture.SHELL).name + '.jsonl')).open('a') as out:
            out.write(json.dumps(snapshot) + '\n')

    def set_clock(self, value):
        temp = self.base / 'fixture-uptime.tmp'
        temp.write_text(value + ' 0.00\n')
        temp.replace(self.clock)

    def logs(self):
        target = self.base / 'v2.current.log'
        return target.read_text() if target.exists() else ''

    def launches(self):
        target = self.base / 'launches'
        return len(target.read_text().splitlines()) if target.exists() else 0

    def until(self, predicate, timeout=15):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(): return
            time.sleep(.05)
        self.fail('deadline exceeded; launches=' + str(self.launches()) + '\n' + self.logs())

    def start_running(self):
        r = self.call('start')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.await_running()

    def crash(self, code=1):
        before = self.launches()
        request = self.base / 'exit-request.tmp'
        request.write_text(str(code))
        request.replace(self.base / 'exit-request')
        if code != 2:
            self.until(lambda: self.launches() == before + 1, timeout=20)
            self.await_running()

    def stable(self):
        # Allow the exact-ELF identity poll to capture the initial clock first.
        time.sleep(2)
        self.set_clock('1060.25')
        self.until(lambda: 'stable child; retry budget reset' in self.logs(), timeout=6)

    def focus_stable_resets_budget_and_delay(self):
        self.start_running()
        original_watch = (self.base / 'v2.watch').read_text()
        self.crash(); self.crash()
        time.sleep(2)
        self.set_clock('1060.24')  # 59.99 sec: must not reset early by rounding.
        time.sleep(2)
        self.assertNotIn('stable child; retry budget reset', self.logs())
        self.set_clock('1060.25')  # Exactly 60 sec since first exact child poll.
        self.until(lambda: 'stable child; retry budget reset' in self.logs(), timeout=6)
        for _ in range(4): self.crash()
        self.assertEqual(self.launches(), 7)  # Exceeds the old lifetime budget.
        self.assertFalse((self.base / 'v2.failure').exists())
        self.assertEqual(self.call('status').returncode, 0)
        self.assertEqual((self.base / 'v2.watch').read_text(), original_watch)
        backoffs = re.findall(r'backoff seconds=(\d+) retry=(\d+)', self.logs())
        self.assertEqual(backoffs, [('1','1'), ('2','2'), ('1','1'), ('2','2'), ('4','3'), ('8','4')])
        self.assertEqual(self.logs().count('stable child; retry budget reset'), 1)
        self.assertEqual(self.call('stop').returncode, 0)
        self.assertEqual(self.call('status').returncode, 3)

    def focus_short_crashes_still_latch(self):
        (self.base / 'mode').write_text('exit1')
        self.call('start')
        self.until(lambda: (self.base / 'v2.failure').exists(), timeout=80)
        self.assertEqual(self.launches(), 6)
        self.assertEqual((self.base / 'v2.failure').read_text(), 'exit=1 retries=5\n')
        self.assertEqual(re.findall(r'backoff seconds=(\d+) retry=(\d+)', self.logs()), [('1','1'), ('2','2'), ('4','3'), ('8','4'), ('8','5')])
        self.assertNotIn('stable child; retry budget reset', self.logs())
        self.assertEqual(self.call('status').returncode, 2)
        self.assertEqual(self.call('start').returncode, 2)
        time.sleep(2)
        self.assertEqual(self.launches(), 6)

    def focus_exit2_latches_after_stability_reset(self):
        self.start_running()
        self.crash()
        self.stable()
        self.crash(2)
        self.until(lambda: (self.base / 'v2.failure').exists())
        self.assertEqual((self.base / 'v2.failure').read_text(), 'exit=2 retries=0\n')
        self.assertEqual(self.call('status').returncode, 2)
        self.assertEqual(self.call('start').returncode, 2)
        time.sleep(2)
        self.assertEqual(self.launches(), 2)
        self.assertEqual(re.findall(r'backoff seconds=(\d+) retry=(\d+)', self.logs()), [('1','1')])


if __name__ == '__main__':
    ARTIFACTS.mkdir(exist_ok=True)
    names = sorted(name for name in dir(BudgetFocus) if name.startswith('focus_'))
    selected = os.environ.get('FOCUS_CASE')
    if selected: names = [name for name in names if name == selected]
    if not names: raise SystemExit('no selected focused cases')
    suite = unittest.TestSuite(BudgetFocus(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())

"""Portable offline/model tests. All identifiers and bytes are FICTIONAL."""
import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))


def profile():
    return {
        'schema': 1, 'serial': 'FICTIONAL-SERIAL-001', 'app_uid': 10123,
        'package': 'com.termux', 'base': '/data/local/tmp/fictional-private-adbd',
        'native_port': 5038, 'native_home': '/data/data/com.termux/files/home',
        'publisher': 'embedded',
        'transport': {'kind': 'controller', 'argv': ['FICTIONAL-controller', '--wait', '15']},
    }


class ProfileTests(unittest.TestCase):
    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('installer'), 'installer API missing')
        return importlib.import_module('installer')

    def test_serial_preserves_daemon_supported_dot_underscore_and_hyphen(self):
        m = self.api()
        p = profile()
        p['serial'] = 'FICTIONAL.SERIAL_001-X'
        try:
            validated = m.validate_profile(p)
        except m.Refusal:
            self.fail('a valid daemon serial was rejected')
        self.assertEqual(validated['serial'], p['serial'])

    def test_strict_profile(self):
        m = self.api()
        self.assertEqual(m.validate_profile(profile()), profile())
        bad_values = [
            ('serial', ''), ('serial', 'bad\nserial'), ('app_uid', 2000),
            ('base', '/data/local/tmp/../escape'), ('base', '/data/local/tmp/a;id'),
            ('native_port', 27184), ('native_home', '/data/local/tmp/home'),
            ('publisher', 'auto'), ('unknown', True), ('package', 'org.other'),
            ('schema', True),
        ]
        for key, value in bad_values:
            with self.subTest(key=key, value=value):
                p = profile(); p[key] = value
                with self.assertRaises(m.Refusal): m.validate_profile(p)
        for transport in [
            {'kind': 'adb', 'argv': ['adb']},
            {'kind': 'adb', 'argv': ['adb'], 'serial': 'FICTIONAL-transport', 'extra': 1},
            {'kind': 'controller', 'argv': 'shell string'},
            {'kind': 'controller', 'argv': []},
        ]:
            with self.subTest(transport=transport):
                p = profile(); p['transport'] = transport
                with self.assertRaises(m.Refusal): m.validate_profile(p)
        p = profile(); p['transport'] = {'kind': 'adb', 'argv': ['adb'], 'serial': 'FICTIONAL-transport'}
        self.assertEqual(m.validate_profile(p), p)


if __name__ == '__main__':
    unittest.main()

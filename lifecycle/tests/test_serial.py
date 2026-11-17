#!/usr/bin/env python3
"""Focused data-only configuration contract; inherits the real Linux fixture."""
import unittest
from test_service import ServiceTests


class SerialTests(ServiceTests):
    def serial_unterminated_suffix_fails_before_state(self):
        config = self.base / 'service.serial'
        config.write_bytes(b'FIXTURE-SERIAL-001\nextra')
        config.chmod(0o600)
        result = self.call('start')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(list(self.base.glob('v2.*')), [])

    def serial_embedded_nul_fails_before_state(self):
        config = self.base / 'service.serial'
        config.write_bytes(b'FIXTURE-SERIAL-001\x00\n')
        config.chmod(0o600)
        result = self.call('start')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(list(self.base.glob('v2.*')), [])

    def serial_missing_empty_multiline_and_shell_text_fail_closed(self):
        config = self.base / 'service.serial'
        marker = self.root / 'must-not-exist'
        for content in (None, '', '\n', 'FIXTURE-SERIAL-001',
                        'FIXTURE-SERIAL-001\nextra\n',
                        'FIXTURE-SERIAL-001\r\n',
                        '$(touch ' + str(marker) + ')\n'):
            with self.subTest(content=content):
                if content is None:
                    config.unlink()
                else:
                    config.write_text(content)
                    config.chmod(0o600)
                result = self.call('start')
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(marker.exists())
                self.assertEqual(list(self.base.glob('v2.*')), [])

    def serial_wrong_permissions_and_hardlink_fail_closed(self):
        config = self.base / 'service.serial'
        config.chmod(0o644)
        self.assertEqual(self.call('start').returncode, 2)
        self.assertEqual(list(self.base.glob('v2.*')), [])
        config.chmod(0o600)
        import os
        os.link(config, self.root / 'alias')
        self.assertEqual(self.call('start').returncode, 2)
        self.assertEqual(list(self.base.glob('v2.*')), [])

    def serial_environment_cannot_override_fixed_file(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, SERIAL='untrusted-environment'):
            result = self.call('start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.await_running()
        self.assertIn(b'FIXTURE-SERIAL-001', bytes.fromhex(
            (self.base / 'v2.child').read_text().split()[4]))


if __name__ == '__main__':
    names = sorted(name for name in dir(SerialTests) if name.startswith('serial_'))
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestSuite(SerialTests(name) for name in names))
    raise SystemExit(not result.wasSuccessful())

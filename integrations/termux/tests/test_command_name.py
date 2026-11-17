#!/usr/bin/env python3
"""Public command-name contract against the real checkout, not fixture copies."""
from pathlib import Path
import json
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1]


class CommandName(unittest.TestCase):
    def test_only_new_wrapper_is_published(self):
        self.assertTrue((SOURCE / 'private-adbd').is_file(), 'new Termux wrapper is missing')
        self.assertFalse((SOURCE / 'tablet-daemon').exists(), 'old wrapper must not remain as an alias')

    def test_help_and_errors_use_new_command_name(self):
        wrapper = SOURCE / 'private-adbd'
        self.assertTrue(wrapper.is_file(), 'new Termux wrapper is missing')
        result = subprocess.run(['bash', str(wrapper), '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('private-adbd start|ensure|status', result.stdout)
        self.assertIn('private-adbd reconcile ', result.stdout)
        self.assertIn('private-adbd pair ', result.stdout)
        self.assertNotIn('tablet-daemon', result.stdout + result.stderr)
        result = subprocess.run(['bash', str(wrapper), 'start', '37001', 'extra'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr, 'private-adbd: too many arguments\n')

    def test_current_docs_match_apk_manager_and_preserved_state(self):
        readme = (SOURCE / 'README.md').read_text()
        config = json.loads(readme.split('```json\n', 1)[1].split('```', 1)[0])
        manager = '/data/data/com.termux/files/usr/bin/private-adbd'
        self.assertEqual(config['managerPath'], manager)
        self.assertEqual(config['heartbeatPath'], '/data/data/com.termux/files/home/.config/tablet-daemon/health.json')
        self.assertIn('updated fork APK', readme)
        self.assertIn('tablet-guardian', readme)
        for text in (readme, (SOURCE.parents[1] / 'README.md').read_text()):
            self.assertIn(manager, text)
            self.assertNotIn('/data/data/com.termux/files/usr/bin/tablet-daemon', text)
            self.assertNotIn('tablet-daemon start', text)
            self.assertNotIn('tablet-daemon pair', text)
            self.assertNotIn('tablet-daemon status', text)
            self.assertNotIn('tablet-daemon ensure', text)
            self.assertNotIn('tablet-daemon reconcile', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)

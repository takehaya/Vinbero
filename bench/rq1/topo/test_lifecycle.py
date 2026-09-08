import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent


class LifecycleTests(unittest.TestCase):
    def run_with_mock_ip(self, script, behavior):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / 'calls'
            ip = root / 'ip'
            ip.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n' + behavior)
            ip.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'],
                       TOPO_NS_PREFIX='guard-', CALLS=str(calls))
            result = subprocess.run(['bash', str(SCRIPTS / script)], env=env,
                                    capture_output=True, text=True, timeout=5)
            return result, calls.read_text().splitlines()

    def test_setup_rollback_attempts_all_created_namespaces(self):
        result, calls = self.run_with_mock_ip('setup.sh', '''
case "$*" in
    "netns exec guard-pea ip link set lo up") exit 42 ;;
    "netns del guard-src") exit 1 ;;
esac
exit 0
''')
        self.assertEqual(result.returncode, 42)
        self.assertEqual([call for call in calls if call.startswith('netns del')],
                         ['netns del guard-src', 'netns del guard-rt', 'netns del guard-pea'])

    def test_teardown_reports_failure_and_attempts_remaining_namespaces(self):
        result, calls = self.run_with_mock_ip('teardown.sh', '''
case "$*" in
    "netns list") printf 'guard-src\\nguard-rt\\nguard-pea\\nguard-peb\\nother-src\\n' ;;
    "netns del guard-rt") exit 1 ;;
esac
exit 0
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call for call in calls if call.startswith('netns del')],
                         ['netns del guard-src', 'netns del guard-rt',
                          'netns del guard-pea', 'netns del guard-peb'])

    def test_teardown_tolerates_absent_namespaces(self):
        result, calls = self.run_with_mock_ip('teardown.sh', 'exit 0\n')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, ['netns list'])

    def test_teardown_reports_listing_failure(self):
        result, calls = self.run_with_mock_ip('teardown.sh', 'exit 2\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, ['netns list'])

    def test_invalid_rate_fails_before_creating_artifacts(self):
        for rate in ['1000000001', '18446744073709551616']:
            with self.subTest(rate=rate), tempfile.TemporaryDirectory() as directory:
                work = Path(directory) / 'run'
                env = dict(os.environ, RATE=rate, WORK=str(work))
                result = subprocess.run(['bash', str(SCRIPTS / 'run_bgp.sh'), '1'], env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(work.exists())

    def test_overflowing_trials_fail_before_creating_artifacts(self):
        for trials in ['9223372036854775807', '9223372036854775808', '18446744073709551616']:
            with self.subTest(trials=trials), tempfile.TemporaryDirectory() as directory:
                work = Path(directory) / 'run'
                env = dict(os.environ, WORK=str(work))
                result = subprocess.run(['bash', str(SCRIPTS / 'run_bgp.sh'), trials], env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn('loop counter range', result.stderr)
                self.assertFalse(work.exists())

    def test_setup_refuses_existing_namespace_without_deleting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls"
            ip = root / "ip"
            ip.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                          'if [[ "$*" == "netns list" ]]; then echo guard-src; fi\n')
            ip.chmod(0o755)
            helper = root / 'netns.sh'
            helper.write_text('echo snapshot-helper\n')
            env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'],
                       TOPO_NS_PREFIX='guard-', CALLS=str(calls), NETNS_HELPER=str(helper))
            result = subprocess.run(['bash', str(SCRIPTS / 'setup.sh')], env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('namespace already exists', result.stderr)
            self.assertIn('snapshot-helper', result.stdout)
            self.assertEqual(calls.read_text(), 'netns list\n')

    def test_invalid_mode_fails_before_creating_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / 'run'
            env = dict(os.environ, MODE='typo', WORK=str(work))
            result = subprocess.run(['bash', str(SCRIPTS / 'run_bgp.sh'), '1'], env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(work.exists())


if __name__ == '__main__':
    unittest.main()

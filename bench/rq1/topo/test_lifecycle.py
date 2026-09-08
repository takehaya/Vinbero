import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent


class LifecycleTests(unittest.TestCase):
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

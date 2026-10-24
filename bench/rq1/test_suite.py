import copy
import ctypes
import itertools
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import affinity
import analysis
import suite


def calibrated():
    return dict(rate=100000, sent=100000, received=100000, lost=0, duplicates=0,
                unknown=0, negative_delays=0, achieved_pps=100000,
                gap_median_us=10, gap_p99_us=10, unsent_schedule_slots=0)


class AffinityTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(version=1, allow_shared_cores=False, gomaxprocs=1,
                           cpus={role: [n] for n, role in enumerate(affinity.ROLES)})
        self.topology = {n: dict(package=0, core=n, node=0) for n in range(6)}

    def validate(self):
        return affinity.validate(self.config, range(6), self.topology)

    def test_separate_physical_cores_and_single_numa(self):
        self.assertEqual(len(self.validate()), 5)
        self.topology[4]['core'] = 0
        with self.assertRaisesRegex(ValueError, 'SMT sibling'):
            self.validate()
        self.topology[4].update(core=4, node=1)
        with self.assertRaisesRegex(ValueError, 'NUMA'):
            self.validate()
        self.config['allow_shared_cores'] = True
        self.validate()

    def test_invalid_assignments(self):
        for role, value in [('sender', [99]), ('sender', [1, 1]), ('sender', []),
                            ('sender', [True]), ('daemon', ['0'])]:
            with self.subTest(value=value):
                bad = copy.deepcopy(self.config)
                bad['cpus'][role] = value
                with self.assertRaises(ValueError):
                    affinity.validate(bad, range(6), self.topology)
        self.config['gomaxprocs'] = 2
        with self.assertRaisesRegex(ValueError, 'gomaxprocs'):
            self.validate()

    def test_exec_applies_and_records_effective_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = affinity.suggest(shared=True)
            config['cpus']['sender'] = [min(os.sched_getaffinity(0))]
            suite.write_json(root / 'affinity.json', config)
            result = subprocess.run([sys.executable, str(Path(affinity.__file__)), 'exec',
                                     '--config', str(root / 'affinity.json'), '--role', 'sender',
                                     '--record', str(root / 'effective.json'), '--', sys.executable,
                                     '-c', 'import os,json; print(json.dumps([os.getpid(), '
                                     'sorted(os.sched_getaffinity(0)), os.environ["GOMAXPROCS"]]))'],
                                    capture_output=True, text=True, check=True, timeout=5)
            pid, cpus, gomax = json.loads(result.stdout)
            self.assertEqual(json.loads((root / 'effective.json').read_text()),
                             dict(role='sender', pid=pid, cpus=cpus, gomaxprocs=int(gomax)))
            self.assertEqual(cpus, config['cpus']['sender'])
            self.assertEqual(gomax, '1')


class ScheduleTests(unittest.TestCase):
    def test_balanced_reproducible_blocks_and_separate_warmups(self):
        tasks = suite.schedule(30, 3, 123)
        self.assertEqual(tasks, suite.schedule(30, 3, 123))
        self.assertNotEqual(tasks, suite.schedule(30, 3, 124))
        self.assertEqual(len({t['id'] for t in tasks}), 99)
        self.assertEqual(sum(t['phase'] == 'warmup' for t in tasks), 9)
        orders = [tuple(t['mode'] for t in tasks[n:n+3]) for n in range(9, 99, 3)]
        self.assertEqual(set(orders), set(itertools.permutations(suite.MODES)))
        self.assertTrue(all(orders.count(order) == 5 for order in set(orders)))

    def test_invalid_design_and_smoke(self):
        for blocks, warmups, seed in [(5, 3, 0), (0, 3, 0), (306, 3, 0),
                                     (6, -1, 0), (6, 0, -1), (6, 0, 2**64)]:
            with self.assertRaises(ValueError):
                suite.schedule(blocks, warmups, seed)
        tasks = suite.schedule(2, 0, 1, smoke=True)
        self.assertEqual(len(tasks), 6)
        self.assertEqual([t['mode'] for t in tasks[:3]], list(reversed([t['mode'] for t in tasks[3:]])))

    def test_calibration_quality_gate(self):
        self.assertEqual(suite.calibration_errors(calibrated(), 100000), [])
        for field, value in [('lost', 1), ('duplicates', 1), ('unknown', 1),
                             ('negative_delays', 1), ('gap_median_us', 16),
                             ('gap_p99_us', 51), ('achieved_pps', 94999), ('rate', 10000),
                             ('unsent_schedule_slots', 1)]:
            bad = calibrated()
            bad[field] = value
            with self.subTest(field=field):
                self.assertTrue(suite.calibration_errors(bad, 100000))

    def test_rate_one_fails_during_planning_before_creating_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = affinity.suggest(shared=True)
            config['allow_shared_cores'] = False
            suite.write_json(root / 'affinity.json', config)
            args = type('Args', (), dict(smoke=False, affinity=root / 'affinity.json',
                                         blocks=6, warmups=0, seed=1, rate=1, plan=True))()
            with patch.object(affinity, 'validate'), self.assertRaisesRegex(ValueError, 'between 2'):
                suite.prepare(args)


class RunnerTests(unittest.TestCase):
    def test_timeout_and_cancellation_allow_child_cleanup(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                script = root / 'child.py'
                script.write_text('import os,signal,time\nfrom pathlib import Path\n'
                                  'def stop(*args):\n    Path("cleaned").write_text("yes")\n    raise SystemExit(0)\n'
                                  'signal.signal(signal.SIGTERM, stop)\n'
                                  + ('os.kill(os.getppid(), signal.SIGTERM)\n' if cancel else '') +
                                  'time.sleep(10)\n')
                # Child cwd is inherited; make cleanup path absolute without
                # changing the test process cwd or depending on a network.
                script.write_text(script.read_text().replace('Path("cleaned")', f'Path({str(root / "cleaned")!r})'))
                runner = suite.ChildRunner()
                old = signal.signal(signal.SIGTERM, runner.interrupt)
                try:
                    code = runner.run([sys.executable, str(script)], root / 'log', os.environ, 1)
                finally:
                    signal.signal(signal.SIGTERM, old)
                self.assertEqual(code, 143 if cancel else 124)
                self.assertTrue((root / 'cleaned').exists())
                self.assertIsNone(runner.child)

    def test_cancellation_sends_term_once_and_waits_for_slow_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'child.py'
            script.write_text('import os,signal,time,threading\nfrom pathlib import Path\n'
                              'def stop(*args):\n'
                              '    signal.signal(signal.SIGTERM, signal.SIG_DFL)\n'
                              '    time.sleep(0.6)\n'
                              f'    Path({str(root / "cleaned")!r}).write_text("yes")\n'
                              '    raise SystemExit(0)\n'
                              'def cancel():\n'
                              '    os.kill(os.getppid(), signal.SIGINT)\n'
                              '    time.sleep(0.05)\n'
                              '    os.kill(os.getppid(), signal.SIGTERM)\n'
                              'signal.signal(signal.SIGTERM, stop)\n'
                              'threading.Thread(target=cancel).start()\n'
                              'time.sleep(10)\n')
            runner = suite.ChildRunner()
            prior = {sig: signal.signal(sig, runner.interrupt) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                code = runner.run([sys.executable, str(script)], root / 'log', os.environ, 3)
            finally:
                for sig, handler in prior.items():
                    signal.signal(sig, handler)
            self.assertEqual(code, 143)
            self.assertTrue((root / 'cleaned').exists())
            self.assertIsNone(runner.child)
            with patch.object(subprocess, 'Popen') as child:
                self.assertEqual(runner.run(['not-launched'], root / 'next', {}, 1), 143)
                child.assert_not_called()

    def test_cancellation_between_initial_check_and_mask_prevents_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = suite.ChildRunner()
            mask = signal.pthread_sigmask

            def interrupt_before_mask(how, signals):
                if how == signal.SIG_BLOCK:
                    runner.interrupt(signal.SIGINT, None)
                return mask(how, signals)

            with patch.object(signal, 'pthread_sigmask', side_effect=interrupt_before_mask), \
                    patch.object(subprocess, 'Popen') as child:
                self.assertEqual(runner.run(['not-launched'], Path(directory) / 'log', {}, 1), 130)
                child.assert_not_called()
            self.assertIsNone(runner.child)

    def test_abnormal_driver_exit_cleans_only_its_descendants(self):
        # Reap orphaned fixture children ourselves instead of depending on PID 1.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        try:
            for mode in ('exit', 'killed', 'ignore', 'cancel'):
                with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    child = root / 'descendant.py'
                    child.write_text('import os,signal,time\nfrom pathlib import Path\n'
                                     'def stop(*args):\n'
                                     '    signal.signal(signal.SIGTERM, signal.SIG_DFL)\n'
                                     f'    Path({str(root / "cleaning")!r}).write_text("started")\n'
                                     '    time.sleep(0.1)\n'
                                     f'    Path({str(root / "cleaned")!r}).write_text("done")\n'
                                     '    raise SystemExit(0)\n'
                                     f'signal.signal(signal.SIGTERM, {"signal.SIG_IGN" if mode == "ignore" else "stop"})\n'
                                     f'Path({str(root / "ready")!r}).write_text(str(os.getpid()))\n'
                                     'time.sleep(30)\n')
                    driver = root / 'driver.py'
                    ending = {'exit': 'os._exit(7)', 'ignore': 'os._exit(7)',
                              'killed': 'os.kill(os.getpid(), signal.SIGKILL)',
                              'cancel': ('def stop(*args):\n'
                                         '    child.send_signal(signal.SIGTERM)\n'
                                         f'    while not Path({str(root / "cleaning")!r}).exists(): time.sleep(0.01)\n'
                                         '    os._exit(9)\n'
                                         'signal.signal(signal.SIGTERM, stop)\n'
                                         'os.kill(os.getppid(), signal.SIGINT)\n'
                                         'time.sleep(30)')}[mode]
                    driver.write_text('import os,signal,subprocess,sys,time\nfrom pathlib import Path\n'
                                      f'child = subprocess.Popen([sys.executable, {str(child)!r}])\n'
                                      f'while not Path({str(root / "ready")!r}).exists(): time.sleep(0.01)\n'
                                      + ending + '\n')
                    # This sibling has a different session and must never be signalled.
                    unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)
                    runner = suite.ChildRunner()
                    prior = signal.signal(signal.SIGINT, runner.interrupt)
                    descendant = None
                    try:
                        with patch.object(suite, 'CLEANUP_GRACE_SECONDS', 0.4, create=True):
                            code = runner.run([sys.executable, str(driver)], root / 'log', os.environ, 5)
                        descendant = int((root / 'ready').read_text())
                        self.assertEqual(code, {'exit': 7, 'ignore': 7, 'killed': -9, 'cancel': 130}[mode])
                        self.assertIsNone(runner.child)
                        self.assertIsNone(unrelated.poll())
                        deadline = time.monotonic() + 1
                        status = None
                        while time.monotonic() < deadline:
                            pid, status = os.waitpid(descendant, os.WNOHANG)
                            if pid:
                                descendant = None
                                break
                            time.sleep(0.01)
                        self.assertIsNone(descendant, 'owned descendant survived driver failure')
                        if mode == 'ignore':
                            self.assertTrue(os.WIFSIGNALED(status))
                            self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                        else:
                            self.assertTrue((root / 'cleaned').exists(), 'descendant lost its TERM cleanup grace')
                    finally:
                        signal.signal(signal.SIGINT, prior)
                        if descendant is None and (root / 'ready').exists():
                            # Successful reaping above makes waitpid raise below.
                            descendant = int((root / 'ready').read_text())
                        if descendant is not None:
                            try:
                                pid, _ = os.waitpid(descendant, os.WNOHANG)
                                if not pid:
                                    os.kill(descendant, signal.SIGKILL)
                                    os.waitpid(descendant, 0)
                            except ChildProcessError:
                                pass
                        unrelated.terminate()
                        unrelated.wait(timeout=5)
        finally:
            self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def test_already_cancelled_does_not_launch(self):
        runner = suite.ChildRunner()
        runner.interrupt(signal.SIGINT, None)
        self.assertEqual(runner.run(['does-not-exist'], Path('/not-created'), {}, 1), 130)

    def test_snapshot_change_fails_before_any_child_and_keeps_pending_trials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source').mkdir()
            (root / 'source/tool').write_text('changed')
            manifest = dict(version=1, state='prepared', kind='smoke', seed=1,
                            affinity={}, sha256={'tool': 'wrong'}, tasks=suite.schedule(2, 0, 1, True))
            suite.write_json(root / 'suite.json', manifest)
            with patch.object(suite, 'trusted_directory', return_value=root), \
                    patch.object(os, 'geteuid', return_value=0), \
                    patch.object(suite.ChildRunner, 'run') as child:
                self.assertEqual(suite.execute(root), 1)
                child.assert_not_called()
            final = json.loads((root / 'suite.json').read_text())
            self.assertEqual(final['state'], 'failed')
            self.assertIn('snapshot changed', final['error'])
            self.assertTrue(all(t['state'] == 'pending' for t in final['tasks']))
            self.assertEqual(len((root / 'trials.csv').read_text().splitlines()), 7)

    def test_recovery_only_uses_child_ownership_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owned = root / 'topology-owned'
            with patch.object(subprocess, 'run') as command:
                suite.recover_topology(root, root / 'source', root / 'recovery.log')
                command.assert_not_called()
                owned.write_text('owned-src\n')
                suite.write_json(root / 'run.json', {'namespace_prefix': 'owned-'})
                suite.recover_topology(root, root / 'source', root / 'recovery.log')
                self.assertEqual(command.call_args.kwargs['env']['TOPOLOGY_OWNED_FILE'], str(owned))
                self.assertEqual(command.call_args.kwargs['env']['TOPO_NS_PREFIX'], 'owned-')
                self.assertFalse(owned.exists())
                owned.write_text('owned-src\n')
                command.side_effect = subprocess.CalledProcessError(1, 'teardown')
                with self.assertRaises(subprocess.CalledProcessError):
                    suite.recover_topology(root, root / 'source', root / 'recovery.log')
                self.assertTrue(owned.exists())

    def test_failed_status_and_launch_errors_stop_without_losing_the_trial(self):
        for problem in ('status', 'launch', 'cancel', 'calibration'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = affinity.suggest(shared=True)
                manifest = dict(version=1, state='prepared', kind='smoke', seed=1, rate=100000,
                                affinity=config, sha256={}, trial_timeout_s=1,
                                tasks=suite.schedule(2, 0, 1, True))
                suite.write_json(root / 'suite.json', manifest)
                suite.write_json(root / 'affinity.json', config)
                calls = []

                def run(runner, command, log, env, timeout):
                    calls.append(command)
                    if command[0] == 'taskset':
                        suite.write_json(log, calibrated())
                        return 1 if problem == 'calibration' else 0
                    if problem == 'launch':
                        raise OSError('launch failed')
                    if problem == 'cancel':
                        runner.interrupt(signal.SIGINT, None)
                        return 130
                    active = Path(env['WORK'])
                    active.mkdir(parents=True)
                    suite.write_json(active / 'status.json', dict(exit_code=0, completed_trials=0, requested_trials=1))
                    return 0

                with patch.object(suite, 'trusted_directory', return_value=root), \
                        patch.object(os, 'geteuid', return_value=0), \
                        patch.object(suite.ChildRunner, 'run', run):
                    self.assertEqual(suite.execute(root), 130 if problem == 'cancel' else 1)
                final = json.loads((root / 'suite.json').read_text())
                self.assertEqual(final['state'], 'interrupted' if problem == 'cancel' else 'failed')
                self.assertEqual(len(calls), 1 if problem == 'calibration' else 2)
                self.assertEqual(final['tasks'][0]['state'], 'pending' if problem == 'calibration' else 'failed')
                self.assertTrue(all(t['state'] == 'pending' for t in final['tasks'][1:]))
                self.assertEqual(len((root / 'trials.csv').read_text().splitlines()), 7)


if __name__ == '__main__':
    unittest.main()

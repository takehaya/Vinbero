import copy
import json
from pathlib import Path
import tempfile
import unittest

import analysis
import suite
from topo import check


def capture(root):
    (root / 'churn.log').write_text('ready\nchange_ns=1020000\n')
    (root / 'sent.csv').write_text('seq,tag,sent_unix_ns\n0,1,1000000\n1,1,1010000\n'
                                 '2,1,1020000\n3,1,1030000\n4,1,1040000\n5,1,1050000\n')
    (root / 'pea.csv').write_text('seq,tag,endpoint,recv_unix_ns\n0,1,pe-a,1001000\n'
                                '2,1,pe-a,1021000\n3,1,pe-a,1061000\n')
    # Probe 1 was in flight at the change; probe 4 is lost. Probe 2 is duplicated
    # across endpoints after the first new arrival and remains misdelivered.
    (root / 'peb.csv').write_text('seq,tag,endpoint,recv_unix_ns\n1,1,pe-b,1026000\n'
                                '5,1,pe-b,1051000\n2,1,pe-b,1071000\n')
    suite.write_json(root / 'sender-schedule.json', dict(rate=100000, start_unix_ns=1000000,
                                                       requested_start_unix_ns='999000', duration_ns=60000))


def run_artifacts(root, task, manifest):
    directory = root / 'runs' / task['id']
    trial = directory / 'trial-1'
    trial.mkdir(parents=True)
    capture(trial)
    suite.write_json(directory / 'status.json', dict(exit_code=0, completed_trials=1, requested_trials=1))
    suite.write_json(directory / 'affinity.json', {'config': manifest['affinity']})
    suite.write_json(directory / 'run.json', dict(mode=task['mode'], rate=100000, trials=1,
                                                source_commit=manifest['source']['commit'], source_dirty=False,
                                                artifacts={'bin/' + Path(name).name: sha for name, sha in manifest['sha256'].items()}))
    (directory / 'results.csv').write_text('trial,mode,latency_us,lost,misdelivered,sample_gap_us\n'
                                          f'1,{task["mode"]},6.000,1,1,10.000\n')
    for role, cpus in manifest['affinity']['cpus'].items():
        suite.write_json(trial / f'{role}-affinity.json', dict(role=role, cpus=cpus, pid=1, gomaxprocs=1))
    for stage, sid in [('initial', 'fd00:a::100'), ('final', 'fd00:b::100')]:
        entry = dict(triggerPrefix=check.PREFIX, mode='SRV6_HEADEND_BEHAVIOR_H_ENCAPS',
                     srcAddr='fd00:100::', dstAddr=sid, segments=[sid])
        plugins, groups = [], []
        if task['mode'] in ('builtin-idle', 'cplane'):
            idle = task['mode'] == 'builtin-idle'
            plugins = [dict(name=check.PLUGIN, endpointBehaviors=[0xFE01], capabilities=['headend'],
                            families=['vpnv6' if idle else 'vpnv4'], deliveryIdle=True,
                            scope={'headendPrefixes': [check.IDLE_PREFIX if idle else check.PREFIX]},
                            headendEntries=0 if idle else 1, since='2026-09-15T00:00:00Z', snapshots='1')]
        if task['mode'] in ('builtin', 'builtin-idle'):
            groups = [dict(groupId=42, prefixes=[check.PREFIX], members=[{'segments': [sid]}])]
        suite.write_json(trial / f'{stage}.json', dict(headend={'headendv4s': [entry]},
                                                      plugins={'plugins': plugins}, groups={'groups': groups}))


class CaptureTests(unittest.TestCase):
    def test_inflight_probe_loss_old_tail_and_actual_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture(root)
            got = analysis.capture_metrics(root)
            self.assertEqual(got['latency_us'], 6)
            self.assertEqual(got['lost'], 1)
            self.assertEqual(got['loss_percent'], 25)
            self.assertEqual(got['misdelivered'], 1)
            self.assertEqual(got['old_after_first_new'], 1)
            self.assertEqual(got['duplicate_arrivals'], 1)
            self.assertEqual(got['sample_gap_us'], 10)
            self.assertEqual(got['gap_p99_us'], 25)
            self.assertEqual(got['gap_before_first_new_us'], 5)
            self.assertEqual(got['achieved_pps'], 100000)
            self.assertEqual(got['send_lag_max_us'], 0)
            self.assertEqual(got['sender_start_lateness_us'], 1)
            self.assertEqual(got['unsent_schedule_slots'], 0)

    def test_malformed_captures_fail_without_silently_dropping_rows(self):
        for filename, extra in [('sent.csv', '1,1,1010000\n'), ('sent.csv', 'six,1,1060000\n'),
                                ('peb.csv', '99,1,pe-b,1071000\n'), ('peb.csv', '2,9,pe-b,1071000\n'),
                                ('peb.csv', '2,1,wrong,1071000\n'), ('peb.csv', '2,1,pe-b,1071000,extra\n')]:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture(root)
                with (root / filename).open('a') as stream:
                    stream.write(extra)
                with self.assertRaises(ValueError):
                    analysis.capture_metrics(root)

    def test_bad_clocks_and_coarse_observation_are_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture(root)
            with (root / 'pea.csv').open('a') as stream:
                stream.write('4,1,pe-a,1035000\n')
            got = analysis.capture_metrics(root)
            self.assertEqual(got['negative_receive_delays'], 1)
            self.assertIn('clock_or_schedule_reversal', got['quality_flags'])

    def test_unsent_tail_is_flagged_even_when_successful_sends_have_exact_pps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture(root)
            schedule = json.loads((root / 'sender-schedule.json').read_text())
            schedule['duration_ns'] = 1000000000
            suite.write_json(root / 'sender-schedule.json', schedule)
            got = analysis.capture_metrics(root)
            self.assertEqual(got['achieved_pps'], 100000)
            self.assertEqual(got['unsent_schedule_slots'], 99994)
            self.assertIn('unsent_schedule_slots', got['quality_flags'])


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = dict(version=1, kind='performance', state='complete', seed=123,
                             calibration={'enforced': True, 'quality_errors': []})
        self.rows = suite.schedule(6, 1, 123)
        for row in self.rows:
            # Large drift between blocks cancels in a paired difference.
            latency = row['block'] * 1000 + {'builtin': 10, 'builtin-idle': 12, 'cplane': 30}[row['mode']]
            row.update(state='complete', latency_us=latency, lost=0, sent_after_change=100,
                       misdelivered=1, old_after_first_new=0, sample_gap_us=10, quality_flags='')

    def test_bootstrap_keeps_conditions_paired_and_excludes_warmup(self):
        self.rows[0]['latency_us'] = 1000000
        result = analysis.summarize_rows(self.rows, self.manifest, repetitions=200)
        self.assertTrue(result['performance_usable'])
        self.assertEqual(result['warmup_completed'], 3)
        self.assertEqual(result['modes']['builtin']['completed'], 6)
        self.assertEqual(result['modes']['builtin']['latency_median_us'], 3510)
        for mode, difference in [('builtin-idle', 2), ('cplane', 20)]:
            pair = result['comparisons'][mode + '-minus-builtin']
            self.assertEqual(pair['paired_blocks'], 6)
            self.assertEqual(pair['paired_median_difference_us'], difference)
            self.assertEqual(pair['ci95_us'], [difference, difference])
        self.assertEqual(result, analysis.summarize_rows(self.rows, self.manifest, repetitions=200))

    def test_failed_incomplete_smoke_and_quality_flagged_have_no_intervals(self):
        for condition in ('failed', 'pending', 'smoke', 'quality', 'calibration'):
            rows, manifest = copy.deepcopy(self.rows), copy.deepcopy(self.manifest)
            if condition in ('failed', 'pending'):
                rows[-1]['state'] = condition
                manifest['state'] = 'failed'
            elif condition == 'smoke':
                manifest['kind'] = 'smoke'
            elif condition == 'quality':
                rows[-1]['quality_flags'] = 'offered_rate_mismatch'
            else:
                manifest['calibration']['quality_errors'] = ['lost=1']
            result = analysis.summarize_rows(rows, manifest)
            with self.subTest(condition=condition):
                self.assertFalse(result['performance_usable'])
                self.assertEqual(result['comparisons'], {})
                self.assertNotIn('median_ci95_us', result['modes']['builtin'])

    def test_missing_completed_artifacts_are_reported_as_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.manifest['tasks'] = self.rows
            suite.write_json(root / 'suite.json', self.manifest)
            rows, summary = analysis.summarize(root)
            self.assertEqual(len(rows), 21)
            self.assertTrue(all(r['state'] == 'failed' for r in rows))
            self.assertFalse(summary['complete'])
            self.assertEqual(summary['state'], 'validation_failed')
            self.assertEqual(summary['modes']['cplane']['failed'], 6)
            self.assertTrue((root / 'trials.csv').exists())
            self.assertTrue((root / 'report.md').exists())

    def test_forwarding_comparison_retains_member_differences(self):
        original = dict(headend={'headendv4s': []}, groups={'groups': [dict(groupId=1, owner='a', members=[{'weight': 1}])]})
        other = copy.deepcopy(original)
        other['groups']['groups'][0].update(groupId=2, owner='b')
        self.assertEqual(analysis.forwarding_state(original), analysis.forwarding_state(other))
        other['groups']['groups'][0]['members'][0]['weight'] = 2
        self.assertNotEqual(analysis.forwarding_state(original), analysis.forwarding_state(other))

    def test_complete_artifact_validation_and_corruption(self):
        manifest = dict(self.manifest, kind='smoke', tasks=suite.schedule(2, 0, 123, True), rate=100000,
                        source=dict(commit='a' * 40, dirty=False),
                        affinity=dict(version=1, allow_shared_cores=True, gomaxprocs=1,
                                      cpus={role: [0] for role in suite.affinity.ROLES}),
                        sha256={name: 'sha-' + Path(name).name for name in suite.BINARIES})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for task in manifest['tasks']:
                task.update(state='complete', exit_code=0)
                run_artifacts(root, task, manifest)
            suite.write_json(root / 'suite.json', manifest)
            rows, summary = analysis.summarize(root)
            self.assertTrue(summary['complete'])
            self.assertFalse(summary['performance_usable'])
            self.assertEqual(summary['modes']['cplane']['lost'], 2)
            self.assertTrue(all(row['state'] == 'complete' for row in rows))
            first = manifest['tasks'][0]
            trial = root / 'runs' / first['id'] / 'trial-1'
            record = json.loads((trial / 'sender-affinity.json').read_text())
            record['cpus'] = [1]
            suite.write_json(trial / 'sender-affinity.json', record)
            rows, summary = analysis.summarize(root)
            self.assertFalse(summary['complete'])
            self.assertIn('effective CPU assignment', rows[0]['error'])
            self.assertEqual(summary['modes']['builtin']['failed'], 1)


if __name__ == '__main__':
    unittest.main()

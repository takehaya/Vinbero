import copy
import csv
from pathlib import Path
import tempfile
import unittest

import check


def state(mode="cplane", sid="fd00:a::100"):
    entry = {"triggerPrefix": check.PREFIX, "mode": "SRV6_HEADEND_BEHAVIOR_H_ENCAPS",
             "srcAddr": "fd00:100::", "dstAddr": sid, "segments": [sid]}
    plugins = []
    groups = []
    if mode == "cplane":
        plugins = [{"name": check.PLUGIN, "endpointBehaviors": [0xFE01], "capabilities": ["headend"],
                    "headendEntries": 1, "since": "2026-09-08T00:00:00Z", "snapshots": "1"}]
    if mode == "builtin":
        groups = [{"prefixes": [check.PREFIX], "members": [{"segments": [sid]}]}]
    return {"headend": {"headendv4s": [entry]}, "plugins": {"plugins": plugins}, "groups": {"groups": groups}}


class CheckTests(unittest.TestCase):
    def test_valid_modes_and_update(self):
        for mode in ("builtin", "cplane", "relay"):
            with self.subTest(mode=mode):
                initial = state(mode)
                check.verify(initial, mode, "fd00:a::100")
                check.verify(state(mode, "fd00:b::100"), mode, "fd00:b::100", initial)

    def test_empty_requires_no_prior_state(self):
        check.verify({"headend": {}, "plugins": {}, "groups": {}}, "cplane", "")
        with self.assertRaises(ValueError):
            check.verify(state(), "cplane", "")

    def test_missing_plugin_cannot_pass_using_builtin_forwarding(self):
        with self.assertRaises(ValueError):
            check.verify(state("builtin"), "cplane", "fd00:a::100")
        with self.assertRaises(ValueError):
            check.verify(state(), "builtin", "fd00:a::100")

    def test_stale_sid_and_group_are_rejected(self):
        with self.assertRaises(ValueError):
            check.verify(state(), "cplane", "fd00:b::100")
        stale = state("builtin", "fd00:b::100")
        stale["groups"]["groups"][0]["members"][0]["segments"] = ["fd00:a::100"]
        with self.assertRaises(ValueError):
            check.verify(stale, "builtin", "fd00:b::100")

    def test_plugin_failures_and_restarts_are_rejected(self):
        for field in ("dead", "droppedEvents", "restarts", "quarantinedEvents", "pendingDeclarations"):
            with self.subTest(field=field):
                bad = state()
                bad["plugins"]["plugins"][0][field] = 1
                with self.assertRaises(ValueError):
                    check.verify(bad, "cplane", "fd00:a::100")
        initial = state()
        for field, value in (("since", "2026-09-08T00:01:00Z"), ("snapshots", "2")):
            bad = copy.deepcopy(initial)
            bad["plugins"]["plugins"][0][field] = value
            with self.assertRaises(ValueError):
                check.verify(bad, "cplane", "fd00:a::100", initial)

    def test_capture_requires_observed_initial_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sent = root / "sent.csv"
            recv = root / "recv.csv"
            sent.write_text("seq,sent_unix_ns\n1,90\n2,110\n")
            for rows, valid in (([(1, 95, "pe-a"), (2, 120, "pe-b")], True),
                                ([(2, 120, "pe-b")], False),
                                ([(1, 95, "pe-b"), (2, 120, "pe-b")], False)):
                with recv.open("w") as stream:
                    writer = csv.writer(stream)
                    writer.writerow(["seq", "recv_unix_ns", "endpoint"])
                    writer.writerows(rows)
                if valid:
                    check.verify_capture(sent, [recv], 100)
                else:
                    with self.assertRaises(ValueError):
                        check.verify_capture(sent, [recv], 100)


if __name__ == "__main__":
    unittest.main()

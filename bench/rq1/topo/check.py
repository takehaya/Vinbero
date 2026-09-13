#!/usr/bin/env python3
"""Read-only readiness and trial validation for the isolated RQ1 topology."""

import argparse
import csv
import ipaddress
import json
from pathlib import Path
import time
import urllib.request

PREFIX = "10.0.2.0/24"
PLUGIN = "rq1-receiver"


def rpc(address, service, method):
    request = urllib.request.Request(
        f"http://{address}/vinbero.v1.{service}/{method}",
        data=b"{}",
        headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"},
    )
    # Environment proxy settings must not redirect namespace-local RPCs.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=2) as response:
        return json.load(response)


def snapshot(address, mode):
    return {
        "headend": rpc(address, "Headendv4Service", "Headendv4List"),
        "groups": rpc(address, "HeadendGroupService", "HeadendGroupList"),
        "plugins": rpc(address, "PluginService", "CplanePluginStats") if mode != "relay" else {},
    }


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(state, mode, sid, previous=None):
    plugins = state["plugins"].get("plugins", [])
    require(not state["plugins"].get("unrestored"), "unrestored plugins are present")
    entries = state["headend"].get("headendv4s", [])
    groups = state["groups"].get("groups", [])
    if not sid:
        require(not entries and not groups and not plugins, "initial state is not empty")
        return

    require(len(entries) == 1, "expected exactly one headend entry")
    entry = entries[0]
    require(entry.get("triggerPrefix") == PREFIX, "wrong headend prefix")
    require(entry.get("mode") == "SRV6_HEADEND_BEHAVIOR_H_ENCAPS", "wrong encap mode")
    require(ipaddress.ip_address(entry.get("srcAddr", "::")) == ipaddress.ip_address("fd00:100::"), "wrong encap source")
    require(entry.get("segments") == [sid], "wrong headend SID")
    require(entry.get("dstAddr") == sid, "wrong outer destination")

    if mode == "builtin":
        require(len(groups) == 1 and groups[0].get("prefixes") == [PREFIX], "expected one builtin group")
        members = groups[0].get("members", [])
        require(len(members) == 1 and members[0].get("segments") == [sid], "wrong group SID")
    else:
        require(not groups, "direct headend unexpectedly has an ECMP group")

    if mode != "cplane":
        require(not plugins, "baseline unexpectedly has a plugin")
        return
    require(len(plugins) == 1 and plugins[0].get("name") == PLUGIN, "measurement plugin is absent")
    plugin = plugins[0]
    require(plugin.get("endpointBehaviors") == [0xFE01], "wrong behavior claim")
    require(plugin.get("capabilities") == ["headend"], "wrong capabilities")
    require(not plugin.get("dead"), "plugin is dead")
    for field in ("droppedEvents", "restarts", "quarantinedEvents", "pendingDeclarations", "localSids", "advertisedRoutes"):
        require(int(plugin.get(field, 0)) == 0, f"plugin {field} is nonzero")
    require(int(plugin.get("headendEntries", 0)) == 1, "plugin does not own the headend")
    require(plugin.get("since"), "plugin start time is missing")
    if previous:
        before = previous["plugins"]["plugins"][0]
        require(plugin["since"] == before["since"], "plugin restarted during the trial")
        require(plugin.get("snapshots", "0") == before.get("snapshots", "0"), "unexpected replay during the trial")


def verify_capture(sent_path, received_paths, change_ns):
    with open(sent_path) as stream:
        sent = {int(r["seq"]): int(r["sent_unix_ns"]) for r in csv.DictReader(stream)}
    received = []
    for path in received_paths:
        with open(path) as stream:
            received.extend(csv.DictReader(stream))
    require(any(t < change_ns for t in sent.values()), "no probes before the change")
    require(any(t >= change_ns for t in sent.values()), "no probes after the change")
    before = [r for r in received if int(r["seq"]) in sent and int(r["recv_unix_ns"]) < change_ns]
    require(any(r["endpoint"] == "pe-a" for r in before), "initial traffic never reached pe-a")
    require(not any(r["endpoint"] == "pe-b" for r in before), "traffic reached pe-b before the change")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    wait = commands.add_parser("wait")
    wait.add_argument("--rpc", default="127.0.0.1:18081")
    wait.add_argument("--mode", choices=("builtin", "cplane", "relay"), required=True)
    wait.add_argument("--sid", default="")
    wait.add_argument("--previous", type=Path)
    wait.add_argument("--out", type=Path, required=True)
    wait.add_argument("--timeout", type=float, default=60)
    capture = commands.add_parser("capture")
    capture.add_argument("--sent", required=True)
    capture.add_argument("--recv", nargs=2, required=True)
    capture.add_argument("--change-ns", type=int, required=True)
    args = parser.parse_args()
    if args.command == "capture":
        verify_capture(args.sent, args.recv, args.change_ns)
        return
    previous = json.loads(args.previous.read_text()) if args.previous else None
    deadline = time.monotonic() + args.timeout
    last_error = "no attempts"
    while time.monotonic() < deadline:
        try:
            state = snapshot(args.rpc, args.mode)
            verify(state, args.mode, args.sid, previous)
            args.out.write_text(json.dumps(state, indent=2) + "\n")
            return
        except (AssertionError, OSError, ValueError) as error:
            last_error = str(error)
            time.sleep(0.2)
    raise SystemExit(f"readiness failed: {last_error}")


if __name__ == "__main__":
    main()

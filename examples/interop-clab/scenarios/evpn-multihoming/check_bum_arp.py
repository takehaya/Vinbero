#!/usr/bin/env python3
"""Check one BusyBox broadcast ARP probe; silence and duplicates both fail."""
import re
import sys


def single_reply(text, target, source, mac):
    rows = [line.strip() for line in text.splitlines() if line.strip()]
    if len(rows) != 4 or rows[0] != f"ARPING {target} from {source} eth1":
        return False
    reply = rf"Unicast reply from {re.escape(target)} \[{re.escape(mac)}\] [0-9]+(?:\.[0-9]+)?ms"
    # BusyBox 1.36.1 reports zero broadcasts under -b even though the request
    # goes to ff:ff:ff:ff:ff:ff; the command flag, not this counter, forces BUM.
    return (re.fullmatch(reply, rows[1], re.IGNORECASE) is not None
            and re.fullmatch(r"Sent 1 probe\(s\) \([01] broadcast\(s\)\)", rows[2]) is not None
            and rows[3] == "Received 1 response(s) (0 request(s), 0 broadcast(s))")


def selfcheck():
    target, source, mac = "10.0.0.10", "10.0.0.30", "aa:bb:cc:00:00:10"
    good = (f"ARPING {target} from {source} eth1\n"
            f"Unicast reply from {target} [{mac}] 0.008ms\n"
            "Sent 1 probe(s) (0 broadcast(s))\n"
            "Received 1 response(s) (0 request(s), 0 broadcast(s))\n")
    assert single_reply(good, target, source, mac)
    assert single_reply(good.replace("(0 broadcast(s))\nReceived", "(1 broadcast(s))\nReceived"), target, source, mac)
    bad = [good.replace(good.splitlines()[1] + "\n", "").replace("Received 1", "Received 0"),
           good.replace("Sent 1", "Sent 0"), good.replace("Received 1", "Received 2"),
           good + good.splitlines()[1], good.replace(f"reply from {target}", "reply from 10.0.0.99"),
           good.replace(f"[{mac}]", "[aa:bb:cc:00:00:99]"), good.replace("0.008ms", "nanms"),
           good.replace("eth1", "eth0"), good.rsplit("Received", 1)[0], "", "malformed"]
    assert all(not single_reply(text, target, source, mac) for text in bad)
    print("BUM ARP parser selfcheck PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["--selfcheck"]:
        selfcheck()
    elif len(sys.argv) == 4:
        raise SystemExit(0 if single_reply(sys.stdin.read(), *sys.argv[1:]) else 1)
    else:
        raise SystemExit("usage: check_bum_arp.py TARGET SOURCE MAC | --selfcheck")

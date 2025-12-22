from __future__ import annotations

import time
from collections import defaultdict
from typing import List
from scapy.all import sniff, DHCP, Packet  # type: ignore

PER_MAC_THRESHOLD = 20       # DHCP DISCOVER per second per MAC
GLOBAL_THRESHOLD = 100       # DHCP DISCOVER per second across network
WINDOW = 5                   # seconds

discover_log = defaultdict(list)
global_log: List[float] = []


def dhcp_monitor(pkt: Packet) -> None:
    if not pkt.haslayer(DHCP):
        return

    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == 1:
            ts = time.time()
            mac = pkt.src

            discover_log[mac].append(ts)
            global_log.append(ts)

            cleanup(mac)
            check_mac(mac)
            check_global()
            break


def cleanup(mac: str) -> None:
    cutoff = time.time() - WINDOW

    discover_log[mac] = [t for t in discover_log[mac] if t >= cutoff]
    global global_log
    global_log = [t for t in global_log if t >= cutoff]


def check_mac(mac: str) -> None:
    events = len(discover_log[mac])
    rate = events / WINDOW

    if rate >= PER_MAC_THRESHOLD:
        print(f"[!] PER-MAC anomaly: {mac} -> {events} / {WINDOW}s (~{rate:.1f}/s)")
    else:
        print(f"[+] {mac}: {events} / {WINDOW}s (~{rate:.1f}/s)")


def check_global() -> None:
    events = len(global_log)
    rate = events / WINDOW

    if rate >= GLOBAL_THRESHOLD:
        print(f"[!] GLOBAL anomaly: {events} / {WINDOW}s (~{rate:.1f}/s)")


if __name__ == "__main__":
    print("DHCP Starvation detector running...")
    sniff(filter="udp and (port 67 or 68)", prn=dhcp_monitor, store=0)

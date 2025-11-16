from scapy.all import sniff, DHCP
from collections import defaultdict
import time

THRESHOLD_PER_SECOND = 20        #how much discover too much and sussy
OBSERVATION_WINDOW = 5           #per 5 last second

discover_log = defaultdict(list)

def dhcp_monitor(pkt):
    if pkt.haslayer(DHCP):
        options = pkt[DHCP].options

        # searching for "message-type: discover"
        for opt in options:
            if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == 1:
                timestamp = time.time()
                mac = pkt.src

                discover_log[mac].append(timestamp)
                cleanup_old_events(mac)

                check_anomaly(mac)
                break

def cleanup_old_events(mac):
    #cleaning our log list for relevant 
    cutoff = time.time() - OBSERVATION_WINDOW
    discover_log[mac] = [t for t in discover_log[mac] if t >= cutoff]

def check_anomaly(mac):
    events = len(discover_log[mac])

    if events >= THRESHOLD_PER_SECOND * OBSERVATION_WINDOW:
        print(f"WARNING Possible DHCP starvation attempt")
        print(f"MAC: {mac}, packets: {events} in last {OBSERVATION_WINDOW}")

    else:
        print(f"[INFO] DHCP Discover from {mac} (count={events})")

if __name__ == "__main__":
    print("Starting DHCP starvation detector...")
    sniff(filter="udp and (port 67 or port 68)", prn=dhcp_monitor, store=0)
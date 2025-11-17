from scapy.all import *
from scapy.layers.l2 import ARP
import os



def restore_arp(ip, mac) -> None:
	print(f"[INFO] Restoring ARP Entry for {ip} -> {mac}")
	os.system(f"arp -s {ip} {mac}")

def detect_arp_spoof(packet, ip, mac) -> None:
	if packet.haslayer(ARP) and packet[ARP].op == 2:
		sender_ip = packet[ARP].psrc
		sender_mac = packet[ARP].hwsrc

		if sender_ip == ip and sender_mac != mac:
			print(f"[ALERT] Detected ARP Spoofing! Router IP ({ip}) is being spoofed by {sender_mac}")
			restore_arp(ip, mac)



def monitor_arp(interface,ip, mac) -> None:
	print("[INFO] Starting ARP Spoofing Detection ... on" + interface)
	restore_arp(ip, mac)
	sniff(iface=interface, filter="arp", store=0, prn=lambda pkt: detect_arp_spoof(pkt, ip, mac))


if __name__ == "__main__":
	ROUTER_IP = ""
	ROUTER_MAC = ""
	interface = "eth0"
	try:
		monitor_arp(interface, ROUTER_IP, ROUTER_MAC)
	except KeyboardInterrupt:
		print("[INFO] Stopping ARP Spoof Protection script.")

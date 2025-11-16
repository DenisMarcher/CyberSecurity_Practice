# DHCP Starvation Lab (Kali Linux)

This repository contains a small educational lab demonstrating DHCP starvation traffic and a basic defensive detector.  
All tests were performed **only in an isolated environment**: Kali Linux attacker VM + victim device (Windows).

## Environment

- Run scripts in **Kali Linux** in a local, isolated test network (VirtualBox).
- For a clearer demonstration:
  - reboot the router (DHCP pool reset),
  - reconnect the victim device to the network.
- Test Devices: home router or test DHCP server + an other device on the same network.

## Usage (Concept)

1. Configure your Kali VM and victim machine in the same isolated LAN.
2. Start `dhcp_starvation.py` on Kali to generate DHCP Discover traffic.
3. In parallel, run `dhcp_starvation_detector.py` to observe:
   - DHCP Discover rate per MAC,
   - potential starvation-like behavior.

## Few words about Defence

DHCP starvation is **not a major threat** to corporate or managed networks due to common protections:

- **DHCP Snooping**
- **Port Security**
- **IP reservation pools / static bindings**
- **Network monitoring / rules**
- **MAC address limits per switch port**

## Disclamer Sequrity
- This lab is for **educational and defensive learning only**.
- Do **not** run these scripts on production networks, public Wi-Fi or any systems you do not own.

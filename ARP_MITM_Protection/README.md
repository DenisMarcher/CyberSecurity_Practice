This folder contains a small educational project demonstrating how to detect and block
ARP spoofing or ARP poisoning attempts commonly used in basic MITM attacks.  
All testing is performed **only inside an isolated virtual lab**  
(Kali Linux attacker VM + victim device+ gateway).

## What the Script Does
- Listens for ARP packets on the selected interface.
- Checks if any device is pretending to be the router (main gateway IP adress).
- If the MAC address does not match the legitimate router MAC:
  - Logs an alert,
  - Restores the correct ARP table entry using a static ARP binding.
  This protects the victim machine from basic **ARP spoofing / MITM attacks**

## Testing the Script
You can test the detection using **Ettercap** in MITM mode  

## Environment

- Run any Linux VM connected to the same test LAN.
- Router IP and router MAC must be filled in manually in the script.
- Interface name  must match your environment.
- This script is designed for **local lab demonstration**, not production use.

For **educational use only**, inside your own network. 

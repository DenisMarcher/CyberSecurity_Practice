This lab project demonstrates how DNS spoofing works inside a controlled
virtual environment (Kali attacker VM + Windows victim VM).

##  How to defend against DNS spoofing / tunneling
Understanding the attack helps understand how to protect against it.

Defensive measures:
- **DNS monitoring**: detect abnormal patterns or unexpected DNS responses.
- **DNSSEC**: cryptographically validates DNS responses.
- **Firewall filtering rules**: block forged DNS packets, unknown resolvers, or 
  unexpected outbound DNS queries.
- **Internal DNS hardening**: use authenticated DNS servers and secure forwarders.
- **Short TTL is risky** – lower TTL values make DNS records expire faster,
  increasing the number of DNS requests and making spoofing easier
- **Endpoint protection**: some modern systems reject conflicting
  DNS answers.

## Lab environment configuration notes
  To study packet redirection, the virtual lab environment needed to be set up:

- Enabling traffic redirection in **Ettercap's configuration file**  
  (cd /etc/ettercap -> sudo nano etter.conf).
- Uncommenting the IPv4 / IPv6 redirection lines inside the *Linux* section.
- Temporarily setting the following fields inside the `privs` section for lab use:
ec_uid = 0
ec_gid = 0
- Adding a custom redirection entry at the bottom of the file for the target test
domain
- DNS spoofing in this lab works **only for HTTP websites** because HTTPS uses
TLS certificates that prevent simple redirection.
- In real networks, devices may resolve DNS faster than the spoofing machine,
which makes spoofing unreliable or ineffective — this is expected behavior.

Pre made tools like Ettercap can perform DNS spoofing, but building the logic manually
using Scapy provides deeper understanding and just simply more intersting.

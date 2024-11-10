from scapy.all import DNS, DNSQR, IP, UDP, send
import time

def simulate_dns_query(target_domain, source_ip='192.168.1.16', dest_ip='8.8.8.8'):
    """
    Simulates a DNS query to a target domain.

    :param target_domain: The domain to query, such as a known safe malicious test domain.
    :param source_ip: Source IP for the simulated packet.
    :param dest_ip: Destination DNS server IP.
    """
    packet = IP(src=source_ip, dst=dest_ip) / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname=target_domain))
    send(packet)
    print(f"Sent DNS query for {target_domain} from {source_ip} to {dest_ip}")

# Define a known flagged test domain for simulation purposes
test_domain = "http://45.61.49.78/razor/r4z0r.mips"  # Safe test domain from URLHaus

# Simulate the DNS query
simulate_dns_query(test_domain)

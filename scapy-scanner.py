import argparse
import ipaddress
import random

from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, ICMP, sr1, send

'''
- Add arg passing
- If host doesn't exist, don't print it in the output
'''

parser = argparse.ArgumentParser(description="Simple network scan")

parser.add_argument(
    "-p",
    type=int,
    nargs="*",
    default=None,
    help="Ports to scan -- if none specified, will default to first 1000 ports"
)
parser.add_argument(
    "--hosts",
    type=str,
    nargs="+",
    required=True

)

args = parser.parse_args()

ports = args.p
hosts = args.hosts

if ports is None:
    ports = []
    for i in range(1000):
        ports.append(i)
for i in range(len(hosts)):
    try:
        network = ipaddress.ip_network(hosts[i], strict=False)
        print(f"Valid subnet {hosts[i]}")
        hosts.remove(hosts[i])
        for ip in network.hosts():
            hosts.append(str(ip))
    except ValueError:
        print("Invalid subnet")
    

print(f"Beginning scan on listed targets...")

responses = {}
for host in hosts:
    print(host)
    icmp = IP(dst=host) / ICMP()
    host_up = sr1(icmp, timeout=0.1, verbose=0)
    if host_up is not None:
        print("\tHost is up")
        responses[host] = []
        for port in ports:
            sport = random.randint(0, 65535)
            pkt = IP(dst=host) / TCP(sport=sport, dport=port, flags="S")
            pkt2 = IP(dst=host) / TCP(sport=sport, dport=port, flags="R")
            response = sr1(pkt, timeout=0.1, verbose=0)
            responses[host].append(response)
            send(pkt2, verbose=0)

for r in responses:
    print(f"\n{r}")
    count = 0
    for i in responses[r]:            
        if(i is not None and i.haslayer(TCP) and (str(i[TCP].flags) == 'SA')):
            print(f"\t{i[TCP].sport}")
        count += 1
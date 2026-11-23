import ipaddress
import random

from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, ICMP, sr, sr1, send

def parse_packets(answered, unanswered):
    results = []
    for sent, received in answered:
        if received.haslayer(TCP):
            results.append((received[TCP].sport, str(received[TCP].flags))) # add tuple (port, flag)
    return results

# Batches ports to be scanned and scans them
def init_pkts(host, ports, timeout):
    ports_per_batch = 5
    num_of_batches = (len(ports) + (ports_per_batch - 1)) // ports_per_batch
    batches = {} # Stores ports according to batch no
    packet_batches = {} # Init var to store full TCP packets according to the batch

    for i in range(num_of_batches):
        batches[i] = ports[i*5:(i+1)*5]
    
    return batches
            
def scan_batch(host, batch, timeout):    
    rst_packets = IP(dst=host) / TCP(sport=random.randint(1001, 65535), dport=batch, flags="R")
    packets = IP(dst=host) / TCP(sport=random.randint(1001, 65535), dport=batch, flags="S")
    answered, unanswered = sr(packets, timeout=timeout, verbose=0)
    send(rst_packets, verbose=0)
    return parse_packets(answered, unanswered) # func returns (port, flag)

def scan_host(host, ports, timeout):
    discovery_pkt = IP(dst=host) / ICMP()
    host_up = sr1(discovery_pkt, timeout=timeout, verbose=0)
    if host_up is not None:
        batches = init_pkts(host, ports, timeout)
        for batch_no in batches:
            # print(scan_batch(host, batches[batch_no], timeout))
            return host, scan_batch(host, batches[batch_no], timeout)

    else:
        return host, "is not up, or is blocking probes"

def init_scan(hosts, ports, sS, sT, sU, v, timeout):
    responses = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []

        for host in hosts:
            futures.append(executor.submit(scan_host, host, ports, timeout))
        
        for future in as_completed(futures):
            host, results = future.result()
            responses[host] = results
    
    return responses

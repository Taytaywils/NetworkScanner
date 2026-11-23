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
def init_batches(ports):
    ports_per_batch = 5
    num_of_batches = (len(ports) + (ports_per_batch - 1)) // ports_per_batch
    batches = {} # Stores ports according to batch no

    for i in range(num_of_batches):
        batches[i] = ports[i*5:(i+1)*5]
    
    return batches
            
def scan_batch(host, batch, timeout):    
    rst_packets = IP(dst=host) / TCP(sport=random.randint(1001, 65535), dport=batch, flags="R")
    packets = IP(dst=host) / TCP(sport=random.randint(1001, 65535), dport=batch, flags="S")
    answered, unanswered = sr(packets, timeout=timeout, verbose=0)
    send(rst_packets, verbose=0)
    return host, parse_packets(answered, unanswered) # func returns (port, flag)

def scan_host(host, timeout):
    discovery_pkt = IP(dst=host) / ICMP()
    host_up = sr1(discovery_pkt, timeout=timeout, verbose=0)
    if host_up is not None:
        return host
    
    return None

def init_scan(hosts, ports, sS, sT, sU, v, timeout):
    responses = {}
    with ThreadPoolExecutor(max_workers=30) as executor:
        host_futures = {}

        for host in hosts:
            future = executor.submit(scan_host, host, timeout)
            host_futures[future] = host

        active_hosts = []

        for future in as_completed(host_futures):
            host = future.result()

            if host is not None:
                active_hosts.append(host)

        batch_futures = {}
        
        for host in active_hosts:
            responses[host] = []
            batches = init_batches(ports)
            
            for batch_no in batches:
                future = executor.submit(scan_batch, host, batches[batch_no], timeout)
                batch_futures[future] = host

        for future in as_completed(batch_futures):
            host, results = future.result()
            responses[host].extend(results)

    return responses

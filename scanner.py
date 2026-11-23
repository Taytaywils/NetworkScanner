import socket as s
from scapy.all import IP, TCP, send

hosts = ['172.19.0.1', '192.168.0.215', '192.168.0.204']
ports = [80, 443, 22, 8006]
def scan_tcp(hosts, ports):
    scanned_hosts = []
    for host in hosts:
        for port in ports:
            # Open socket
            with s.socket(s.AF_INET, s.SOCK_RAW, s.IPPROTO_RAW) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))

                if result == 0:
                    scanned_hosts.append((host, True))
                else:
                    scanned_hosts.append((host, False))

                pkt = IP(src="172.19.0.8", dst=host)/TCP(dport=port)
                pkt.show()
                try:
                    sock.sendall(pkt)
                    received = sock.recvmsg(512)
                    print(received)
                except Exception as e:
                    print(e)

    return scanned_hosts

if __name__ == "__main__":
    results = scan_tcp(hosts, ports)
    
    for r in results:
        print(r)


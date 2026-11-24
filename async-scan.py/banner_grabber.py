import socket as s

host = "192.168.0.204"
port = 80
def grab_banner(host, port):
    with s.socket(s.AF_INET, s.SOCK_STREAM) as sock:
            sock.connect((host, port))

print(f"Banner: {grab_banner(host, port)}")
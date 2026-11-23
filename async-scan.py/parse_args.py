import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Asyncronous network scanner built on python")

    parser.add_argument(
        "hosts",
        nargs="+",
        help="Specify hosts you want to scan as individual IPs or a subnet in CIDR notation."
    )
    parser.add_argument(
        "-p", "--ports",
        nargs="*",
        default=None,
        # type=int,
        help="Specify ports to scan -- if not specified, will default to first 1000 ports"
    )

    parser.add_argument(
        "-sS",
        action="store_true",
        help="Enable SYN scan"
    )

    parser.add_argument(
        "-sT",
        action="store_true",
        help="Enable full TCP connect scan"
    )

    parser.add_argument(
        "-sU",
        action="store_true",
        help="Enable UDP scan"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose mode"
    )

    parser.add_argument(
        "--timeout",
        default=0.1,
        type=float
    )

    args = parser.parse_args()
    if args.ports is None:
        args.ports=[]
        for i in range(1000):
            args.ports.append(i + 1)
    else:
        temp_list = []
        
        for port in args.ports:
            if "-" in port:
                temp_port = port.split("-")
                temp_list.extend(str(i) for i in range(int(temp_port[0]), int(temp_port[1]) + 1))
            elif "," in port:
                temp_port = port.split(",")
                temp_list.extend(i for i in temp_port)
            else:
                temp_list.append(port)
        args.ports = []
        for port in temp_list:
            args.ports.append(int(port))
            
    return args
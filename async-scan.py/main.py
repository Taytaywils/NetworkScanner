
from format_responses import format_responses
from parse_args import parse_args
from scan import init_scan
# import format_responses

args = parse_args()
responses = init_scan(args.hosts, args.ports, args.sS, args.sT, args.sU, args.verbose, args.timeout)

format_responses(responses)
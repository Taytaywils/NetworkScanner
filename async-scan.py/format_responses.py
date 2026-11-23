


def format_responses(responses):
    for host in responses:
        print(host)
        sorted_results = sorted(responses[host], key=lambda x: x[0])
        for port, flag in sorted_results:
            if flag == 'SA':
                print(f"\t{port}: OPEN")
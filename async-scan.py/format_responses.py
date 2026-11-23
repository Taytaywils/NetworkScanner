


def format_responses(responses):
    for response in responses:
        if type(responses[response]) is not str:
            print(response)
            for t in responses[response]:
                for port, flag in t:
                    if flag == 'SA':
                        print(f"\t{port}: Open")
        else:
            print(f"{response} {responses[response]}")
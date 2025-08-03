# Only used to import csv data - not during runtime

import csv
import json


def main():
    ans = {}
    with open('service-names-port-numbers.csv', 'r') as f:
        data = csv.reader(f)
        services = csv_to_dict(data)
    for service in services:
        if service['Service Name'] and service['Port Number']:
            try:
                ans[service['Port Number']] = service['Service Name']
            except BaseException:
                pass
    with open('valid_ports.json', 'w') as f:
        json.dump(ans, f, indent=2)


def csv_to_dict(data):
    """
    Convert a CSV file to a dictionary.
    """
    header = next(data)
    return [dict(zip(header, row)) for row in data]


main()

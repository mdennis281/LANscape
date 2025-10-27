"""
CSV to JSON converter for port service mappings.
Converts IANA service-names-port-numbers CSV file to a simplified JSON format
for use in the LANscape application. Only used during development, not at runtime.
"""

import csv
import json


def main():
    """
    Main function to convert CSV port data to a JSON mapping.

    Reads port information from a CSV file, processes it to extract port numbers
    and service names, and writes the resulting mapping to a JSON file.
    """
    ans = {}
    with open('service-names-port-numbers.csv', 'r', encoding='utf-8') as f:
        data = csv.reader(f)
        services = csv_to_dict(data)
    for service in services:
        if service['Service Name'] and service['Port Number']:
            try:
                ans[service['Port Number']] = service['Service Name']
            except BaseException:
                pass
    with open('valid_ports.json', 'w', encoding='utf-8') as f:
        json.dump(ans, f, indent=2)


def csv_to_dict(data):
    """
    Convert a CSV file to a dictionary.
    """
    header = next(data)
    return [dict(zip(header, row)) for row in data]


main()

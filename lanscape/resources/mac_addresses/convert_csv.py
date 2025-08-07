"""
CSV to JSON converter for MAC address vendor mappings.
Processes vendor MAC address prefix data from CSV format to a simplified JSON lookup table
for use in the LANscape application. Only used during development, not at runtime.
"""

import csv
import json


def main():
    """
    Main function to convert CSV MAC vendor data to a JSON mapping.

    Reads MAC vendor information from a CSV file, processes it to extract
    MAC address prefixes and vendor names, and writes the resulting mapping
    to a JSON file for efficient lookup.
    """
    ans = {}
    with open('mac-vendors-export.csv', 'r', encoding='utf-8') as f:
        data = csv.reader(f)
        services = csv_to_dict(data)
    for service in services:
        if service['Vendor Name'] and service['Mac Prefix']:
            try:
                ans[service['Mac Prefix']] = service['Vendor Name']
            except BaseException:
                pass
    with open('mac_db.json', 'w', encoding='utf-8') as f:
        json.dump(ans, f, indent=2)


def csv_to_dict(data):
    """
    Convert a CSV file to a dictionary.
    """
    header = next(data)
    return [dict(zip(header, row)) for row in data]


main()

# Only used to import csv data - not during runtime

import csv
import json


def main():
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
    with open('mac_db.json', 'w') as f:
        json.dump(ans, f, indent=2)


def csv_to_dict(data):
    """
    Convert a CSV file to a dictionary.
    """
    header = next(data)
    return [dict(zip(header, row)) for row in data]


main()

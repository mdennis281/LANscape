import ipaddress
import re

def parse_ip_input(ip_input):
    # Split input on commas for multiple entries
    entries = [entry.strip() for entry in ip_input.split(',')]
    ip_ranges = []

    for entry in entries:
        # Handle CIDR notation or IP/32
        if '/' in entry:
            ip_ranges.append(ipaddress.IPv4Network(entry, strict=False))
        
        # Handle IP range (e.g., 10.0.0.15-10.0.0.25)
        elif '-' in entry:
            ip_ranges += parse_ip_range(entry)
        
        # Handle shorthand IP range (e.g., 10.0.9.1-253)
        elif re.search(r'\d+\-\d+', entry):
            ip_ranges += parse_shorthand_ip_range(entry)

        # If no CIDR or range, assume a single IP
        else:
            ip_ranges.append(ipaddress.IPv4Address(entry))

    return ip_ranges

def parse_ip_range(entry):
    start_ip, end_ip = entry.split('-')
    start_ip = ipaddress.IPv4Address(start_ip.strip())
    
    # Handle case where the second part is a partial IP (e.g., '253')
    if '.' not in end_ip:
        end_ip = start_ip.exploded.rsplit('.', 1)[0] + '.' + end_ip.strip()
    
    end_ip = ipaddress.IPv4Address(end_ip.strip())
    return list(ip_range_to_list(start_ip, end_ip))

def parse_shorthand_ip_range(entry):
    start_ip, end_part = entry.split('-')
    start_ip = ipaddress.IPv4Address(start_ip.strip())
    end_ip = start_ip.exploded.rsplit('.', 1)[0] + '.' + end_part.strip()
    
    return list(ip_range_to_list(start_ip, ipaddress.IPv4Address(end_ip)))

def ip_range_to_list(start_ip, end_ip):
    # Yield the range of IPs
    for ip_int in range(int(start_ip), int(end_ip) + 1):
        yield ipaddress.IPv4Address(ip_int)
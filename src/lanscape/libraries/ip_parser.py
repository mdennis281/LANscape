import ipaddress
import re

MAX_IPS_ALLOWED = 10000 

def parse_ip_input(ip_input):
    # Split input on commas for multiple entries
    entries = [entry.strip() for entry in ip_input.split(',')]
    ip_ranges = []

    for entry in entries:
        # Handle CIDR notation or IP/32
        if '/' in entry:
            net = ipaddress.IPv4Network(entry,strict=False)
            if net.num_addresses > MAX_IPS_ALLOWED:
                raise SubnetTooLargeError(ip_input)
            for ip in net.hosts():
                ip_ranges.append(ip) 
        
        # Handle IP range (e.g., 10.0.0.15-10.0.0.25)
        elif '-' in entry:
            ip_ranges += parse_ip_range(entry)
        
        # Handle shorthand IP range (e.g., 10.0.9.1-253)
        elif re.search(r'\d+\-\d+', entry):
            ip_ranges += parse_shorthand_ip_range(entry)

        # If no CIDR or range, assume a single IP
        else:
            ip_ranges.append(ipaddress.IPv4Address(entry,strict=False))
        if len(ip_ranges) > MAX_IPS_ALLOWED:
            raise SubnetTooLargeError(ip_input)
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


class SubnetTooLargeError(Exception):
    """Custom exception raised when the subnet size exceeds the allowed limit."""
    def __init__(self, subnet, max_ips=MAX_IPS_ALLOWED):
        self.subnet = subnet
        self.max_ips = max_ips
        super().__init__(f"Subnet {subnet} exceeds the limit of {max_ips} IP addresses.")
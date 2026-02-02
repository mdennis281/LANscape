#!/usr/bin/env python3
"""
Service Scan Analysis Script

Runs an aggressive service scan on a subnet and collects detailed data
about service identification results to help improve the service scanning logic.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Add parent dir to path for lanscape imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lanscape import (  # noqa: E402  # pylint: disable=wrong-import-position,wrong-import-order
    ScanManager,
    ScanConfig,
    ScanType,
    ServiceScanConfig,
    ServiceScanStrategy,
    PortManager
)


def get_available_port_lists() -> List[str]:
    """Get all available port list names."""
    pm = PortManager()
    return pm.get_port_lists()


def run_scan(subnet: str, port_list: str = 'large') -> Dict[str, Any]:
    """
    Run a network scan with aggressive service scanning.

    Args:
        subnet: The subnet to scan (e.g., '10.0.4.0/22')
        port_list: Name of port list to use

    Returns:
        Dict containing scan results and analysis
    """
    print(f"\n{'=' * 60}")
    print("Service Scan Analysis")
    print(f"{'=' * 60}")
    print(f"Subnet: {subnet}")
    print(f"Port List: {port_list}")
    print("Strategy: AGGRESSIVE")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"{'=' * 60}\n")

    # Configure aggressive service scanning
    service_cfg = ServiceScanConfig(
        timeout=8.0,  # Longer timeout for better results
        lookup_type=ServiceScanStrategy.AGGRESSIVE,
        max_concurrent_probes=15
    )

    cfg = ScanConfig(
        subnet=subnet,
        port_list=port_list,
        lookup_type=[ScanType.ICMP_THEN_ARP],
        service_scan_config=service_cfg
    )

    print(f"Port list has {len(cfg.get_ports())} ports")
    print("Scanning...")

    sm = ScanManager()
    try:
        scan = sm.new_scan(cfg)
        scan.debug_active_scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        scan.terminate()

    return analyze_results(scan.results)


def analyze_results(results) -> Dict[str, Any]:  # pylint: disable=too-many-branches,too-many-statements
    """
    Analyze scan results and extract service scanning insights.

    Args:
        results: ScanResults object from the scan

    Returns:
        Dict containing analysis data
    """
    analysis = {
        'timestamp': datetime.now().isoformat(),
        'total_devices': len(results.devices),
        'devices_with_ports': 0,
        'total_open_ports': 0,
        'service_counts': defaultdict(int),
        'services_by_port': defaultdict(lambda: defaultdict(int)),
        'unknown_responses': [],
        'tls_detected': [],
        'response_patterns': defaultdict(list),
        'request_response_pairs': [],
    }

    for device in results.devices:
        if not device.ports:
            continue

        analysis['devices_with_ports'] += 1
        analysis['total_open_ports'] += len(device.ports)

        for svc_info in device.service_info:
            port = svc_info.port
            service = svc_info.service
            response = svc_info.response
            request = svc_info.request
            is_tls = getattr(svc_info, 'is_tls', False)

            # Count services
            analysis['service_counts'][service] += 1
            analysis['services_by_port'][port][service] += 1

            # Track TLS
            if is_tls:
                analysis['tls_detected'].append({
                    'ip': device.ip,
                    'port': port,
                    'service': service,
                    'response_snippet': response[:200] if response else None
                })

            # Collect unknown responses for analysis
            if service == 'Unknown' and response:
                analysis['unknown_responses'].append({
                    'ip': device.ip,
                    'port': port,
                    'response': response,
                    'request': request,
                    'response_length': len(response)
                })

            # Track request/response pairs for learning
            if response:
                analysis['request_response_pairs'].append({
                    'ip': device.ip,
                    'port': port,
                    'service': service,
                    'request': request,
                    'response_snippet': response[:300] if len(response) > 300 else response,
                    'is_tls': is_tls
                })

                # Look for patterns in responses
                response_lower = response.lower()
                patterns = extract_patterns(response_lower)
                if patterns:
                    analysis['response_patterns'][service].append({
                        'port': port,
                        'patterns': patterns
                    })

    # Convert defaultdicts to regular dicts for JSON serialization
    analysis['service_counts'] = dict(analysis['service_counts'])
    analysis['services_by_port'] = {
        k: dict(v) for k, v in analysis['services_by_port'].items()
    }
    analysis['response_patterns'] = dict(analysis['response_patterns'])

    return analysis


def extract_patterns(response: str) -> List[str]:  # pylint: disable=too-many-branches,too-many-statements
    """
    Extract interesting patterns from a response for learning.

    Args:
        response: The response text (lowercase)

    Returns:
        List of identified patterns
    """
    patterns = []

    # HTTP patterns
    if 'http/' in response:
        patterns.append('http-version')
    if 'server:' in response:
        patterns.append('server-header')
    if 'content-type:' in response:
        patterns.append('content-type')
    if 'application/json' in response:
        patterns.append('json-api')
    if 'x-powered-by:' in response:
        patterns.append('x-powered-by')

    # Protocol banners
    if 'ssh-' in response:
        patterns.append('ssh-banner')
    if 'ftp' in response:
        patterns.append('ftp')
    if 'smtp' in response or '220 ' in response:
        patterns.append('smtp-banner')
    if '+ok' in response:
        patterns.append('pop3')
    if '* ok' in response:
        patterns.append('imap')

    # Databases
    if 'mysql' in response or 'mariadb' in response:
        patterns.append('mysql')
    if 'postgresql' in response or 'postgres' in response:
        patterns.append('postgresql')
    if 'redis' in response or '+pong' in response:
        patterns.append('redis')
    if 'mongodb' in response:
        patterns.append('mongodb')

    # Web servers
    if 'nginx' in response:
        patterns.append('nginx')
    if 'apache' in response:
        patterns.append('apache')
    if 'iis' in response:
        patterns.append('iis')
    if 'lighttpd' in response:
        patterns.append('lighttpd')

    # Security/TLS
    if '\\x15\\x03' in response or '\\x16\\x03' in response:
        patterns.append('tls-binary')
    if 'certificate' in response:
        patterns.append('certificate')
    if 'ssl' in response:
        patterns.append('ssl')

    # Messaging/Streaming
    if 'websocket' in response:
        patterns.append('websocket')
    if 'mqtt' in response:
        patterns.append('mqtt')
    if 'amqp' in response or 'rabbitmq' in response:
        patterns.append('amqp')

    # Other services
    if 'minecraft' in response:
        patterns.append('minecraft')
    if 'rtsp' in response:
        patterns.append('rtsp')
    if 'sip' in response:
        patterns.append('sip')
    if 'upnp' in response or 'ssdp' in response:
        patterns.append('upnp')

    return patterns


def print_analysis(analysis: Dict[str, Any]):
    """Print analysis results to console."""
    print(f"\n{'=' * 60}")
    print("SCAN ANALYSIS RESULTS")
    print(f"{'=' * 60}\n")

    print(f"Total devices found: {analysis['total_devices']}")
    print(f"Devices with open ports: {analysis['devices_with_ports']}")
    print(f"Total open ports: {analysis['total_open_ports']}")

    print("\n--- SERVICE IDENTIFICATION ---")
    for service, count in sorted(analysis['service_counts'].items(),
                                 key=lambda x: x[1], reverse=True):
        print(f"  {service}: {count}")

    if analysis['tls_detected']:
        print(f"\n--- TLS DETECTED ({len(analysis['tls_detected'])} ports) ---")
        for item in analysis['tls_detected'][:10]:
            print(f"  {item['ip']}:{item['port']} -> {item['service']}")

    if analysis['unknown_responses']:
        print(f"\n--- UNKNOWN RESPONSES ({len(analysis['unknown_responses'])} total) ---")
        print("(First 10 shown)")
        for item in analysis['unknown_responses'][:10]:
            resp_preview = item['response'][:100].replace('\n', '\\n')
            print(f"\n  {item['ip']}:{item['port']}")
            print(f"    Request: {item['request']}")
            print(f"    Response: {resp_preview}...")

    # Analyze patterns in unknown responses
    unknown_patterns = defaultdict(int)
    for item in analysis['unknown_responses']:
        patterns = extract_patterns(item['response'].lower())
        for p in patterns:
            unknown_patterns[p] += 1

    if unknown_patterns:
        print("\n--- PATTERNS IN UNKNOWN RESPONSES ---")
        for pattern, count in sorted(unknown_patterns.items(),
                                     key=lambda x: x[1], reverse=True):
            print(f"  {pattern}: {count}")

    # Port-to-service mapping insights
    print("\n--- PORT TO SERVICE MAPPING ---")
    for port, services in sorted(analysis['services_by_port'].items()):
        if len(services) > 1 or 'Unknown' in services:
            service_str = ', '.join(f"{s}({c})" for s, c in services.items())
            print(f"  Port {port}: {service_str}")


def save_analysis(analysis: Dict[str, Any], filename: str = None):
    """Save analysis to JSON file."""
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"service_analysis_{timestamp}.json"

    output_path = Path(__file__).parent / filename

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, default=str)

    print(f"\nAnalysis saved to: {output_path}")
    return output_path


def main():
    """Main entry point."""
    # Default values
    subnet = '10.0.4.0/22'
    port_list = 'large'

    # Parse command line args
    if len(sys.argv) > 1:
        subnet = sys.argv[1]
    if len(sys.argv) > 2:
        port_list = sys.argv[2]

    # Show available port lists
    available = get_available_port_lists()
    print(f"Available port lists: {', '.join(available)}")

    if port_list not in available:
        print(f"Error: Port list '{port_list}' not found")
        print(f"Available: {available}")
        sys.exit(1)

    # Run the scan
    analysis = run_scan(subnet, port_list)

    # Print and save results
    print_analysis(analysis)
    save_analysis(analysis)

    return analysis


if __name__ == '__main__':
    main()

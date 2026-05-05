"""DHCP listener usage examples.

Run with elevated privileges:
    sudo python examples/dhcp_example.py
    # or on Windows (in an admin terminal):
    python examples/dhcp_example.py
"""

from __future__ import annotations

import signal
import sys

from lanscape.core.dhcp_listener import DhcpFilter, DhcpListener, DhcpMessageType


# ── Example 1: Simplest possible — print everything ─────────────────────────

def watch_all():
    """Print a one-line summary for every DHCP packet on the LAN."""
    print("Listening for DHCP traffic on all interfaces (Ctrl-C to stop)…\n")

    with DhcpListener() as listener:
        for event in listener:
            print(event.summary())


# ── Example 2: Filter to a specific subnet ───────────────────────────────────

def watch_subnet(subnet: str = "192.168.1.0/24"):
    """Only show events whose effective IP falls within *subnet*."""
    print(f"Filtering to subnet {subnet}\n")

    dhcp_filter = DhcpFilter(subnets=[subnet])
    with DhcpListener(dhcp_filter=dhcp_filter) as listener:
        for event in listener:
            print(event.summary())


# ── Example 3: Callback-driven with transaction correlation ──────────────────

def watch_with_transactions():
    """Print each event AND a full transaction summary when ACK/NAK is received."""

    def on_event(event):
        # Coloured output: client=cyan, server=yellow
        colour = '\033[96m' if event.direction == 'client' else '\033[93m'
        reset  = '\033[0m'
        print(f"  {colour}{event.summary()}{reset}")

    def on_complete(tx):
        print(f"\n{'─'*70}")
        print(f"  TRANSACTION COMPLETE: {tx.summary()}")
        if tx.events:
            last = tx.events[-1]
            if last.routers:
                print(f"  Gateway  : {', '.join(last.routers)}")
            if last.dns_servers:
                print(f"  DNS      : {', '.join(last.dns_servers)}")
            if last.lease_time:
                hours, rem = divmod(last.lease_time, 3600)
                mins,  sec = divmod(rem, 60)
                print(f"  Lease    : {hours}h {mins}m {sec}s")
        print(f"{'─'*70}\n")

    listener = DhcpListener(
        on_event=on_event,
        on_transaction_complete=on_complete,
    )

    def _shutdown(*_):
        print("\nStopping…")
        listener.stop()

    signal.signal(signal.SIGINT, _shutdown)

    listener.start()
    print("Listening for DHCP traffic (Ctrl-C to stop)…\n")

    # Block the main thread until Ctrl-C triggers stop()
    while listener.running:
        signal.pause() if hasattr(signal, 'pause') else __import__('time').sleep(0.5)


# ── Example 4: Forensic dump — capture for N seconds then inspect ────────────

def forensic_capture(duration: float = 30.0):
    """Capture DHCP traffic for *duration* seconds, then print a full report."""
    print(f"Capturing for {duration:.0f} seconds…")

    events = []
    with DhcpListener() as listener:
        for event in listener.events(timeout=duration):
            events.append(event)

    print(f"\nCaptured {len(events)} DHCP event(s):\n")
    for event in events:
        print(f"  {event.summary()}")

    transactions = {}
    for e in events:
        if e.xid not in transactions:
            transactions[e.xid] = []
        transactions[e.xid].append(e)

    print(f"\n{len(transactions)} unique transaction(s):\n")
    for xid, evts in transactions.items():
        flow = ' → '.join(e.message_type.name for e in evts)
        macs = {e.client_mac for e in evts}
        print(f"  xid={xid:#010x}  mac={next(iter(macs))}  flow={flow}")


# ── Example 5: Watch for rogue DHCP servers ──────────────────────────────────

def watch_for_rogue_servers(known_server: str = "192.168.1.1"):
    """Alert when DHCP OFFERs or ACKs come from an unexpected server."""
    print(f"Watching for rogue DHCP servers (known: {known_server})…\n")

    rogue_filter = DhcpFilter(
        message_types=[DhcpMessageType.OFFER, DhcpMessageType.ACK],
    )
    with DhcpListener(dhcp_filter=rogue_filter) as listener:
        for event in listener:
            if event.server_identifier and event.server_identifier != known_server:
                print(f"\033[91m[ROGUE SERVER DETECTED]\033[0m {event.summary()}")
            else:
                print(event.summary())


if __name__ == '__main__':
    examples = {
        '1': watch_all,
        '2': watch_subnet,
        '3': watch_with_transactions,
        '4': forensic_capture,
        '5': watch_for_rogue_servers,
    }

    choice = sys.argv[1] if len(sys.argv) > 1 else '1'
    fn = examples.get(choice)
    if fn is None:
        print(f"Unknown example {choice!r}. Choose from: {list(examples)}")
        sys.exit(1)

    fn()

## What is ARP (Address Resolution Protocol)
ARP (Address Resolution Protocol) is a network protocol used to map an IP address to a physical machine address (MAC address) on a local area network. When a device wants to communicate with another device on the same network, it uses ARP to discover the MAC address associated with the target IP address. This process enables devices to send data to the correct hardware on the network.

## Why do we use it?
While tools like `ping` can be used to check if a device is reachable on the network, they rely on the target device responding to ICMP echo requests. Devices can be configured to ignore or block these requests, making `ping` an unreliable method for discovering devices or their addresses. ARP, on the other hand, operates at a lower level and is necessary for actual data transmission, regardless of whether a device responds to `ping`. This makes ARP a more reliable mechanism for mapping IP addresses to MAC addresses on a local network.

## Getting it working (Mac/Linux)
Unfortunately the only known solution to get python Scapy (ARP lookup library) working on unix machines is to run the program as root. If you aren't comfortable with this, there is a ping mechanism used as a backup in the code that will be invoked on a failed ARP lookup.

## Getting it working (Windows)
Windows doesn't need any special elevation, but it does need a dependency installed on your computer
[npcap download](https://npcap.com/#download)
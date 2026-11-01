# net-vlan-discovery
Discovers VLAN IDs being used on a network segment by sending tagged frames and analyzing responses. Useful for network mapping and identifying potential VLAN hopping vulnerabilities. - Focused on Basic network operations

## Install
`git clone https://github.com/ShadowGuardAI/net-vlan-discovery`

Install the requirements with `pip install -r requirements.txt`. The ARP resolution path (used when `--dst-mac` is not supplied) requires scapy, named in requirements.txt. Supplying `--dst-mac` avoids that path. The rest of the tool uses only the Python standard library.

## Usage
`python3 main.py -i <interface> -t <target> [params]`

Example: `python3 main.py -i eth0 -t 192.168.1.10 -v 1-100 -d aa:bb:cc:dd:ee:ff`

## How a VLAN is judged active
A VLAN is logged as likely active only when a received packet matches the probe: it is a TCP packet whose source address is the target, whose source port is the probed port, and whose flags carry a SYN reply (SYN and ACK set). Unrelated traffic received during the wait is ignored and does not mark a VLAN active.

## Source IP address
The crafted packets carry the source IP given with `--src-ip` when that argument is supplied. Otherwise the address assigned to the named interface is used, and the scan exits with an error if no address can be read from the interface.

## Parameters
- `-h`: Show help message and exit
- `-i, --interface`: Network interface to use for sending packets (e.g., eth0, wlan0). Required.
- `-t, --target`: Target IP address on the network segment. Required.
- `-v, --vlan-range`: VLAN ID range to scan (e.g., 1-100, 1000-2000). Default: 1-4094
- `-p, --port`: Destination port to send packets to. Default: 80
- `-s, --src-mac`: Source MAC address (optional). If not provided, it will be retrieved from the interface.
- `-d, --dst-mac`: Destination MAC address (optional). If not provided, it will be resolved via ARP, which requires scapy.
- `--timeout`: Timeout in seconds for receiving responses. Default: 2.0
- `--arp-timeout`: Timeout in seconds for ARP resolution. Default: 1.0
- `--payload`: Payload of the packet sent.
- `--src-ip`: Source IP address for the crafted packets. If not provided, the address assigned to the interface is used.

## Exit status
At the end of a scan the tool prints a closing summary counting the probes sent, answered, and failed. The run exits with status 1 when every probe failed to send. A scan that sent at least one probe exits with status 0, including a scan that found no active VLAN.

## License
Copyright (c) ShadowGuardAI

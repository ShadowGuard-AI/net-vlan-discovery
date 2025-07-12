# net-vlan-discovery
Discovers VLAN IDs being used on a network segment by sending tagged frames and analyzing responses. Useful for network mapping and identifying potential VLAN hopping vulnerabilities. - Focused on Basic network operations

## Install
`git clone https://github.com/ShadowGuardAI/net-vlan-discovery`

## Usage
`./net-vlan-discovery [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: No description provided
- `-t`: Target IP address on the network segment.
- `-v`: No description provided
- `-p`: Destination port to send packets to. Default: 80
- `-s`: No description provided
- `-d`: No description provided
- `--timeout`: Timeout in seconds for receiving responses. Default: 2.0
- `--arp-timeout`: Timeout in seconds for ARP resolution. Default: 1.0
- `--payload`: Payload of the packet sent.

## License
Copyright (c) ShadowGuardAI

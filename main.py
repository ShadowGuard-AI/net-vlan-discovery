import socket
import argparse
import logging
import struct
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the VLAN discovery tool.
    """
    parser = argparse.ArgumentParser(description="Discovers VLAN IDs on a network segment.")
    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="Network interface to use for sending packets (e.g., eth0, wlan0).")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address on the network segment.")
    parser.add_argument("-v", "--vlan-range", dest="vlan_range", default="1-4094",
                        help="VLAN ID range to scan (e.g., 1-100, 1000-2000).  Default: 1-4094")
    parser.add_argument("-p", "--port", dest="port", type=int, default=80,
                        help="Destination port to send packets to. Default: 80")
    parser.add_argument("-s", "--src-mac", dest="src_mac",
                        help="Source MAC address (optional). If not provided, it will be retrieved from the interface.")
    parser.add_argument("-d", "--dst-mac", dest="dst_mac",
                        help="Destination MAC address (optional). If not provided, it will be resolved via ARP.")
    parser.add_argument("--timeout", dest="timeout", type=float, default=2.0,
                        help="Timeout in seconds for receiving responses. Default: 2.0")
    parser.add_argument("--arp-timeout", dest="arp_timeout", type=float, default=1.0,
                        help="Timeout in seconds for ARP resolution. Default: 1.0")  # ARP resolution timeout
    parser.add_argument("--payload", dest="payload", default="VLAN Discovery Probe",
                        help="Payload of the packet sent.")  # Customizable payload
    parser.add_argument("--src-ip", dest="src_ip",
                        help="Source IP address for the crafted packets. If not provided, the address assigned to the interface is used.")
    return parser.parse_args()


def get_mac_address(interface):
    """
    Retrieves the MAC address of a given network interface.
    Args:
        interface (str): The name of the network interface.
    Returns:
        str: The MAC address of the interface, or None if an error occurs.
    """
    try:
        import fcntl
        import struct

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(interface, 'utf-8')[:15]))
        return ':'.join('%02x' % b for b in info[18:24])
    except Exception as e:
        logging.error(f"Error getting MAC address for {interface}: {e}")
        return None


def get_ip_address(interface):
    """
    Retrieves the IPv4 address assigned to a given network interface.
    Args:
        interface (str): The name of the network interface.
    Returns:
        str: The IPv4 address of the interface, or None if an error occurs.
    """
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes(interface, 'utf-8')[:15]))
        return socket.inet_ntoa(info[20:24])
    except Exception as e:
        logging.error(f"Error getting IP address for {interface}: {e}")
        return None


def resolve_mac_address(ip_address, interface, timeout=1.0):
    """
    Resolves the MAC address of a given IP address using ARP.
    Args:
        ip_address (str): The IP address to resolve.
        interface (str): The network interface to use for ARP requests.
        timeout (float): The timeout in seconds for ARP resolution.
    Returns:
        str: The MAC address corresponding to the IP address, or None if resolution fails.
    """
    try:
        import scapy.all as scapy
        arp_request = scapy.ARP(pdst=ip_address)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp_request
        answered_list = scapy.srp(packet, iface=interface, timeout=timeout, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            logging.warning(f"ARP resolution failed for {ip_address}")
            return None
    except ImportError:
        logging.error("Scapy is not installed. Please install it to use ARP resolution.")
        return None
    except Exception as e:
        logging.error(f"Error resolving MAC address for {ip_address}: {e}")
        return None


def craft_vlan_packet(src_mac, dst_mac, vlan_id, target_ip, target_port, payload, src_ip=None):
    """
    Crafts an Ethernet frame with a VLAN tag and a TCP payload.
    Args:
        src_mac (str): The source MAC address.
        dst_mac (str): The destination MAC address.
        vlan_id (int): The VLAN ID to include in the tag.
        target_ip (str): The target IP address.
        target_port (int): The target port.
        payload (str): The payload to send.
    Returns:
        bytes: The crafted Ethernet frame as bytes.
    """
    try:
        # Ethernet header
        eth_dst = bytes.fromhex(dst_mac.replace(':', ''))
        eth_src = bytes.fromhex(src_mac.replace(':', ''))
        eth_type = 0x8100  # 802.1Q VLAN
        eth_header = struct.pack('!6s6sH', eth_dst, eth_src, eth_type)

        # 802.1Q VLAN header
        # Masking to 12 bits throws the priority and drop eligible bits away. This probe only
        # ever tests plain VLAN membership, never the QoS side of the tag.
        vlan_tci = vlan_id & 0x0FFF  # VLAN ID, 12 bits
        vlan_tpid = 0x0800  # IP Protocol
        vlan_header = struct.pack('!HH', vlan_tci, vlan_tpid)

        # IP Header (Minimal, assuming default values are acceptable)
        ip_version = 4
        ip_ihl = 5  # Minimum header length
        ip_tos = 0
        ip_length = 20 + 20 + len(payload.encode())  # IP header length + TCP header length + payload length
        ip_id = 12345  # Dummy ID
        ip_flags = 0
        ip_frag_offset = 0
        ip_ttl = 64  # Time to live
        ip_protocol = 6  # TCP
        ip_checksum = 0  # Will be calculated later, placeholder
        # Source IP: the --src-ip value when given, otherwise the address
        # assigned to the sending interface (resolved by the caller).
        ip_src = socket.inet_aton(src_ip) if src_ip else socket.inet_aton("127.0.0.1")
        ip_dst = socket.inet_aton(target_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                 (ip_version << 4) | ip_ihl, ip_tos, ip_length, ip_id,
                                 (ip_flags << 13) | ip_frag_offset, ip_ttl, ip_protocol,
                                 ip_checksum, ip_src, ip_dst)

        # TCP Header (Minimal, assuming default values are acceptable)
        # Source port and sequence are the same fixed values on every VLAN I probe. Replies are
        # matched without either, so the numbers only matter to the target, not to my matching.
        tcp_src_port = 12345  # Dummy source port
        tcp_dst_port = target_port
        tcp_seq_num = 0
        tcp_ack_num = 0
        tcp_data_offset = 5  # Minimum header length
        tcp_flags = 0x002  # SYN flag
        tcp_window_size = 8192
        tcp_checksum = 0  # Will be calculated later, placeholder
        tcp_urgent_ptr = 0

        tcp_header = struct.pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq_num,
                                 tcp_ack_num, (tcp_data_offset << 4), tcp_flags,
                                 tcp_window_size, tcp_checksum, tcp_urgent_ptr)

        # Calculate IP checksum
        ip_checksum = calculate_checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                 (ip_version << 4) | ip_ihl, ip_tos, ip_length, ip_id,
                                 (ip_flags << 13) | ip_frag_offset, ip_ttl, ip_protocol,
                                 ip_checksum, ip_src, ip_dst)

        # Calculate TCP checksum (requires pseudo-header)
        pseudo_header = struct.pack('!4s4sBBH', ip_src, ip_dst, 0, ip_protocol, len(tcp_header) + len(payload.encode()))
        tcp_checksum = calculate_checksum(pseudo_header + tcp_header + payload.encode())
        tcp_header = struct.pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq_num,
                                 tcp_ack_num, (tcp_data_offset << 4), tcp_flags,
                                 tcp_window_size, tcp_checksum, tcp_urgent_ptr)
        # Combine headers and payload
        # I put payload bytes in a SYN packet. Some stacks treat data on a SYN oddly or drop it,
        # so silence can mean my packet shape was rejected rather than the VLAN being absent.
        packet = eth_header + vlan_header + ip_header + tcp_header + payload.encode()
        return packet
    except Exception as e:
        logging.error(f"Error crafting packet for VLAN {vlan_id}: {e}")
        return None


def calculate_checksum(data):
    """
    Calculates the IP or TCP checksum.
    Args:
        data (bytes): The data to calculate the checksum for.
    Returns:
        int: The calculated checksum value.
    """
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        # Network byte order: the first byte of each pair is the high byte.
        s += (data[i] << 8) + data[i+1]
    if n:
        s += data[len(data)-1] << 8
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s


def is_probe_response(data, target_ip, target_port):
    """
    Checks whether a received packet is a reply to the probe: an IPv4
    TCP packet from the target address and the probed port, carrying
    SYN reply flags (SYN and ACK both set).

    Args:
        data (bytes): The received packet, Ethernet header included.
        target_ip (str): The probed target IP address.
        target_port (int): The probed destination port.

    Returns:
        bool: True only when the packet matches the probe.
    """
    try:
        if len(data) < 14:
            return False
        eth_type = struct.unpack('!H', data[12:14])[0]
        ip_offset = 14
        if eth_type == 0x8100:  # 802.1Q tagged frame
            if len(data) < 18:
                return False
            eth_type = struct.unpack('!H', data[16:18])[0]
            ip_offset = 18
        if eth_type != 0x0800:  # Not IPv4
            return False
        ip_header = data[ip_offset:ip_offset + 20]
        if len(ip_header) < 20:
            return False
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ihl = (iph[0] & 0x0F) * 4
        if iph[6] != 6:  # Not TCP
            return False
        if socket.inet_ntoa(iph[8]) != target_ip:  # Source is not the target
            return False
        tcp_offset = ip_offset + ihl
        tcp_header = data[tcp_offset:tcp_offset + 20]
        if len(tcp_header) < 20:
            return False
        src_port = struct.unpack('!H', tcp_header[0:2])[0]
        if src_port != target_port:
            return False
        flags = tcp_header[13]
        # My match stops at source address, source port, and these two flags. I never check the
        # destination port or the ack number, so an unrelated SYN ACK from the same service,
        # for some other connection of mine, would count as this VLAN answering.
        return (flags & 0x02) != 0 and (flags & 0x10) != 0  # SYN and ACK
    except Exception:
        return False


def send_and_receive_status(interface, packet, timeout, target_ip=None, target_port=None):
    """
    Sends a packet and waits for a matching response.

    Returns:
        tuple: (status, data) where status is "answered" when a packet
        matching the probe arrived, "no_response" when the wait timed
        out with no matching packet, and "failed" when sending or
        receiving raised an error. Unrelated packets received during
        the wait are ignored.
    """
    s = None
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) # ETH_P_ALL
        s.bind((interface, 0))
        s.send(packet)
        s.settimeout(timeout)

        while True:
            try:
                data = s.recv(65535) # Maximum IP packet size
            except socket.timeout:
                return ("no_response", None)
            if target_ip is None or target_port is None:
                return ("answered", data)
            if is_probe_response(data, target_ip, target_port):
                return ("answered", data)
            # Unrelated packet: keep waiting until the timeout.
    except Exception as e:
        logging.error(f"Error sending/receiving data on interface {interface}: {e}")
        return ("failed", None)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def send_and_receive(interface, packet, timeout, target_ip=None, target_port=None):
    """
    Sends a packet on the specified interface and listens for a response
    that matches the probe (see is_probe_response).

    Args:
        interface (str): The network interface to use.
        packet (bytes): The packet to send.
        timeout (float): The timeout in seconds for receiving a response.
        target_ip (str): The probed target IP address.
        target_port (int): The probed destination port.

    Returns:
        bytes: The matching received data, or None if no matching
        response is received within the timeout.
    """
    status, data = send_and_receive_status(interface, packet, timeout, target_ip, target_port)
    return data



def main():
    """
    Main function to drive the VLAN discovery process.
    """
    args = setup_argparse()

    # Input validation for VLAN range
    try:
        vlan_start, vlan_end = map(int, args.vlan_range.split("-"))
        if not (1 <= vlan_start <= 4094 and 1 <= vlan_end <= 4094 and vlan_start <= vlan_end):
            raise ValueError("Invalid VLAN range. Must be between 1 and 4094, and start <= end.")
    except ValueError as e:
        logging.error(f"Invalid VLAN range: {e}")
        sys.exit(1)

    # Get source MAC address
    src_mac = args.src_mac
    if not src_mac:
        src_mac = get_mac_address(args.interface)
        if not src_mac:
            logging.error("Could not determine source MAC address.  Please specify with --src-mac.")
            sys.exit(1)
        logging.info(f"Using source MAC address: {src_mac}")

    # Resolve destination MAC address
    dst_mac = args.dst_mac
    if not dst_mac:
        dst_mac = resolve_mac_address(args.target, args.interface, args.arp_timeout)
        if not dst_mac:
            logging.error(f"Could not resolve MAC address for {args.target}. Please specify with --dst-mac.")
            sys.exit(1)
        logging.info(f"Resolved destination MAC address: {dst_mac}")

    # Resolve the source IP for the crafted packets
    src_ip = args.src_ip
    if not src_ip:
        src_ip = get_ip_address(args.interface)
        if not src_ip:
            logging.error("Could not determine the source IP address from the interface. Please specify with --src-ip.")
            sys.exit(1)
        logging.info(f"Using source IP address: {src_ip}")

    logging.info(f"Scanning VLAN range {vlan_start}-{vlan_end} on interface {args.interface} targeting {args.target}:{args.port}")

    sent = 0
    answered = 0
    failed = 0
    attempted = 0

    # Iterate through VLAN IDs
    # One fresh socket and up to a full timeout per VLAN. The default sweep of 4094 IDs at
    # 2 seconds each is an hours long worst case, and I print no progress while it runs.
    for vlan_id in range(vlan_start, vlan_end + 1):
        attempted += 1
        packet = craft_vlan_packet(src_mac, dst_mac, vlan_id, args.target, args.port, args.payload, src_ip=src_ip)
        if packet:
            status, response = send_and_receive_status(args.interface, packet, args.timeout, args.target, args.port)
            if status == "failed":
                failed += 1
                logging.warning(f"VLAN {vlan_id}: Probe failed to send or receive.")
            else:
                sent += 1
                if status == "answered" and response:
                    answered += 1
                    logging.info(f"VLAN {vlan_id}: Received a matching response. The VLAN is likely active.")
                else:
                    logging.debug(f"VLAN {vlan_id}: No matching response received.")
        else:
            failed += 1
            logging.warning(f"Skipping VLAN {vlan_id} due to packet crafting failure.")

    summary = f"Scan summary: sent={sent}, answered={answered}, failed={failed}"
    logging.info(summary)
    print(summary)

    if attempted and failed == attempted:
        logging.error("Every probe failed; no probe was sent.")
        sys.exit(1)

if __name__ == "__main__":
    main()
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


def craft_vlan_packet(src_mac, dst_mac, vlan_id, target_ip, target_port, payload):
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
        vlan_tci = vlan_id & 0x0FFF  # VLAN ID, 12 bits
        vlan_tpid = 0x0800  # IP Protocol
        vlan_header = struct.pack('!HH', vlan_tci, vlan_tpid)

        # IP Header (Minimal, assuming default values are acceptable)
        ip_version = 4
        ip_ihl = 5  # Minimum header length
        ip_tos = 0
        ip_length = 20 + len(payload.encode())  # IP header length + TCP payload length
        ip_id = 12345  # Dummy ID
        ip_flags = 0
        ip_frag_offset = 0
        ip_ttl = 64  # Time to live
        ip_protocol = 6  # TCP
        ip_checksum = 0  # Will be calculated later, placeholder
        ip_src = socket.inet_aton("192.168.1.1")  # Replace with appropriate source IP if needed.  Important for routing.  Consider adding as argument.
        ip_dst = socket.inet_aton(target_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                 (ip_version << 4) | ip_ihl, ip_tos, ip_length, ip_id,
                                 (ip_flags << 13) | ip_frag_offset, ip_ttl, ip_protocol,
                                 ip_checksum, ip_src, ip_dst)

        # TCP Header (Minimal, assuming default values are acceptable)
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
        s += data[i] + (data[i+1] << 8)
    if n:
        s += data[len(data)-1]
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s


def send_and_receive(interface, packet, timeout):
    """
    Sends a packet on the specified interface and listens for a response.

    Args:
        interface (str): The network interface to use.
        packet (bytes): The packet to send.
        timeout (float): The timeout in seconds for receiving a response.

    Returns:
        bytes: The received data, or None if no response is received within the timeout.
    """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) # ETH_P_ALL
        s.bind((interface, 0))
        s.send(packet)
        s.settimeout(timeout)

        try:
            data = s.recv(65535) # Maximum IP packet size
            return data
        except socket.timeout:
            return None  # Timeout occurred, no response received
        finally:
            s.close() # close the socket no matter what
    except Exception as e:
        logging.error(f"Error sending/receiving data on interface {interface}: {e}")
        return None



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

    logging.info(f"Scanning VLAN range {vlan_start}-{vlan_end} on interface {args.interface} targeting {args.target}:{args.port}")

    # Iterate through VLAN IDs
    for vlan_id in range(vlan_start, vlan_end + 1):
        packet = craft_vlan_packet(src_mac, dst_mac, vlan_id, args.target, args.port, args.payload)
        if packet:
            response = send_and_receive(args.interface, packet, args.timeout)
            if response:
                logging.info(f"VLAN {vlan_id}: Received response.") # A response indicates that the VLAN is likely active.
            else:
                logging.debug(f"VLAN {vlan_id}: No response received.")
        else:
            logging.warning(f"Skipping VLAN {vlan_id} due to packet crafting failure.")

if __name__ == "__main__":
    main()
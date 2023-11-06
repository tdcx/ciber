import socket
import struct
import subprocess
import sys

def analyze_packet(packet):
    # Extract Ethernet header information
    eth_header = packet[:14]
    eth_header = struct.unpack("!6s6sH", eth_header)
    src_mac = ":".join([hex(x)[2:].zfill(2) for x in eth_header[0]])
    dst_mac = ":".join([hex(x)[2:].zfill(2) for x in eth_header[1]])
    eth_type = socket.ntohs(eth_header[2])

    print(f"Source MAC: {src_mac}  Destination MAC: {dst_mac}  EtherType: {hex(eth_type)}")

    # Extract IP header information
    if eth_type == 0x0800:  # IPv4
        ip_header = packet[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        print(f"Source IP: {src_ip}  Destination IP: {dst_ip}  Protocol: {protocol}")

    # Add more packet analysis code for other protocols as needed

def start_packet_capture(interface):
    # Create a raw socket to capture packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Bind the socket to the specified interface
    sock.bind((interface, 0))

    # Set socket options to receive all packets
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Start capturing packets
    while True:
        try:
            # Receive a packet
            packet, _ = sock.recvfrom(65535)

            # Process the packet
            analyze_packet(packet)

        except KeyboardInterrupt:
            break

    # Disable promiscuous mode and close the socket
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sock.close()



def find_wireless_interface():
    encoding = sys.getdefaultencoding()  # Get the system's default encoding
    output = subprocess.check_output("netsh wlan show interfaces")
    output = output.decode(encoding, errors='ignore')  # Ignore decoding errors
    lines = output.splitlines()
    interface_name = None

    for line in lines:
        if "Name" in line:
            _, interface_name = line.split(":")
            interface_name = interface_name.strip()

    return interface_name


# Start the packet capture on a specific network interface
interface = find_wireless_interface()  # Find the wireless interface name
start_packet_capture(interface)

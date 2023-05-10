"""
The intention of this program is to visualize and understand all the traffic in
a network. By creating a map:
    Fase 1: Non-interactive map, maybe just an array and some form of displaying
    the traffic
    Fase 2: Interactive map with all the data accessible to the user to evaluate.
"""
import pyshark
import socket

def main():
    """
    This will be the main function and will descrive the program and how to use it.
    """
    capture = pyshark.LiveCapture(interface='wlan0')
    for packet in capture.sniff_continuously(packet_count=10):
        output(packet)

def output(packet):
    """
    This function will define the temporary output and filtering of the desired 
    data of the packet.
    """

    ip_proto={v:k[8:] for (k,v) in vars(socket).items() if k.startswith('IPPROTO')}
    ip_protocol = ip_proto.get(packet.ip.proto)
    ip_src = packet.ip.src
    ip_dst = packet.ip.dst

    print("ip_protocol", ip_protocol, "ip_src", ip_src, "ip_dst", ip_dst)


if __name__ == '__main__':
    main()

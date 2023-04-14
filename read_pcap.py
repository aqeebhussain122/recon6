#!/usr/bin/python3
import dpkt
import pyshark
import socket
from dpkt.compat import compat_ord

def mac_addr(address):
    """
	Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

"""
Print out info about each packet in the pcap file
  Args:
    pcap: dpkt pcap reader object
"""

# Processing of a given PCAP file to present detected link local IPv6 addresses
def process_pcap(pcap):
    read_pcap = pyshark.FileCapture(pcap, use_json=True)
    # Dictionary to get an IPv6 addresses and the MAC address.
    ipv6_pkts = {}
    # Dictionary to store the IPv4 address and the corresponding MAC.
    ipv4_pkts = {}

    for pkt in read_pcap:
        # Look for all packets which are of a TCP origin before digging into the IP layer.
        if "TCP" and "IPv6" in pkt:
            # Print the IPv6 details of the packet as a whole.
            #print(pkt.ipv6)
            # If we want the source IPv6 address which is what we'll want because the destination is a multicast call to all nodes.
            src_ipv6 = pkt.ipv6.src # We want to store this in a variable and then store it in our dictionary.
            src_ndp_mac = pkt.eth.src  # We want to store this in a variable and then store it in our dictionary.
            ipv6_pkts['{}'.format(src_ipv6)] = src_ndp_mac
            # Corresponding MAC which is retrieved via NDP
            # Add all of the MACs which have been found
            #pkt_macs.append(pkt.eth.src)

        # We attempt to find our MAC address via packets where ARP is present.
        if "arp" in pkt:
            pass
            src_ipv4 = pkt[1].src.proto.ipv4
            src_arp_mac = 
            #print(pkt[1].src.proto_ipv4)
            #print(pkt[1].src.hw_mac)

    
    print(ipv6_pkts)
    # All of the MAC addresses collected. 
    #for i in range(len(pkt_macs)):
        #print(pkt_macs[i])

    #print("IPv4 Addresses")
 
    # Print IPv4 packets with corresponding MACs
    #for pkt in read_pcap:
        # ARP details are printed. Would be good to get them printed somehow.
    #    if "arp" in pkt:
            # We can access the packet based on available layers. Layer 0 being Ethernet and Layer 1 being ARP.
    #        print(pkt[1])
            
            # DO NOT ERASE
            # This will print the IPv4 address. 
            #print(pkt[1].src.proto_ipv4)

def comp_macs():
    pass

def main():
  # Open a binary file stream of the pcap file
  with open('pyshark-test.pcapng', 'rb') as f:
    process_pcap('pyshark-test.pcapng')

if __name__ == '__main__':
  main()

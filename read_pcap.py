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
    # We use JSON to help us know the field names of the fields to print for our tools
    read_pcap = pyshark.FileCapture(pcap, use_json=True)
    # Dictionary to get an IPv6 addresses and the MAC address via NDP.
    ipv6_pkts = {}
    # Dictionary to store the IPv4 address and the corresponding MAC via ARP.
    ipv4_pkts = {}

    for pkt in read_pcap:
        # Look for all packets which are of a TCP origin and checking IPv6 is also part of the layer(s).
        if "TCP" and "IPv6" in pkt:
            # Print the IPv6 details of the packet as a whole.
            #print(pkt.ipv6)
            
            # If we want the source IPv6 address which is what we'll want because the destination is a multicast call to all nodes.
            src_ipv6 = pkt.ipv6.src # We want to store this in a variable and then store it in our dictionary.
            src_ndp_mac = pkt.eth.src  # We want to store this in a variable and then store it in our dictionary.
            ipv6_pkts['{}'.format(src_ipv6)] = src_ndp_mac
            # Corresponding MAC which is retrieved via NDP
            # Add all of the MACs which have been found

        # We attempt to find our MAC address via packets where ARP is present.
        if "arp" in pkt:
            src_ipv4 = pkt[1].src.proto_ipv4
            src_arp_mac = pkt[1].src.hw_mac
            ipv4_pkts['{}'.format(src_ipv4)] = src_arp_mac
    
    # Print the dictionaries we need.
    #print(ipv6_pkts)
    #print(ipv4_pkts)

    # We can return the two dicts from the function in order to talk to them in other functions.
    return ipv6_pkts, ipv4_pkts

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

def compare_mac_addr(pcap):
    # Get the MAC addresses from IPv6 dict.
    # Get the MAC addresses from IPv4 dict
    ipv6_dict, ipv4_dict = process_pcap(pcap)

    ipv4_macs = ipv6_dict.values()
    ipv6_macs = ipv4_dict.values()

    print(ipv6_macs, ipv4_macs)
    res = set(ipv6_macs).intersection(set(ipv4_macs))

    print("Common MAC address: {}".format(str(list(res))))
    str_res = str(res)

    value = {i for i in ipv6_macs if ipv6_macs[i]==str_res}
    print("key by value:",value)
    # We want to search for the value discovered with the corresponding key on each side so that we can map the link local IPv6 and IPv4 addresses together. We can then create a new dict which can be returned from this function and perhaps dumped as an XML file.

    

def main():
  pcap = 'test-capture.pcapng'
  # Open a binary file stream of the pcap file
  with open(pcap, 'rb') as f:
    process_pcap(pcap)

  print(compare_mac_addr(pcap))

if __name__ == '__main__':
  main()

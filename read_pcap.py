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
            #ipv6_pkts['{}'.format(src_ipv6)] = src_ndp_mac
            
            # SWAPPED.
            ipv6_pkts['{}'.format(src_ndp_mac)] = src_ipv6
            # Corresponding MAC which is retrieved via NDP
            # Add all of the MACs which have been found

        # We attempt to find our MAC address via packets where ARP is present.
        if "arp" in pkt:
            src_ipv4 = pkt[1].src.proto_ipv4
            src_arp_mac = pkt[1].src.hw_mac

            #ipv4_pkts['{}'.format(src_ipv4)] = src_arp_mac
            
            # SWAPPED.
            ipv4_pkts['{}'.format(src_arp_mac)] = src_ipv4
    
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
    ip_addrs = []
    # Whole dictionary contained (items)
    ipv6_dict, ipv4_dict = process_pcap(pcap)

    # Call the keys from the dictionaries.
    ipv4_macs = ipv6_dict.keys()
    ipv6_macs = ipv4_dict.keys()

    uniq = set(ipv6_macs).intersection(set(ipv4_macs))

    list_uniq = list(uniq)
    print(len(list_uniq))
    # We want to search this particular value in both dictionaries
    # This MUST be a list in order to work with join

    # Need to test with a network of VMs in which there can be several MAC addresses.
    if len(list_uniq) == 1:
        str_uniq = ''.join(list_uniq)
        print("Common MAC address: {}\n".format(str_uniq))
        print(str_uniq)
        # This grabs the two fields we need which correspond to the same MAC.
        get_ipv6_addr = ipv6_dict.get("{}".format(str_uniq)) 
        get_ipv4_addr = ipv4_dict.get("{}".format(str_uniq)) 
        print(get_ipv4_addr)
        print(get_ipv6_addr)
        #ip_mac_dict = {'{}'.format(str_uniq): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}

    if len(list_uniq) > 1:
        for i in list_uniq:
            get_ipv6_addr = ipv6_dict.get("{}".format(i))
            get_ipv4_addr = ipv4_dict.get("{}".format(i))
            print(i)
            print(get_ipv4_addr)
            print(get_ipv6_addr)

    # Create a new dictionary appending this in. 

    #ip_mac_dict = {'{}'.format(str_uniq): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
    #print(ip_mac_dict)
        
    #print(type(ip_mac_dict))
    #print(ip_mac_dict[str_uniq])
    # str_uniq becomes the key for two different values
    #ip_mac_dict['{}'.format(get_ipv4_addr)] = str_uniq
    #ip_mac_dict['{}'.format(get_ipv6_addr)] = str_uniq
    
    #return ip_mac_dict
    
    # We want to search for the value discovered with the corresponding key on each side so that we can map the link local IPv6 and IPv4 addresses together. We can then create a new dict which can be returned from this function and perhaps dumped as an XML file.



def main():
    pcap = 'icmpv6.pcapng'
    # Open a binary file stream of the pcap file
    with open(pcap, 'rb') as f:
        process_pcap(pcap)

    print(compare_mac_addr(pcap))

if __name__ == '__main__':
  main()

# https://www.w3schools.com/python/python_dictionaries_access.asp
# https://stackoverflow.com/questions/5946236/how-to-merge-dicts-collecting-values-from-matching-keys

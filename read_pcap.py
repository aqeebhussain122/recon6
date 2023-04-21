#!/usr/bin/python3
import dpkt
import pyshark
import json
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

# Currently parsing a PCAP file, upgrade intended to sniff live packets and then process these in real time.
# Perform a ping sweep to populate the ARP table

# More steps available from the training slides.

# Adjust the process code so it can allow sniffing depending on what arg parse says.

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
    # Whole dictionary contained (items)
    ipv6_dict, ipv4_dict = process_pcap(pcap)

    # Call the keys from the dictionaries.
    ipv4_macs = ipv6_dict.keys()
    ipv6_macs = ipv4_dict.keys()

    uniq = set(ipv6_macs).intersection(set(ipv4_macs))

    list_uniq = list(uniq)
    list_len = len(list_uniq)
    # We want to search this particular value in both dictionaries
    # This MUST be a list in order to work with join

    # Need to test with a network of VMs in which there can be several MAC addresses.
    """
    if list_len == 1:
        str_uniq = ''.join(list_uniq)
        print("Common MAC address: {}\n".format(str_uniq))
        print(str_uniq)
        # This grabs the two fields we need which correspond to the same MAC.
        get_ipv6_addr = ipv6_dict.get("{}".format(str_uniq)) 
        get_ipv4_addr = ipv4_dict.get("{}".format(str_uniq)) 
        print(get_ipv4_addr)
        print(get_ipv6_addr)
        ip_mac_dict = {'{}'.format(str_uniq): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
        return ip_mac_dict

    if list_len > 1:
        for i in list_uniq:
            get_ipv6_addr = ipv6_dict.get("{}".format(i))
            get_ipv4_addr = ipv4_dict.get("{}".format(i))
            print(i)
            print(get_ipv4_addr)
            print(get_ipv6_addr)
    """
    ip_mac_list = []
    if list_len == 1:
        str_uniq = ''.join(list_uniq)
        print("Common MAC address: {}".format(str_uniq))
        print(str_uniq)
        # This grabs the two fields we need which correspond to the same MAC.
        get_ipv6_addr = ipv6_dict.get("{}".format(str_uniq)) 
        get_ipv4_addr = ipv4_dict.get("{}".format(str_uniq)) 
        print(get_ipv4_addr)
        print(get_ipv6_addr)
        ip_mac_dict = {'{}'.format(str_uniq): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
        # Return this piece of info which then gets written to a file for further parsing.
        return ip_mac_dict

    elif list_len > 1:
        for i in list_uniq:
            get_ipv6_addr = ipv6_dict.get("{}".format(i))
            get_ipv4_addr = ipv4_dict.get("{}".format(i))
            print(i)
            print(get_ipv4_addr)
            print(get_ipv6_addr)
            ip_mac_dict = {'{}'.format(i): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
            #ip_mac_dict['{}'.format(i)].append(['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)])
            ip_mac_list.append(ip_mac_dict)

    # Wrap all of the individual dicts into a whole list which can then get parsed and written to a file
    return ip_mac_list

    # JSON or XML? Idk yet.

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

# Parse the info from being a list of dicts to something like XML or JSON and then passing this data to an appropriate tool to perform some scans.
def parse_macs(pcap):
    macs = compare_mac_addr(pcap)
    #data = {'1':[{'ipv4_address': '2', 'ipv6_address': '3'}]}
    #print(json.dumps(data, sort_keys = True, indent = 4))

    json_list = []
    # Access the individual dicts stored within the list.
    for mac in macs:
        # Access the key and value stored in each individual dict.
        for key, val in mac.items():
            mac_addr = key
            ipv4 = val[0]
            ipv6 = val[1]
            data = {'{}'.format(mac_addr):[{'ipv4_address': '{}'.format(ipv4), 'ipv6_address': '{}'.format(ipv6)}]}
            json_list.append(data)
            
        #data = {'aa':[{'ipv4': '{}'.format(mac[0]), 'ipv6':'{}'.format(mac[1])}]}

    data_json = json.dumps(json_list, sort_keys = True, indent = 4)

    return data_json
    """
    for mac in macs:
        for key, val in mac.items():
            # Make a JSON variable which will append all of the data into itself.
            ipv4 = val[0]
            ipv6 = val[1]
    """

# Read our JSON file in order to pick out exactly what we might need in order to pass through to other tools in the pipeline 
def read_json(json_file):
    # Read the JSON file through a file stream and then load the incoming data via json library.
    with open(json_file, 'r') as j:
        contents = json.loads(j.read())

    # Loop through the content of the file 
    for content in contents:
        # Dynamic items so that we can access the keys and values together.
        dynamic_items = content.items()
        # Loop through the key and value, we only want the value to scope down on it.
        for key, val in dynamic_items:
            # Access the values individually and pull out the exact value we want which is the IPv6 address
            for vals in val:
                # We want to grab these addresses and potentially send them to NMAP
                print(vals['ipv6_address'])

                # Potentially return the IPv6 addresses in a list which can then get unpacked elsewhere in order to be scanned via NMAP.


def main():
    pcap = 'test-capture.pcapng'
    # Open a binary file stream of the pcap file
    with open(pcap, 'rb') as f:
        process_pcap(pcap)

#    comp = compare_mac_addr(pcap)
    parse = parse_macs(pcap)
    print(parse)

    read = read_json('test.json')

if __name__ == '__main__':
  main()

# https://www.w3schools.com/python/python_dictionaries_access.asp
# https://stackoverflow.com/questions/5946236/how-to-merge-dicts-collecting-values-from-matching-keys

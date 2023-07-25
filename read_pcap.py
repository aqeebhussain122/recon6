#!/usr/bin/python3
import sys
import subprocess
import dpkt
import pyshark
import json
import nmap
import argparse
from dpkt.compat import compat_ord
from scapy.all import *


# Still need this code to send ARP packets via NMAP because it's faster.

def send_arp_pkts(target_subnet):
    # Make a scanner.
    nmScanner = nmap.PortScanner()
    # Once a list of params are pulled in, make the list compatible like this...
    #compatible_list = ', '.join(read)
    # ARP scan. NMAP based pings aren't sent to Wireshark needs to be investigated.
    nmScanner.scan(hosts='{}'.format(target_subnet), arguments='-n -sP -PR')
    all_hosts = nmScanner.all_hosts()
    for host in all_hosts:
        print("Host: %s" % (host))
        print('State : %s' % nmScanner[host].state())


# Sniff out ARP/NDP traffic as filter which will be used in scapy.
def pkt_display(pkt):
    # If the traffic is of type ARP.
    if pkt[ARP].op == 1:  # who-has (request)
        return f"Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}"
    if pkt[ARP].op == 2:  # is-at (response)
        return f"*Response: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}"

'''
Send ARP/NDP (ping6) packets to the targets.
'''

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
    
    # We can return the two dicts from the function in order to talk to them in other functions.
    return ipv6_pkts, ipv4_pkts

    # All of the MAC addresses collected. 
    #for i in range(len(pkt_macs)):
        #print(pkt_macs[i])

    # Print IPv4 packets with corresponding MACs
    #for pkt in read_pcap:
        # ARP details are printed. Would be good to get them printed somehow.
    #    if "arp" in pkt:
            # We can access the packet based on available layers. Layer 0 being Ethernet and Layer 1 being ARP.
    #        print(pkt[1])
            
            # DO NOT ERASE
            # This will print the IPv4 address. 
            #print(pkt[1].src.proto_ipv4)

# This is to tie the MACs from v4 and v6 together.
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

    # Could mebs refactor this part.
    ip_mac_list = []
    if list_len == 1:
        str_uniq = ''.join(list_uniq)
        #print("Common MAC address: {}".format(str_uniq))
        #print(str_uniq)
        # This grabs the two fields we need which correspond to the same MAC.
        get_ipv6_addr = ipv6_dict.get("{}".format(str_uniq)) 
        get_ipv4_addr = ipv4_dict.get("{}".format(str_uniq)) 
        #print(get_ipv4_addr)
        #print(get_ipv6_addr)
        ip_mac_dict = {'{}'.format(str_uniq): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
        # Return this piece of info which then gets written to a file for further parsing.
        return ip_mac_dict

    elif list_len > 1:
        for i in list_uniq:
            get_ipv6_addr = ipv6_dict.get("{}".format(i))
            get_ipv4_addr = ipv4_dict.get("{}".format(i))
            #print(i)
            #print(get_ipv4_addr)
            #print(get_ipv6_addr)
            ip_mac_dict = {'{}'.format(i): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
            ip_mac_list.append(ip_mac_dict)

    # Wrap all of the individual dicts into a whole list which can then get parsed and written to a file
    return ip_mac_list

    #ip_mac_dict = {'{}'.format(str_uniq): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
    #print(ip_mac_dict)
        
    #print(type(ip_mac_dict))
    #print(ip_mac_dict[str_uniq])
    # str_uniq becomes the key for two different values
    #ip_mac_dict['{}'.format(get_ipv4_addr)] = str_uniq
    #ip_mac_dict['{}'.format(get_ipv6_addr)] = str_uniq
    
    #return ip_mac_dict
    
    # We want to search for the value discovered with the corresponding key on each side so that we can map the link local IPv6 and IPv4 addresses together. We can then create a new dict which can be returned from this function and perhaps dumped as JSON.

# Parse the info from being a list of dicts to something like XML or JSON and then passing this data to an appropriate tool to perform some scans.
def parse_macs(pcap):
    macs = compare_mac_addr(pcap)

    json_list = []
    # Access the individual dicts stored within the list.

    # If there's more than one MAC found making it "macs"...
    if len(macs) > 1:
        for mac in macs:
        # Access the key and value stored in each individual dict.
            for key, val in mac.items():
                mac_addr = key
                ipv4 = val[0]
                ipv6 = val[1]
                # MAC address is tied to an IPv4/IPv6 address.
                data = {'{}'.format(mac_addr):[{'ipv4_address': '{}'.format(ipv4), 'ipv6_address': '{}'.format(ipv6)}]}
                json_list.append(data)
            
    # Need this to write to a file, returning the file as a result which then goes into read_json 
    data_json = json.dumps(json_list, sort_keys = True, indent = 4)
 
    return data_json

# Read our JSON file in order to pick out exactly what we might need in order to pass through to other tools in the pipeline 
def read_json(json_file):
    ipv6_addrs = []
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
                ipv6_addrs.append(vals['ipv6_address'])

    # Close the file stream.
    j.close()
    # Return IPv6 addresses in a list which can then get unpacked in order to be scanned via NMAP.
    return ipv6_addrs

# Perform an NMAP scan on all of the identified addresses.
# Active function which does the scanning.
# This needs to be edited heavily!
def scan_ipv6():
    #read = read_json('ipv6_targets.txt')
    # Spawn a scanner
    nmScanner = nmap.PortScanner()
    with open('ipv6_targets.txt', 'r') as ipv6_targets:
        for ipv6_target in ipv6_targets:
            # Pass for now...
            pass
            """
            nmScanner.scan(hosts=ipv6_target, arguments='-vvv -sT -n -Pn -T4 -6')
            print('Host : %s (%s)' % (ipv6_target, nmScanner[ipv6_target[:-1]].hostname()))
            print('State : %s' % nmScanner[ipv6_target].state())
            print(nmScanner.command_line())
            """
    ipv6_targets.close()

    # This needs work!            
    print("Performing NMAP scan")


	# run a loop to print all the found result about the ports
#    for host in nmScanner.all_hosts():
#    	print('Host : %s (%s)' % (host, nmScanner[host].hostname()))
#    	print('State : %s' % nmScanner[host].state())

def main():
    parser = argparse.ArgumentParser(description='SYN Scan and flood tool which forms raw packets taking required IP addresses and port numbers')
    # -i and -s cannot be launched together.
    group = parser.add_mutually_exclusive_group(required=True)
    # Finished component
    group.add_argument("-i", "--informational", help="Queries the PCAP file provided for the IPv4/IPv6 addresses tied with their MAC addresses.", action='store_true')
    parser.add_argument("capture_file", nargs='?', help='Capture file which should contain packets of ARP/ICMPv6 traffic.', type=str)
    parser.add_argument("--subnet", nargs='?', help='Subnet to send ARP packets to.', type=str)
    # Needs more work.
    group.add_argument("-s", "--scan", help="Actively scan the network sending the required packets and automating IPv4/IPv6 scanning. (This is still under development)", action='store_true')
    args = parser.parse_args()

    # The -i option.
    if args.informational:
        # Quick fix to make the arg parsing a bit more flexible.
        if len(sys.argv) == 2:
            raise Exception("I need a capture file to proceed!")
            
        pcap = args.capture_file
        # Raw JSON.
        comp = compare_mac_addr(pcap)
    
        # Clean JSON.
        parse = parse_macs(pcap)
        print(parse)
        with open('test.json', 'w') as f:
            f.write(parse)
        
        f.close()

        # This function was written to send the IPv6 files to NMAP.
        #json = read_json('test.json')
        # Returns for the IPv6 addresses which can be manually scanned.

        #This is for active scanning.
         #arp = send_arp_pkts('192.168.0.0/24')

    # This option needs more work.
    # Put the code into a while true loop with a signal handler to kill it.
    # Send NDP/ARP traffic via this option. Filter it out and grab the packets needed.
    # Write the traffic to a PCAP.
    # Read the PCAP using the informational functions and write it to a JSON file.
    # Once the JSON file has been written 
    if args.scan:
         pkts = sniff(prn=pkt_display, filter="arp", iface='ens33', store=0, count=1000)
         print("Sending ARP packets.")
         arp = send_arp_pkts(args.subnet) 
         print(arp)
         print(pkts.summary())

if __name__ == '__main__':
  main()

# https://www.w3schools.com/python/python_dictionaries_access.asp
# https://stackoverflow.com/questions/5946236/how-to-merge-dicts-collecting-values-from-matching-keys

"""
This needs to be refactored later...
#primary_interface = subprocess.Popen("ip route list | grep -i default | awk {'print $5'}", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #primary_interface.communicate()
    #print(primary_interface)

    # I need the primary network interface
    with open('ipv6_targets.txt', 'a') as f:
        for ipv6 in ipv6_addrs:
            f.write(ipv6 + '\n')
            #f.write(ipv6 + '%' + '{}'.format(primary_interface) + '\n')
"""

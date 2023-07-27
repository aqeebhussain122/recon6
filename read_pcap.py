#!/usr/bin/python3
import sniffer
import sys
import subprocess
import dpkt
import pyshark
import json
import nmap
import argparse
from signal import signal, SIGINT
from dpkt.compat import compat_ord
from scapy.all import *


class readPCAP:
    def __init__(self, pcap):
        self.pcap = pcap

    def process_pcap(self):
        read_pcap = pyshark.FileCapture(self.pcap, use_json=True)
        ipv6_pkts = {}
        ipv4_pkts = {}
        
        for pkt in read_pcap:
            if "TCP" and "IPv6" in pkt:
                src_ipv6 = pkt.ipv6.src
                src_ndp_mac = pkt.eth.src
                ipv6_pkts['{}'.format(src_ndp_mac)] = src_ipv6

            if "arp" in pkt:
                src_ipv4 = pkt[1].src.proto_ipv4
                src_arp_mac = pkt[1].src.hw_mac
                ipv4_pkts['{}'.format(src_arp_mac)] = src_ipv4

        return ipv6_pkts, ipv4_pkts 

    def compare_mac_addr(self):
        # Whole dictionary contained (items)
        ipv6_dict, ipv4_dict = self.process_pcap()

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
            get_ipv6_addr = ipv6_dict.get("{}".format(str_uniq)) 
            get_ipv4_addr = ipv4_dict.get("{}".format(str_uniq)) 
            ip_mac_dict = {'{}'.format(str_uniq): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
            return ip_mac_dict
    
        elif list_len > 1:
            for i in list_uniq:
                get_ipv6_addr = ipv6_dict.get("{}".format(i))
                get_ipv4_addr = ipv4_dict.get("{}".format(i))
                ip_mac_dict = {'{}'.format(i): ['{}'.format(get_ipv4_addr), '{}'.format(get_ipv6_addr)]}
                ip_mac_list.append(ip_mac_dict)
    
        # Wrap all of the individual dicts into a whole list which can then get parsed and written to a file
        return ip_mac_list

    def parse_macs(self):
        macs = self.compare_mac_addr()

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
        
        ipv6_targets.close()
	# This needs work!            
        print("Performing NMAP scan")

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

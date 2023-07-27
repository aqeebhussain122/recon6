#!/usr/bin/python3
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
import sniffer
import read_pcap

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
        comp = read_pcap.compare_mac_addr(pcap)
    
        # Clean JSON.
        parse = read_pcap.parse_macs(pcap)
        print(parse)
        # JSON file produced to take away.
        with open('test.json', 'w') as f:
            f.write(parse)

        # Closing of file streams to keep things clean
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
         print("[!] Sniffing begins... [!]")
         try:
             signal(SIGINT, sniffer.signal_handler)
         #sniffer.signal_handler(SIGINT, sniffer.signal_handler)
             while True:
                 # Filter might need to be expanded. (filter=arp)
                 pkts = sniff(prn=sniffer.network_monitoring, filter="arp", iface='ens33', timeout=10)
                 write_file = wrpcap('sniffed.pcap', pkts, append=True)
                 print(pkts.summary())
         except KeyboardInterrupt:
              sys.exit(0)

if __name__ == '__main__':
  main()

# https://www.w3schools.com/python/python_dictionaries_access.asp
# https://stackoverflow.com/questions/5946236/how-to-merge-dicts-collecting-values-from-matching-keys

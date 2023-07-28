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
import capture_pcap
import read_pcap

def main():
    parser = argparse.ArgumentParser(description='SYN Scan and flood tool which forms raw packets taking required IP addresses and port numbers')
    # -i and -s cannot be launched together.
    group = parser.add_mutually_exclusive_group(required=True)
    # Finished component
    group.add_argument("-i", "--informational", help="Queries the PCAP file provided for the IPv4/IPv6 addresses tied with their MAC addresses.", action='store_true')
    # This is for informational capture.
    parser.add_argument("capture_file", nargs='?', help='Capture file which should contain packets of ARP/ICMPv6 traffic.', type=str)
    # This is for writing to a file.
    parser.add_argument("--write-file", nargs='?', help='New file which will contain packets of sniffed traffic.', type=str)
    parser.add_argument("--subnet", nargs='?', help='Subnet to send ARP packets to.', type=str)
    # Needs more work.
    group.add_argument("-s", "--scan", help="Actively scan the network sending the required packets and automating IPv4/IPv6 scanning. (This is still under development)", action='store_true')
    args = parser.parse_args()
    pcap = args.capture_file

    readPCAP = read_pcap.readPCAP(pcap)
    # The -i option.
    if args.informational:
        # Quick fix to make the arg parsing a bit more flexible.
        if len(sys.argv) == 2:
            raise Exception("I need a capture file to proceed!")
            
        pcap = args.capture_file
        # Raw JSON.
        comp = readPCAP.compare_mac_addr()
    
        # Clean JSON.
        parse = readPCAP.parse_macs()
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
         #sniffer.signal_handler(SIGINT, sniffer.signal_handler)
             while True:
                 # Filter might need to be expanded. (filter=arp)
                 # This contains the maximum value.

                 # We need to turn these into argparse args at some point...
                 capture_file = capture_pcap.capture_file(1073741824, args.write_file)
                 print(capture_file.check_file_size())
         except KeyboardInterrupt:
              sys.exit(0)

if __name__ == '__main__':
  main()

# https://www.w3schools.com/python/python_dictionaries_access.asp
# https://stackoverflow.com/questions/5946236/how-to-merge-dicts-collecting-values-from-matching-keys

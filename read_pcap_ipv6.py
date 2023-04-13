#!/usr/bin/python3
import dpkt
from datetime import datetime
import socket
# Helps to get the MAC address
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
# Rework on this with Pyshark.

def main():
  # Open a binary file stream of the pcap file
  with open('sniffed.pcap', 'rb') as f:
    # Read the PCAP file
    pcap = dpkt.pcap.Reader(f)
    #print_icmp(pcap)
    process_pcap(pcap)

if __name__ == '__main__':
  main()

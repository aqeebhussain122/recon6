#!/usr/bin/python3
import dpkt
import pyshark
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
    read_pcap = pyshark.FileCapture(pcap)
    for pkt in read_pcap:
        # Look for all packets which are of a TCP origin before digging into the IP layer.
        if "TCP" and "IPv6" in pkt:
            # Print the IPv6 details of the packet.
            print(pkt.ipv6)
            # Corresponding MAC, this is all going to need to be parsed though.
            print(pkt.eth)


# Rework on this with Pyshark.

def main():
  # Open a binary file stream of the pcap file
  with open('pyshark-test.pcapng', 'rb') as f:
    process_pcap('pyshark-test.pcapng')

if __name__ == '__main__':
  main()

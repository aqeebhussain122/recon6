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
  packets = 0
  time_list = []
  mac_list = []
  ip_details = []
  # with open the csv file, we can just write the entire loop into a csv...
  for timestamp, buf in pcap:
      packets += 1
      # Ethernet variable to assign a buffer to the PCAP file
      eth = dpkt.ethernet.Ethernet(buf)
      # Get all MAC addresses
      mac_addresses = mac_addr(eth.dst)
      mac_list.append(mac_addresses)

      # If a packet is not ethernet+IP then discard it from the output, because we don't care about those.
      if not isinstance(eth.data, dpkt.ip.IP):
        pass
        continue
      
	  # We don't care if it's not an IPv6 packet.
      ip = eth.data
	  # Seems like IPv4 which we probs do not want.
      ip_src_str = socket.inet_ntoa(ip.src)
      ip_dst_str = socket.inet_ntoa(ip.dst)

      proto = ip.get_proto(ip.p).__name__
      # We want to append a MAC address, the corresponding IPv4 address and source IPv6 address
      ip_details.append([proto, ip_src_str, ip_dst_str, mac_addr(eth.dst)])

      date = str(datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d"))
      time = str(datetime.utcfromtimestamp(timestamp).strftime("%H:%M:%S"))
      mins = str(datetime.utcfromtimestamp(timestamp).strftime("%M:%S.%f"))

      # Using datetime objects we do calculations.
      new_timestamp = str(datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f"))
      test = datetime.strptime(new_timestamp, "%Y-%m-%d %H:%M:%S.%f")
	  
      time_list.append(test)
  
  print("MACs: {}".format(set(mac_list)))
  print("IP Details: {}".format(ip_details))


def test():
  # Open a binary file stream of the pcap file
  with open('sniffed.pcap', 'rb') as f:
    # Read the PCAP file
    pcap = dpkt.pcap.Reader(f)
    #print_icmp(pcap)
    process_pcap(pcap)

if __name__ == '__main__':
  test()

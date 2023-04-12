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
# Processing of a given PCAP file which gets to a CSV file for ML processing
def process_pcap(pcap):
  packets = 0
  time_list = []
  # with open the csv file, we can just write the entire loop into a csv...
  for timestamp, buf in pcap:
      packets += 1
        # Ethernet variable to assign a buffer to the PCAP file
      eth = dpkt.ethernet.Ethernet(buf)
      # Get all MAC addresses
	  print(mac_addr(eth.dst))

      # If a packet is not ethernet+IP then discard it from the output
      if not isinstance(eth.data, dpkt.ip.IP):
       # print("Non IP packet")
       # pass will do nothing
        pass
        continue
    
    
      ip = eth.data
      ip_src_str = socket.inet_ntoa(ip.src)
      ip_dst_str = socket.inet_ntoa(ip.dst)

      proto = ip.get_proto(ip.p).__name__
      #print("{},{},{}".format(proto, ip_src_str, ip_dst_str))

      date = str(datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d"))
      time = str(datetime.utcfromtimestamp(timestamp).strftime("%H:%M:%S"))
      mins = str(datetime.utcfromtimestamp(timestamp).strftime("%M:%S.%f"))


      # Using datetime objects we do calculations.
      new_timestamp = str(datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f"))
      test = datetime.strptime(new_timestamp, "%Y-%m-%d %H:%M:%S.%f")
	  
      time_list.append(test)

def test():
  # Open a binary file stream of the pcap file
  with open('sniffed.pcap', 'rb') as f:
    # Read the PCAP file
    pcap = dpkt.pcap.Reader(f)
    #print_icmp(pcap)
    process_pcap(pcap)

if __name__ == '__main__':
  test()

#!/usr/bin/python3
import dpkt
from datetime import datetime
import socket


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
  with open('test.csv', "w") as f:
    print("protocol,source_ip,destination_ip,src_port,dst_port,payload_size,flags,date,time,duration", file=f) # - Print out the CSV headers of the file
    for timestamp, buf in pcap:
      packets += 1
        # Ethernet variable to assign a buffer to the PCAP file
      eth = dpkt.ethernet.Ethernet(buf)
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
	  
      # Timestamp is a full value taken from the packet extracted

 
      #result = "{:02.0f}:{:02.0f}:{:02.0f}".format(hours, minutes, seconds)
      #print(result)

      #print ('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
      #print ('Date: ', str(datetime.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")))

      # Every single time the packet is cycled in the capture file, then perform a calculation on the new last and second last entry in the milliseconds list
	  # The second last element should be subtracted by the last element

      time_list.append(test)
      #for i in range(len(time_list)):
      #    result = time_list[i] - time_list[i-1]
      #    print(result)
      #    print("timestamp {} is at {} and is {}".format(i+1, i, time_list[i]))
      
	  #print(time_list[-1] - time_list[0])


      # Iterate inside the list rather than outside it 
      #result = time_list[-1] - time_list[0]
      #print(result)

      payload_size = len(ip)
      # Import sniffer, bring in convert_bytes function then convert the bits to bytes
      #print(len(buf)) - Payload size
	  # Need payload size
      # 
	  #print(str(datetime.datetime.utcfromtimestamp(timestamp)))
    # If the packet is of type TCP
    #
      if isinstance(ip.data, dpkt.tcp.TCP): 
        for i in range(len(time_list)):
            time_diff = time_list[i] - time_list[i-1]
            #print(result)

        print(time_diff)
        tcp = ip.data
        tcp_src_port = tcp.sport
        tcp_dest_port = tcp.dport

		# Subtract the time between each packet
        #seconds.append(seconds_element)
        #print(seconds)
        # Add the flags by checking the numbers to each associated flag and then comparing that inside the TCP packet
        flags = tcp.flags
        if tcp.flags == 1:
            flags == 'FIN'
        if tcp.flags == 2:
            flags = 'SYN'
        if tcp.flags == 4:
            flags = 'RST'
        if tcp.flags == 16:
            flags = 'ACK'
        if tcp.flags == 24:
            flags = 'ACK/PSH'


        """
        if(tcp.dport == 21):
            tcp_dest_port = 'FTP'
        if(tcp.dport == 22):
            tcp_dest_port = 'SSH'
        if(tcp.dport == 23):
            tcp_dest_port = 'Telnet'
        if(tcp.dport == 25):
            tcp_dest_port = 'SMTP'
        if(tcp.dport == 80):
            tcp_dest_port = 'HTTP'
        if(tcp.dport == 135):
            tcp_dest_port = 'netBIOS'
        if(tcp.dport == 443):
            tcp_dest_port = 'HTTPS'
        if(tcp.dport == 445):
            tcp_dest_port = 'MSRPC'
        if(tcp.dport == 9001):
            tcp_dest_port = 'TOR'
        """

        fmt_tcp = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}'
		# Translate ports to service names such as HTTP,HTTPS,FTP - Lots of ifs.

        # Print gets written into the CSV via the given for loop
        print(fmt_tcp.format(proto,ip_src_str,ip_dst_str,tcp_src_port,tcp_dest_port,payload_size,flags,date,time,time_diff),file=f)
        print("{},{},{},{},{},{},{},{},{},{}".format(proto, ip_src_str, ip_dst_str, tcp_src_port, tcp_dest_port, payload_size, flags, date, time, time_diff))

      # If the packet is UDP
      if isinstance(ip.data, dpkt.udp.UDP):
        for i in range(len(time_list)):
           time_diff = time_list[i] - time_list[i-1]

        udp = ip.data
        udp_src_port = udp.sport
        udp_dest_port = udp.dport
        print("{},{},{},{},{},{},{},{},{},{}".format(proto, ip_src_str, ip_dst_str, udp_src_port, udp_dest_port, payload_size, '', date, time, time_diff), file=f)

      # Print out specific protocols such as UDP, ICMP and TCP.

      if isinstance(ip.data, dpkt.icmp.ICMP):
        for i in range(len(time_list)):
            time_diff = time_list[i] - time_list[i-1]

        icmp = ip.data
        icmp_payload_size = len(icmp)
        # Print to stdout
        print("{},{}".format(proto,ip_dst_str))
        print("{},{},{},{},{},{},{},{},{},{}".format(proto,ip_src_str,ip_dst_str,'','',icmp_payload_size,'',date,time, time_diff), file=f)

    #print("Number of packets: {}".format(packets))

  """
  Print out info about each packet in the pcap file

    Args:
      pcap: dpkt pcap reader object
  """


def test():
  # Open a binary file stream of the pcap file
  with open('sniffed.pcap', 'rb') as f:
    # Read the PCAP file
    pcap = dpkt.pcap.Reader(f)
    #print_icmp(pcap)
    process_pcap(pcap)

if __name__ == '__main__':
  test()

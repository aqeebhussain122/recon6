from scapy.all import *
from scapy.layers.http import HTTPRequest
import sys
import datetime
import os
import time
from signal import signal, SIGINT


'''
    Signal handler to end sniffing.
'''
def signal_handler(signal, frame):
	print("\n[!] Sniffing ended [!]")
	sys.exit(0)

def send_icmpv6():
    # Make an IPv6 object
    i = IPv6()
    # Send a multicast to all IPv6 hosts in the network.
    i.dst = "ff02::1"
    # Make a request in order to trigger some behaviour
    q=ICMPv6EchoRequest()
    p=(i/q)
    # Send 100 packets.
    send(p, count=100)

def in6_addrtomac(addr):
    # type: (str) -> Optional[str]
    """
    Extract the mac address from provided address. None is returned
    on error.
    """
    mask = inet_pton(socket.AF_INET6, "::ffff:ffff:ffff:ffff")
    x = in6_and(mask, inet_pton(socket.AF_INET6, addr))
    ifaceid = inet_ntop(socket.AF_INET6, x)[2:]
    return in6_ifaceidtomac(ifaceid)

def network_monitoring(pkt):
	# Packet count - Dynamic count or static count
    current_time = datetime.datetime.now()
    """
    if pkt.haslayer(TCP):
        print("\nPacket is TCP")
        print("Source IP: {}\nDestination IP: {}".format(pkt[IP].src, pkt[IP].dst))
        print("Source port: {}\nDestination port: {}".format(pkt.sport, pkt.dport))
        # We want to extract the MAC addresses and return them in a list which can then get processed.
        print("MAC: {}".format(getmacbyip(pkt[IP].dst)))
    """

    if IPv6 in pkt:
        print("IPv6 packet")
        print(pkt[IPv6].src)

def convert_bytes(size):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0

# Check the size of a file and if it gets too high then stop writing
# https://www.gbmb.org/mb-to-bytes
def check_file_size(cap_file):
	MAX_SIZE = convert_bytes(1073741824)
	if os.path.isfile(cap_file):
		file_info = os.stat(cap_file)
		file_size = file_info.st_size
		# File size condition is done here
		if file_size < 1073741824:
			print("File size is less than {}".format(MAX_SIZE))
		else:
			print("Wiping capture file...")
			os.system("rm {} && touch {}".format(cap_file, cap_file))
			# Wipe the capture echo file and then start again
		return convert_bytes(file_size)
		#return convert_bytes(file_info.st_size)
	else:
		print("A file was not provided")
		return 1

	# if the file size gets to a certain limit of 2MB then absolutely kick offffffff
	# The product can be tested with bigger sizes but development should be a small size to speed things up a little bit
	return file_info

'''
https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
Rather than using the haslayer function for several use cases, instead we could access the internal IPV4 payload structure which will tell us the contained protocol.
'''

def main():
	# Send the icmpv6 request before starting anything else.
    target_interface = sys.argv[1]
    print("[!] Sniffing begins... [!]")
	#print(check_file_size('sniffed.pcap'))
	# prn function is applied to every single packet which is sniffed.
    try:
		# Signal listener so when ctrl + c comes in it kills the program and the cleanup function is called as a result.
        signal(SIGINT, signal_handler)
        while True:
            pkts = sniff(prn=network_monitoring, iface=target_interface, timeout=10)
            write_file =  wrpcap('sniffed.pcap', pkts, append=True)
            print("File size: {}".format(check_file_size('sniffed.pcap')))
    except KeyboardInterrupt:
        sys.exit(0)
			#check_file('sniffed.pcap')
			# Termination signal if true will exit the program 
			# If the pcap file size gets too high then write to another
		# KeyboardInterrupt sends a ctrl + c signal to the program
		#sys.exit("Sniffing ends")
		# If the pcap file size gets too high then write to another
        return 0

if __name__ == '__main__':
	main()

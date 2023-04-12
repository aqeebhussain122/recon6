from scapy.all import *
from scapy.layers.http import HTTPRequest
import sys
import datetime
import os
import time
from signal import signal, SIGINT


'''
	A cleanup function which takes a signal and is recursively called.
	Signal - Linux signal provided to the signal handler e.g. SIGINT
	Frame  - Working function which will behave upon the signal. 
'''
def signal_handler(signal, frame):
	print("\n[!] Sniffing ended [!]")
	sys.exit(0)


# Remove the networking monitoring function
# Create a sniffer function and then implement the file checks
# Stick it into main so this works as a single component before it needs to be merged later

def network_monitoring(pkt):
	# Packet count - Dynamic count or static count
	current_time = datetime.datetime.now()
	'''
	for i in range(len(pkt)):
		print(i)
	partial solution of counting the number of packets
	'''

	if pkt.haslayer(TCP):
		print("\nPacket is TCP")
		print("Source IP: {}\nDestination IP: {}".format(pkt[IP].src, pkt[IP].dst))
		print("Source port: {}\nDestination port: {}".format(pkt.sport, pkt.dport))
	# Test for HTTP inside of the TCP layer
	

	if pkt.haslayer(HTTPRequest):
		# HTTPRequest is analysed and then URL is printed if it's found.
		url = pkt[HTTPRequest].Host.decode()
		print("URL: {}".format(url))

	if pkt.haslayer(UDP):
		print("Packet is UDP")

	if pkt.haslayer(ICMP):
		print("Packet is ICMP")

	# if pkt.haslayer(HTTPS)

	# Return the packet from the function 

# Printing out the protocol type without using haslayer

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
	# prn is a function of the sniff functionality which allows a custom function applied to each packet, we can perform 
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

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
    # If the traffic is of type ARP.
    if pkt[ARP].op == 1:  # who-has (request)
        return f"Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}"
    if pkt[ARP].op == 2:  # is-at (response)
        return f"*Response: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}"

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
	else:
		print("A file was not provided")
		return 1

	# Might need to uncomment later.
	#return file_info


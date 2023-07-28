from scapy.all import *
from scapy.layers.http import HTTPRequest
import sys
import datetime
import os
import time
from signal import signal, SIGINT

'''
   As data is being sniffed via the scan option, the capture_file class will write the data to a file, whilst monitoring its size to make sure it doesn't go overboard.
'''

class capture_file:
    def __init__(self, max_size = 0, cap_file = None):
        self.max_size = max_size
        self.cap_file = cap_file
     
    # Make a function independent parameter called 'size' to make it "one size fits all"
    def convert_bytes(self, size):
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return "%3.1f %s" % (size, x)
            
            size /= 1024.0

        return size

    # Check the size of a file and if it gets too high then stop writing
    # https://www.gbmb.org/mb-to-bytes
    def check_file_size(self):
        # Get the biggest size of the file which is what we declare.
        MAX_SIZE = self.convert_bytes(self.max_size)
        
        # Check it is a file before we do anything and then check if it's even a PCAP or not...
        if os.path.isfile(self.cap_file) and self.cap_file.endswith(".pcap") or self.cap_file.endswith(".pcapng"):
            # We get the base information from the capture file.
            file_info = os.stat(self.cap_file)
            # The file size is internally calculated which we grab from "file_info"
            file_size = file_info.st_size

            # If the internal size is less than our declared limit.
            if file_size < self.max_size:
                # Tell us this.
                print("File size is less than {}".format(MAX_SIZE))
            # If it's not.
            else:
                return "File size is too big"
			    # Wipe thenhe capture echo file and then start again

            # Perform everything based on whether it's a file.
            return self.convert_bytes(file_size)
        else:
            raise Exception("The file is not compatible!")

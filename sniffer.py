from scapy.all import *
from scapy.layers.http import HTTPRequest
import sys
import datetime
import os
import time
from signal import signal, SIGINT

class capture_file:
    def __init__(self, file_size = 0, cap_file = None):
        self.file_size = file_size
        self.cap_file = cap_file
     
    # Make a function independent parameter to make it "one size fits all"
    def convert_bytes(self, size):
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return "%3.1f %s" % (size, x)
            
            size /= 1024.0

        return size

    # Check the size of a file and if it gets too high then stop writing
    # https://www.gbmb.org/mb-to-bytes
    def check_file_size(self):
        # Get the biggest size of the file which is 1GB
        MAX_SIZE = self.convert_bytes(1073741824)
        
        # Check it is a file.
        if os.path.isfile(self.cap_file):
            file_info = os.stat(self.cap_file)
            #file_size = file_info.st_size
            # Get the file size.
            self.file_size = file_info.st_size
		    # File size condition is done here
		    #if file_size < 1073741824:

        if self.file_size < 1073741824:
            print("File size is less than {}".format(MAX_SIZE))
        else:
            print("Wiping capture file...")
            os.system("rm {} && touch {}".format(self.cap_file, self.cap_file))
			    # Wipe thenhe capture echo file and then start again

        return self.convert_bytes(self.file_size)
	    #else:
	#	    print("A file was not provided")
	#	    return 1

	    # Might need to uncomment later.
	    #return file_info


from scapy.all import *
from scapy.layers.http import HTTPRequest
import sys
import datetime
import os
import time
from signal import signal, SIGINT


# Remove the networking monitoring function
# Create a sniffer function and then implement the file checks
# Stick it into main so this works as a single component before it needs to be merged later

class sniffer:

    def __init__(self):
        pass

    def network_monitoring(pkt):
        # If the traffic is of type ARP.
        if pkt[ARP].op == 1:  # who-has (request)
            return f"Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}"
        if pkt[ARP].op == 2:  # is-at (response)
            return f"*Response: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}"

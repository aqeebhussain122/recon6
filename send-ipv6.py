from scapy.all import *

i = IPv6()
# Send a multicast to all IPv6 hosts in the network.
i.dst = "ff02::1"
q=ICMPv6EchoRequest()
p=(i/q)
send(p, count=100)

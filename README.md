# recon6 - (IPv6 Sniffing Tool)

Description: Recon6 is a network sniffer using various Python libraries such as Scapy and PyShark in order to locate link local IPv6 addresses.

# Initial release: 25/07/2023

Information: The product is still under development with only the informational component completed. In order to make use of recon6 with "informational" capabilities, a populated PCAP file is required in which ARP packets or pings are made to target subnet(s) with a listening instance of tcpdump or Wireshark. Furthermore, IPv6 calls must be made within the internal network using the following syntax: `ping6 -I (Name of Network Interface) -c 4 ff02::1`

Once this data has been captured, proceed to use recon6 with the syntax of: 
`python3 read_pcap.py -i (PCAP filename)`

If you have packages which are not installed for this software, please run the `install.sh` installation script which will install required packages.

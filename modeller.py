#! /usr/bin/env python

import sys
from scapy.all import *

# PCAP READ AND PARSE #
"""

pkts = rdpcap("pcap/ftp2.pcap")

# P1. Collect FTP pkts which contain Messages

client_ip = ""
server_ip = ""
req_raw_paylds = []
res_raw_paylds = []

i = 0
for pkt in pkts:
	i = i+1
	raw_string = pkt.getlayer(Raw)
	ip = pkt.getlayer(IP)
	if raw_string != None :
		if server_ip == "":
			server_ip = ip.src
		if client_ip == "" and server_ip != ip.src:
			client_ip = ip.src
		if ip.dst == server_ip:
			req_raw_paylds.append(raw_string)
		elif ip.dst == client_ip:
			res_raw_paylds.append(raw_string)


print "IP of client : ", client_ip
print "IP of server : ", server_ip
print "[[[ REQUESTS ]]]"
for str in req_raw_paylds:
	print str
print "[[[ RESPONSES ]]]"
for str in res_raw_paylds:
	print str

# P2. Compare each FTP payload with previously stored tokens

# -- varible strings to be stored as each tuple ([payload], ([begin_index], [end_index]))
variable_paylds = []

for req_payld in req_raw_paylds:
"""

if len(sys.argv) < 3:
	print "Please specify the destination IP and payload\n"

dst_ip = sys.argv[1]
payload = sys.argv[2]

p = IP(dst=dst_ip)/TCP()/payload

p

# Generate message



# Send message and listen
#! /usr/bin/env python

import sys
from scapy.all import *

pkts = rdpcap("pcap/ftp2.pcap")
client_ip = ""
server_ip = ""
req_raw_strings = []
res_raw_strings = []


#print ls(pkts[3])
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
			req_raw_strings.append(raw_string)
		elif ip.dst == client_ip:
			res_raw_strings.append(raw_string)

print "IP of client : ", client_ip
print "IP of server : ", server_ip
print "[[[ REQUESTS ]]]"
for str in req_raw_strings:
	print str
print "[[[ RESPONSES ]]]"
for str in res_raw_strings:
	print str



# P1. Collect FTP pkts which contain Messages

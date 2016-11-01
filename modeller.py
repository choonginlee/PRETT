#! /usr/bin/env python

import sys
import pickle
import time
from scapy.all import *

# INSTRUCTION #
# To run modeller, you have to specify target IP address with arguement.
# EX ) sudo python modeller.py [target IP]
# Before launch the modeller, you have to change the kernel setting to avoid from automatic TCP RST.
# Just type the command below in the terminal 
# $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# Have fun !!

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

# -- varible strings to be stored as each tuple ([payload], [token], ([begin_index], [end_index]))
variable_paylds = []
token_db = []

"""

def handshake(dst_ip, dport, sport):
	#Initiate TCP connection - 3 handshaking
	print "[+] ======== Hand Shaking ========"
	SYN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = "S") # SYN
	SYN_ACK = sr1(SYN) # Listen ACK
	ACK1 = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=SYN_ACK.ack, ack=SYN_ACK.seq + 1, flags = "A") # SYN - ACK
	RESPONSE = sr1(ACK1) # Listen ACK

	#Next Ack no. calculation : last seq + prev. tcp payload len
	ACK2 = generate_ftp_ack(RESPONSE)
	send(ACK2)
	print "[+] Handshake over."
	print "[+] ===============================\n"
	return RESPONSE

def disconnect_ftp(rp):
	print "[+] ======== Disconnection ========"
	p = generate_ftp_msg("QUIT", rp)
	ans, unans = sr(p, multi=1, timeout=0.3, verbose=0) # SEND -> GET ACK -> GET RESPONSE (normal case)

	for snd, rcv in ans:
		if rcv.haslayer("Raw"):
			# FTP packet received
			#print "[+] FTP PACKET ::: \n"
			print "[+] RESPONSE FTP PAYLOAD : ", rcv.getlayer("Raw").load # this is protocol response message
			rp = rcv
			ack_p = generate_ftp_ack(rp) # ACK to the last Response
			send(ack_p)

	# Finally, send FIN, ACK to the server
	fin_ack_p = generate_ftp_fin_ack(rp)
	send(fin_ack_p)
	print "[+] FTP disconnected\n"

def generate_ftp_ack(rp):
	tcp_seg_len = len(rp.getlayer(Raw).load)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = "A")
	return p

def generate_ftp_fin_ack(rp):
	tcp_seg_len = len(rp.getlayer(Raw).load)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = 0x11)
	return p

def generate_ftp_msg(payload, rp) :
	tcp_seg_len = len(rp.getlayer(Raw).load)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = 0x18)/(payload+delimiter)
	return p

def clear_tcp_connection(dst_ip, dport, sport):
	#Clear TCP connection
	FIN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = 0x11) # FIN
	FIN_ACK = sr1(FIN)
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq + 1, flags = "A")
	send(ACK)
	print "[+] TCP connection clean ... "

dst_ip = sys.argv[1]
dport = 21
sport = 1005
delimiter = "\r\n"

"""
if len(sys.argv) == 3 and sys.argv[2] == "clean":
	clear_tcp_connection(dst_ip, dport, sport)
	sys.exit()
else :
	rp = handshake(dst_ip, dport, sport)
"""

mode = raw_input("[!] Manual? or Auto? (m / a) : ")

if mode == 'm':
	rp = handshake(dst_ip, dport, sport)

	for i in range(10) :
		payload = raw_input("[!] payload? : ")
		p = generate_ftp_msg(payload, rp)
		print p.getlayer("Raw").show()
		if raw_input("[ ] Send Packet? (y/n) : ") != 'y' :
			print "[+] Program ends... \n"
			break
		ans, unans = sr(p, multi=1, timeout=0.3, verbose=0) # SEND -> GET ACK -> GET RESPONSE (normal case)
		#print "[+] %d packets received." % len(ans)

		for snd, rcv in ans:
			if rcv.haslayer("Raw"):
				# FTP packet received
				#print "[+] FTP PACKET :::"
				print "[+] RESPONSE FTP PAYLOAD : ", rcv.getlayer("Raw").load # this is protocol response message
				rp = rcv
				ack_p = generate_ftp_ack(rp)
				send(ack_p)

elif mode == 'a' :
	with open("./tokenfile/total_tokens.txt") as f:
		token_db = pickle.load(f)

	# Simple message format ( 1 word )
	for token in token_db:
		sport = int(RandShort())

		#Start with 3WHS
		rp = handshake(dst_ip, dport, sport)
		payload = token[0]

		# Generate message from tokens
		p = generate_ftp_msg(payload, rp)
		print "[+] Message to be sent \n", p.getlayer("Raw").show()
		if raw_input("[?] Send Packet? (y/n) : ") != 'y' :
			print "[+] Program ends... \n"
			break

		# Send message and listen
		ans, unans = sr(p, multi=1, timeout=0.3, verbose=0) # SEND -> GET ACK -> GET RESPONSE (normal case)
		i = 0

		for snd, rcv in ans:
			if rcv.haslayer("Raw"):
				i = i + 1
				print "[+] FTP Response %d received.\n" % i
				# FTP packet received
				#print "[+] FTP PACKET :::"
				print "[+] RESPONSE FTP PAYLOAD : ", rcv.getlayer("Raw").load # this is protocol response message
				rp = rcv
				ack_p = generate_ftp_ack(rp)
				send(ack_p)
				print "[+] ACK sent."

		# Finish TCP connection
		# Request QUIT -> TCP FIN Handshake
		disconnect_ftp(rp)
		time.sleep(1)

else :
	print "[-] Invalid Input... exit...\n"
	sys.exit()


"""
for payld in req_raw_paylds:
	for token in token_db:
		if token[1] > 1:
			index = payld.load.lower().find(token[0], 0)
			if index >= 0:
				tuple_data = (payld.load, token[0], (index, index+len(token[0])))
				variable_paylds.append(tuple(tuple_data))

for item in variable_paylds :
	print item

print len(variable_paylds), "Variable payloads found"

"""


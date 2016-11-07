#! /usr/bin/env python
import os
import sys
import pickle
import logging
import time
import re
import matplotlib.pyplot as pyplot
import matplotlib.image as mplotimg
from transitions.extensions import GraphMachine as Machine
from scapy.all import *

# INSTRUCTION #
# To run modeller, you have to specify target IP address with arguement.
# EX ) sudo python modeller.py [target IP]
# Before launch the modeller, you have to change the kernel setting to avoid from automatic TCP RST.
# Just type the command below in the terminal 
# $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# Have fun !!

#Contains a FTP Protocol model
class FTPModel(object):
	def __init__(self, name):
		self.name = name

def handshake(dst_ip, dport, sport):
	#Initiate TCP connection - 3 handshaking
	logging.info("[+] ======== Hand Shaking ========\n")
	SYN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = "S") # SYN
	SYN_ACK = sr1(SYN, verbose=False) # Listen ACK
	ACK1 = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=SYN_ACK.ack, ack=SYN_ACK.seq + 1, flags = "A") # SYN - ACK
	RESPONSE = sr1(ACK1, verbose=False) # Listen ACK

	#Next Ack no. calculation : last seq + prev. tcp payload len
	ACK2 = generate_ftp_ack(RESPONSE)
	send(ACK2, verbose=False)
	logging.info("[+] Handshake over.")
	logging.info("[+] ===============================\n")
	return RESPONSE

def disconnect_ftp(rp):
	logging.info("[+] ======== Disconnection ========\n")
	p = generate_ftp_msg("QUIT", rp)
	ans, unans = sr(p, multi=1, timeout=0.1, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)

	for snd, rcv in ans:
		if rcv.haslayer("Raw"):
			# FTP packet received
			#logging.info("[+] FTP PACKET ::: \n")
			#print "[+] RESPONSE FTP PAYLOAD : \n", rcv.getlayer("Raw").load # this is protocol response message
			rp = rcv
			ack_p = generate_ftp_ack(rp) # ACK to the last Response
			send(ack_p, verbose=False)

	# Finally, send FIN, ACK to the server
	fin_ack_p = generate_ftp_fin_ack(rp)
	send(fin_ack_p, verbose=False)
	logging.info("[+] FTP disconnected\n")

def build_state_machine(sm, crnt_state, spyld, rpyld):
	# sm : state machine, crnt_state : current state, payload : response packet payload 
	
	# Build and fix a state machine based on the response
	global num_of_states, transition_info

	#Check if the response already seen before
	for t in sm.get_triggers(crnt_state):
		#logging.info("Trigger t : \n", t)
		if re.search(rpyld, t):
			# if it is already seen,
			# - No need to make new state
			# - Find the corresponding src & dst state
			# - Add new transition
			"""
			t_label = spyld + "," + t
			dst_state = transition_info.get(t)[1]
			sm.add_transition(t_label, source = crnt_state, dest = dst_state) # add transition
			transition_info[t_label] = [crnt_state, dst_state] # add transition info
			"""
			return
		
	#If not seen before,
	# - Add a new state
	# - Add a new transition from current state
	num_of_states = num_of_states + 1
	dst_state = str(num_of_states)
	sm.add_states(dst_state)

	t_label = spyld + " / " + rpyld
	sm.add_transition(t_label, source = crnt_state, dest = dst_state)
	transition_info[t_label] = [crnt_state, dst_state] # add transition info

def generate_ftp_model():
	ftpmodel = FTPModel("FTP Model")
	ftpmachine = Machine(model = ftpmodel, states = ['0'], initial = '0', auto_transitions=False)
	return ftpmachine

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
	FIN_ACK = sr1(FIN, verbose=False)
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq + 1, flags = "A")
	send(ACK, verbose=False)
	logging.info("[+] TCP connection clean ... \n")


logging.basicConfig(level=logging.DEBUG, filename="ptmsg_log", filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")

dst_ip = sys.argv[1]
dport = 21
sport = 1005
delimiter = "\r\n"
num_of_states = 0

#Mode Selection
mode = raw_input("[!] Manual? or Auto? ( \'m\' - for testing / \'a\' - basic mode) : ")

#Crate ftp machine and assign protocol model
ftpmachine = generate_ftp_model()

# It will contain trasition info like 
# trigger as key (string) : [src_state (string), [dest_state (string)]]
transition_info = {}

cnt = 0

# Disable Kernel's RST in iptable
os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

if mode == 'm':
	rp = handshake(dst_ip, dport, sport)

	for i in range(10) :
		payload = raw_input("[!] payload? : ")
		p = generate_ftp_msg(payload, rp)
		logging.info(p.getlayer("Raw").show())
		if raw_input("[ ] Send Packet? (y/n) : ") != 'y' :
			# Disconnect with pretty FIN ANK

			print "[+] Program ends... \n"
			break
		ans, unans = sr(p, multi=1, timeout=0.1, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)

		for snd, rcv in ans:
			if rcv.haslayer("Raw"):
				# FTP packet received
				#logging.info("[+] FTP PACKET :::\n")
				logging.info("[+] RESPONSE FTP PAYLOAD : \n", rcv.getlayer("Raw").load) # this is protocol response message
				rp = rcv
				ack_p = generate_ftp_ack(rp)
				send(ack_p, verbose=False)

elif mode == 'a' :
	with open("./tokenfile/total_tokens.txt") as f:
		token_db = pickle.load(f)

	# Simple message format ( 1 word )
	for token in token_db:
		sport = sport + 1
		cnt = cnt + 1

		#Start with 3WHS
		rp = handshake(dst_ip, dport, sport)
		payload = token[0]

		# Generate message from tokens
		p = generate_ftp_msg(payload, rp)
		#print "[+] Message to be sent \n", p.getlayer("Raw").show()

		"""
		if cnt % 10000 == 0 and raw_input("[?] Trial %d, Send Packet? (y/n) : " % cnt) != 'y' :
			# Disconnect with pretty FIN ANK
			disconnect_ftp(rp)
			print "[+] Program ends... \n"
			break
		"""

		# Send message and listen
		ans, unans = sr(p, multi=1, timeout=0.1, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
		i = 0

		for snd, rcv in ans:
			if rcv.haslayer("Raw"):
				i = i + 1
				logging.info("[+] FTP Response %d received.\n" % i)
				sentpayload = snd.getlayer("Raw").load
				rcvdpayload = rcv.getlayer("Raw").load
				logging.info("[+] RESPONSE FTP PAYLOAD : " + rcvdpayload + "\n") # this is protocol response message
				rp = rcv
				ack_p = generate_ftp_ack(rp)
				send(ack_p, verbose=False)
				logging.info("[+] FTP ACK sent.\n")
				build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
		
		# Finish TCP connection
		# Request QUIT -> TCP FIN Handshake
		disconnect_ftp(rp)

		#Initialize current state as 0
		cs = 0

		if cnt % 1000 == 0 :
			graphname = "diagram/sample_state" + str(cnt) + ".png"
			ftpmachine.model.graph.draw(graphname, prog='dot')
			#img = mplotimg.imread("diagram/sample_state.png")
			#plt.imshow(img)
			#plt.show()
		
	# Program normally ends.
	ftpmachine.model.graph.draw("diagram/sample_state_fin.png", prog='dot')
	img = mplotimg.imread("diagram/sample_state_fin.png")
	plt.imshow(img)
	plt.show()
	sys.exit()

else :
	print "[-] Invalid Input... exit...\n"
	sys.exit()

""" ============ APPENDIX ============ """

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


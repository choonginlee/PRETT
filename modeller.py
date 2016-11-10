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

class State:
	def __init__(self, numb, parent=None, token=None, token_index=0):
		self.numb = numb
		self.parent = parent
		self.token = token
		self.token_index = token_index


class StateList:
	def __init__(self, state_list=[]):
		self.state_list = state_list

	def add_state(self, state):
		self.state_list.append(state)

state_numb_list = [0]
current_state = 0
state_list = StateList()
sample = State(0)
state_list.add_state(sample)

def handshake_init(dst_ip, dport, sport):
	#Initiate TCP connection - 3 handshaking
	logging.info("[+] ======== Hand Shaking ========\n")
	SYN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = "S") # SYN
	SYN_ACK = sr1(SYN, verbose=False) # Listen ACK
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=SYN_ACK.ack, ack=SYN_ACK.seq + 1, flags = "A") # SYN - ACK
	RESPONSE = sr1(ACK, verbose=False) # Send ACK, Listen FTP Response
	logging.info("[+] Handshake over.")
	logging.info("[+] ===============================\n")

	return RESPONSE # This is FTP Response from server

def disconnect_ftp(rp):
	# Send Req. QUIT (c) -> Get Resp Goodbye (s) -> get FIN-ACK (s) -> send ACK (c) -> Send FIN-ACK (c) -> get ACK
	logging.info("[+] ======== Disconnection ========\n")
	start_time = time.time()

	p = generate_ftp_msg("QUIT", rp)
	# Listen FIN-ACK
	ans, unans = sr(p, filter = "tcp", multi=1, timeout=0.015, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
	
	"""
	if len(ans) == 0 :
		logging.error("No packet in timeout!")
		rp = sniff(filter = "tcp", timeout = 10, count = 2)
		if len(rp) == 0:
			logging.error("It takes too long time! abort...")
			sys.exit()
	elif len(ans) == 1 :
		logging.error("Not enough packet in timeout!")
		# Wait for the next packet
		rp = sniff(filter = "tcp", timeout = 10, count = 1)
		if len(rp) == 0:
			logging.error("It takes too long time! abort...")
			sys.exit()
		else:
			ans[1][1] = rp
			pass

	elif len(ans) == 2 :
		pass
		
	elif len(ans) >= 3:
		logging.error("Unexpected packet received.")
		return
	"""

	if len(ans) < 2:
		return

	FIN_ACK = ans[1][1]

	#elapsed_time = time.time() - start_time
	#print "After sniffing and parsing FIN-ACK..." + str(elapsed_sudo time) + "\n"

	# Send ack to fin-ack
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq, flags = "A") # SYN - ACK
	send(ACK, verbose=False)

	#elapsed_time = time.time() - start_time
	#print "After sending ack to finack..." + str(elapsed_time) + "\n"

	# Finally, send FIN, ACK to the server
	FIN_ACK = generate_ftp_fin_ack(FIN_ACK)
	send(FIN_ACK, verbose=False)

	logging.info("[+] FTP disconnected\n")

def send_receive_ftp(rp, token):
	# SEND Req. -> Get ACK -> GET Rep. -> Send ACK (normal TCP-based protocol)
	global cnt
	temp_rp = rp
	cnt = cnt + 1
	start_time = time.time()

	# Generate message from tokens
	payload = token[0]
	p = generate_ftp_msg(payload, rp)
	#print "[+] Message to be sent \n", p.getlayer("Raw").show()

	"""
	if cnt % 10000 == 0 and raw_input("[?] Trial %d, Send Packet? (y/n) : " % cnt) != 'y' :
		# Disconnect with pretty FIN ANK
		disconnect_ftp(rp)
		print "[+] Program ends... \n"
		sys.exit()
	"""

	# Send Req, then get ACK and Resp of tcp
	ans, unans = sr(p, filter = "tcp", multi=1, timeout=0.015, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
	
	if len(ans) == 0:
		logging.debug("No packet in short timeout!")
		# It takes long time to get... sniff single tcp packet and determine...
		rp = sniff(filter = "tcp", timeout = 10, count = 1)
		if len(rp) == 0:
			logging.error("It takes too long time! abort...")
			return temp_rp
		else:
			sentpayload = p.getlayer("Raw").load
			rcvdpayload = rp.getlayer("Raw").load
			logging.info("[+] RESPONSE FTP PAYLOAD : " + rcvdpayload + "\n") # this is protocol response message
			ack_p = generate_ftp_ack(rcv)

			#elapsed_time = time.time() - start_time
			#print "After sniffing and parsing ftp..." + str(elapsed_time) + "\n"

			logging.debug("Got Response : "+str(rp.getlayer(Raw).load))

			send(ack_p, verbose=False)
			logging.info("[+] FTP ACK sent.\n")
			build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
			return rp

	for sp, rp in ans:
		if rp.haslayer("Raw"):
			sentpayload = sp.getlayer("Raw").load
			rcvdpayload = rp.getlayer("Raw").load
			logging.info("[+] RESPONSE FTP PAYLOAD : " + rcvdpayload + "\n") # this is protocol response message
			ack_p = generate_ftp_ack(rp)
			#elapsed_time = time.time() - start_time
			#print "After sniffing and parsing ftp..." + str(elapsed_time) + "\n"
			logging.debug("Got Response : "+str(rp.getlayer(Raw).load))
			send(ack_p, verbose=False)
			logging.info("[+] FTP ACK sent.\n")
			build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
			return rp

	logging.debug("No response FTP packet!")
	sys.exit()

def check_ftp_resp(pkt):
	global start_time
	#elapsed_time = time.time() - start_time
	#print "After calling filter..." + str(elapsed_time) + "\n"
	if pkt.haslayer(Raw) :
		#elapsed_time = time.time() - start_time
		#print "After raw check..." + str(elapsed_time) + "\n"
		return True
	else :
		return False

def check_fin_ack(pkt):
	# Cheeck if it is TCP fin-ack
	if pkt.haslayer(TCP) and pkt[TCP].flags == 0x11 :
		return True
	else :
		return False

def generate_ftp_model():
	ftpmodel = FTPModel("FTP Model")
	ftpmachine = Machine(model = ftpmodel, states = ['0'], initial = '0', auto_transitions=False)
	return ftpmachine

def generate_ftp_ack(rp):
	# Generates ack message to FTP Response packet
	tcp_seg_len = len(rp.getlayer(Raw).load)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = "A")
	return p

def generate_ftp_fin_ack(rp):
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+1, flags = 0x11)
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

def build_state_machine(sm, crnt_state, spyld, rpyld):
	# sm : state machine, crnt_state : current state, payload : response packet payload 
	
	# Build and fix a state machine based on the response
	global num_of_states, transition_info, state_numb_list, state_list, current_state

	#Check if the response already seen before
	for t in sm.get_triggers(crnt_state):
		#logging.info("Trigger t : \n", t)
		if re.search(rpyld, t):
			# if it is already seen,
			# - No need to make new state
			# - Find the corresponding src & dst state
			# - Add input counts for each seen transition
			transition_info[t][2] = transition_info[t][2] + 1
			return
		
	#If not seen before,
	# - Add a new state
	# - Add a new transition from current state
	num_of_states = num_of_states + 1
	dst_state = str(num_of_states)
	sm.add_states(dst_state)

	t_label = spyld + " / " + rpyld
	sm.add_transition(t_label, source = crnt_state, dest = dst_state)
	transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info
	state_numb_list.append(num_of_states)	
	state_list.add_state(State(num_of_states, current_state, spyld))

logging.basicConfig(level=logging.DEBUG, filename="ptmsg_log", filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")

dst_ip = sys.argv[1]
dport = 21
sport = 1005
delimiter = "\r\n"
num_of_states = 0
g_start_time = 0

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
g_start_time = time.time()

if mode == 'm':
	rp = handshake_init(dst_ip, dport, sport)
	#Next Ack no. calculation : last seq + prev. tcp payload len
	ftp_ack = generate_ftp_ack(rp)
	send(ftp_ack, verbose=False)

	for i in range(10) :
		payload = raw_input("[!] payload? : ")
		p = generate_ftp_msg(payload, rp)
		logging.info(p.getlayer("Raw").show())
		if raw_input("[ ] Send Packet? (y/n) : ") != 'y' :
			# Disconnect with pretty FIN ANK

			print "[+] Program ends... \n"
			break

		ans, unans = sr(p, multi=1, timeout=0.01, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)

		for sp, rcv in ans:
			if rcv.haslayer("Raw"):
				# FTP packet received
				#logging.info("[+] FTP PACKET :::\n")
				logging.info("[+] RESPONSE FTP PAYLOAD : \n", rcv.getlayer("Raw").load) # this is protocol response message
				rp = rcv
				ack_p = generate_ftp_ack(rp)
				send(ack_p, verbose=False)

elif mode == 'b' :
	# bfs
	with open("./tokenfile/total_tokens.txt") as f:
		token_db = pickle.load(f)

	while True:

		if current_state > num_of_states:
			break

		move_state_token =[]
		target_state = current_state

		while True:
			current_parent = state_list.state_list[target_state].parent
			if current_parent is not None:
				move_state_token.insert(0, state_list[target_state].token)
				target_state = current_parent
				continue
			else: # root node
				break;

		# Simple message format ( 1 word )
		for token in token_db:
			if token[0] == "quit":
				continue
			sport = sport + 1

			#Start with 3WHS
			rp = handshake_init(dst_ip, dport, sport)

			#If handshake finished, the server sends response. Send ack and get the last req packet info.
			ftp_ack = generate_ftp_ack(rp)
			send(ftp_ack, verbose=False)

			for tk in move_state_token:
				rp = send_receive_ftp(rp, tk)
			
			# Send message and listen
			rp = send_receive_ftp(rp, token)

			# Finish TCP connection
			disconnect_ftp(rp)

			#Initialize current state as 0
			cs = 0

			if cnt % 1000 == 0 :
				elapsed_time = time.time() - g_start_time
				print "[+] COUNT OF TRIALS : %d" % cnt, "Time Elapsed :", elapsed_time, "s"
				graphname = "diagram/sample_state" + str(cnt) + ".png"
				ftpmachine.model.graph.draw(graphname, prog='dot')
				#img = mplotimg.imread("diagram/sample_state.png")
				#plt.imshow(img)
				#plt.show()
				
		current_state = current_state + 1
	
	elapsed_time = time.time() - g_start_time
	print "Total elapsed time : ", elapsed_time, "\n"
	# Program normally ends.
	ftpmachine.model.graph.draw("diagram/sample_state_bfs_fin.png", prog='dot')
	logging.info(transition_info)
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


#! /usr/bin/env python
import os
import sys
import pickle
import logging
import time
import re
import json
import matplotlib.pyplot as pyplot
import matplotlib.image as mplotimg
from transitions.extensions import GraphMachine as Machine
from scapy.all import *
from collections import OrderedDict

# INSTRUCTION #
# To run modeller, you have to specify target IP address with arguement.
# EX ) sudo python modeller.py [target IP]
# Before launch the modeller, you have to change the kernel setting to avoid from automatic TCP RST.
# Just type the command below in the terminal 
# $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# Have fun !!

# Disable Kernel's RST in iptable
os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

# Delete all the previous files
os.system("rm -rf ./ptmsg_log")
os.system("rm -rf ./diagram/*")

logging.basicConfig(level=logging.DEBUG, filename="ptmsg_log", filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")

sport = 1000 # find sport here

dst_ip = sys.argv[1]
if len(sys.argv) == 3:
	sport = int(sys.argv[2])

#These informations are prerequisite.
dport = 21

delimiter = "\r\n"
exit_label = "QUIT / 221 Goodbye."
num_of_states = 0
g_start_time = 0
state_found = 0
mul_start = 0
new_state = []
myiface = "enp0s8"
is_pruning = 0

level_dict = {1 : ['0']}
cur_state = '0'
timeout = 0.01
sniff_timeout = 5
long_timeout = 15
depth_count = 0
current_level = 1

if not os.path.exists('./diagram'):
	os.makedirs('./diagram')

#Mode Selection
mode = raw_input("[!] Manual? or Auto(BFS, DFS)? ( \'m\' - for testing / \'b\' - bfs mode / \'d\' - dfs mode / \'p\' - prune mode /) : ")

# It will contain trasition info like 
# trigger as key (string) : [src_state (string), dest_state (string), cnt]
transition_info = {}
mul_transition_info = {}

g_start_time = time.time()
skt = conf.L3socket(iface = myiface)

#Contains a FTP Protocol model
class FTPModel(object):
	def __init__(self, name):
		self.name = name


class State:
	def __init__(self, numb, parent=None, spyld=None, rpyld=None):
		self.numb = numb
		self.parent = parent
		self.spyld = spyld
		self.rpyld = rpyld


class StateList:
	def __init__(self, state_list=[]):
		self.state_list = state_list

	def add_state(self, state):
		self.state_list.append(state)

	def remove_state(self, state):
		self.state_list.remove(state)

	def find_state(self, numb):
		for state in self.state_list:
			if state.numb == numb:
				return state
		return None

state_list = StateList([State('0')])

def handshake_init(dst_ip, dport, sport):
	#Initiate TCP connection - 3 handshaking
	global skt
	SYN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = "S") # SYN
	SYN_ACK = skt.sr1(SYN, verbose=False, retry=-1) # Listen ACK
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=SYN_ACK.ack, ack=SYN_ACK.seq + 1, flags = "A") # SYN - ACK
	RESPONSE = skt.sr1(ACK, verbose=False, retry=-1) # Send ACK, Listen FTP Response
	#logging.info("[+] Handshake over.")

	return RESPONSE # This is FTP Response from server


def disconnect_ftp(rp):
	# Send Req. QUIT (c) -> Get Resp Goodbye (s) -> get FIN-ACK (s) -> send ACK (c) -> Send FIN-ACK (c) -> get ACK
	start_time = time.time()
	global timeout, skt, finack_timeout, sniff_timeout

	temp_rp = rp
	p = generate_ftp_msg("quit", rp)
	# Listen FIN-ACK
	ans, unans = skt.sr(p, multi=1, timeout=timeout*5, verbose=False) # SEND -> GET RESPONSE (normal case) -> GET FINACK
	ans = filter_tcp_ans(ans)

	FIN_ACK = None

	# Found FINACK in 2 or 3 packets
	for sp, rp in ans:
		if rp.getlayer("TCP").flags == 0x11:
			FIN_ACK = rp

	# Second barrier
	if FIN_ACK is None:
		rp = sniff(filter = "tcp", iface = myiface, timeout = timeout*5, count = 10)
		for pkt in rp:
			if pkt.haslayer("TCP"):
				FIN_ACK = pkt 

	# Third barrier, Timeout checker
	while True:
		if FIN_ACK is not None:
			break
		else:
			rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 1)
			if len(rp) == 0:
				# Timeout (Internal server error). No FINACK at all
				logging.debug("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all" % sport)
				for sp, rp in ans:
					if rp.haslayer("TCP"):
						FIN_ACK = rp # not FINACK
				# SUCKS!
				logging.debug("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all. No answered in sr." % sport)
				FIN_ACK = temp_rp
			elif rp[0].getlayer("TCP").flags == 0x11:
				# FIN_ACK found
				FIN_ACK = rp[0]
			else:
				continue
	# 2 or 3
	# 2 : 0 -> listen 2
	# 2 : 1 -> listen 1

	# 3 : 0 -> listen 3
	# 3 : 1 -> listen 2
	# 3 : 2 -> listen 3

	# listen in short time --> check any fin in the lst --> if yes, then ACK and FINACK
	#												  --> if no, listen long time for 1 packet
	#																						--> if yes, ACK and FINACK
	#																						--> if no, if no, listen long time for 1 packet
	"""
	
	if len(ans) == 0 :
		rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 2)
		if len(rp) == 2 :
			for pkt in rp:
				if pkt.getlayer("TCP").flags == 0x11:
					FIN_ACK = pkt

		elif len(rp) == 1 :
			logging.debug("[!] [port no. %d] DISCONNECT : Only one packet" % sport)
			FIN_ACK = rp[0] # not FINACK
		else :
			logging.debug("[!] [port no. %d] DISCONNECT : No packet in 5 secs" % sport)
			sys.exit()

	elif len(ans) == 1 :
		# FINACK not yet found. Listen for FINACK again
		rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 1)
		if len(rp) > 0 and rp[0].getlayer("TCP").flags == 0x11:
			FIN_ACK = rp[0]
		else :
			logging.debug("[!] [port no. %d] DISCONNECT : No FINACK" % sport)
			for sp, rp in ans:
				if rp.getlayer("TCP").flags == 0x11:
					FIN_ACK = rp # not FINACK
			
	elif len(ans) == 2 :
		for sp, rp in ans:
			if rp.getlayer("TCP").flags == 0x11:
				FIN_ACK = rp

	else :
		logging.debug("[!] [port no. %d] DISCONNECT : Answer length is %d. Strange packet is in." % (sport, len(ans)))
		# print ans.summary()
		for sp, rp in ans:
			if rp.getlayer("TCP").flags == 0x11:
				FIN_ACK = rp
	"""
	
	# Send ack to fin-ack
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq, flags = "A") # SYN - ACK
	skt.send(ACK)
	
	# Finally, send FIN, ACK to the server
	FIN_ACK = generate_ftp_fin_ack(FIN_ACK)
	skt.send(FIN_ACK)
		
def send_receive_ftp(rp, payload):
	# SEND Req. -> Get ACK -> GET Rep. -> Send ACK (normal TCP-based protocol)
	global skt, timeout, sniff_timeout, long_timeout, mul_start
	origin_rp = rp
	start_time = time.time()

	# Generate message from tokens
	p = generate_ftp_msg(payload, rp)

	# Send Req, then get 1. ACK and 2. FTP response
	ans, unans = skt.sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
	ans = filter_tcp_ans(ans)

	if len(ans) == 0:
		logging.debug("[!] [port no. %d] Answer length is 0. Check wireshark" % sport)
		
		rp = sniff(filter = "tcp", iface = myiface, timeout = long_timeout, count = 2)
		if len(rp) < 2:
			# Timeout (Internal server error). Pass to disconnect.
			return origin_rp
		else:
			# Good 2 packets
			for pkt in rp:
				if pkt.haslayer("Raw"):
					return send_ftp_ack_build(p, pkt)
					
	elif len(ans) == 1:
		logging.debug("[ ] [port no. %d] Answer length is 1." % sport)

		# FTP reponse -> ACK (Strange, but normal)
		for sp, rp in ans:
			if rp.haslayer("Raw"):
				return send_ftp_ack_build(sp, rp)

		# Maybe waiting for the FTP response
		rp = sniff(filter = "tcp", iface = myiface, timeout = long_timeout, count = 1)

		# FTP response obtained (Good)
		# ACK -> FTP response (Auth)
		if len(rp) > 0 and rp[0].haslayer("Raw") :
			# It is normal FTP.
			return send_ftp_ack_build(p, rp[0])

		# No packet after ACK
		else:
			logging.debug("[+] [port no. %d] Waited for 15 seconds... Timeout!" % sport)
			return origin_rp

	# Got ACK and FTP response
	elif len(ans) == 2:
		for sp, rp in ans:
			if rp.haslayer("Raw"):
				return send_ftp_ack_build(sp, rp)

		# Strange packet is in
		logging.debug("[!] [port no. %d] Answer length is 2. not yet found FTP Response." % sport)
		rp = sniff(filter = "tcp", iface = myiface, timeout = timeout, count = 10)
		for pkt in rp:
			if pkt.haslayer("Raw"):
				return send_ftp_ack_build(p, pkt)	

	# More than 3 tcp packets
	else:
		for sp, rp in ans:
			if rp.haslayer("Raw"):
				return send_ftp_ack_build(sp, rp)

		logging.debug("[!] [port no. %d] Answer length is %d. not yet found FTP Response." % (sport, len(ans)))
		rp = sniff(filter = "tcp", iface = myiface, timeout = timeout, count = 10)
		for pkt in rp:
			if pkt.haslayer("Raw"):
				return send_ftp_ack_build(p, pkt)	

		# Timeout (Internal server error). Pass to disconnect.
		return origin_rp

def send_ftp_ack_build(sp, rp):
	global skt, ftpmachine, mul_start
	sentpayload = sp.getlayer("Raw").load.replace('\r\n', '')
	rcvdpayload = rp.getlayer("Raw").load.replace('\r\n', '')
	if mul_start == 1 and rcvdpayload.find("ogin") >= 0:
		logging.debug("[port no. %d] [SEND_FTP_ACK_BUILD] " % sport + rcvdpayload)
	ack_p = generate_ftp_ack(rp)				
	skt.send(ack_p)
	build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
	return rp

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
	ftpmachine.add_transition(exit_label, source = '0', dest = '0')
	return ftpmachine

def get_tcp_seg_len(rp):
	ip_total_len = rp.getlayer(IP).len
	ip_header_len = rp.getlayer(IP).ihl * 32 / 8
	tcp_header_len = rp.getlayer(TCP).dataofs * 32/8
	tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len
	return tcp_seg_len
	
def generate_ftp_ack(rp):
	# Generates ack message to FTP Response packet
	tcp_seg_len = get_tcp_seg_len(rp)
	#tcp_seg_len = len(rp.getlayer("TCP"))-len(rp.getlayer("IP").options)-len(rp.getlayer("TCP").options)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = "A")
	#logging.info("[+] [GEN FTP ACK] - PKT GEN OVER.")
	return p

def generate_tcp_ack(rp): 
	# Generate ack to the normal tco (ack to the ack)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq, flags = "A")
	return p

def generate_ftp_fin_ack(rp):
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+1, flags = 0x11)
	return p

def generate_ftp_msg(payload, rp) :
	tcp_seg_len = get_tcp_seg_len(rp)
	#tcp_seg_len = len(rp.getlayer("TCP"))-len(rp.getlayer("IP").options)-len(rp.getlayer("TCP").options)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = 0x18)/(payload+delimiter)
	return p


def clear_tcp_connection(dst_ip, dport, sport):
	#Clear TCP connection
	global skt
	FIN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = 0x11) # FIN
	FIN_ACK = skt.sr1(FIN, verbose=False, retry=-1)
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq + 1, flags = "A")
	skt.send(ACK)
	#logging.info("[+] TCP connection clean ... \n")


def build_state_machine(sm, crnt_state, spyld, rpyld):
	# sm : state machine, crnt_state : current state, payload : response packet payload 
	# Build and fix a state machine based on the response
	global num_of_states, transition_info, state_list, cur_state, state_found, new_state, depth_count, is_pruning, mul_start, current_level

	send_payload = spyld.replace('\r\n', '')

	#Check if the response already seen before
	if mul_start == 0:
		# search each transition label in transition info data structure
		for t in transition_info.keys(): # No!
			if transition_info[t][0] == crnt_state:
				#logging.info("Trigger t : \n", t)
				if rpyld == "Timeout" and len(send_payload) > 15:
					abbr_spyld = send_payload[0:15] + "-abbr"
					break
				if re.search(rpyld, t):
					# if it is already seen,
					# - No need to make new state
					# - Find the corresponding src & dst state
					# - Add input counts for each seen transition
					transition_info[t][2] = transition_info[t][2] + 1
					return
	
	# multiple remove duplication
	# else:
	# 	for t in mul_transition_info.keys():
	# 		if mul_transition_info[t][0] == crnt_state:
	# 			#logging.info("Trigger t : \n", t)
	# 			if rpyld == "Timeout" and len(send_payload) > 15:
	# 				abbr_spyld = send_payload[0:15] + "-abbr"
	# 				break
	# 			if re.search(rpyld, t):
	# 				# if it is already seen,
	# 				# - No need to make new state
	# 				# - Find the corresponding src & dst state
	# 				# - Add input counts for each seen transition
	# 				mul_transition_info[t][2] = mul_transition_info[t][2] + 1
	# 				return


	#If not seen before,
	# - Add a new state
	# - Add a new transition from current state
	if is_pruning == 0:
		num_of_states = num_of_states + 1
		dst_state = str(num_of_states)
		# sm.add_states(dst_state)

	# In case of timeout with huge inputs, store full send/receive label in transition_info
	# but store abbrebiated send/receive label in transition model (as well as state machine diagram)
	if len(send_payload) > 100:
		abbr_spyld = send_payload[0:15] + "-abbr"
		t_label = abbr_spyld + " / " + rpyld
	else:
		t_label = send_payload + " / " + rpyld

	if is_pruning == 0:

		if mul_start == 0:
			transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info
		else:
			mul_transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info

		if mul_start == 1 and rpyld.find("ogin"):
			logging.debug("[port no. %d] [BUILD_STATE_MACHINE_BEFORE_ADDSTATE] " % sport + rpyld)
		state_list.add_state(State(str(num_of_states), parent=str(cur_state), spyld=str(send_payload), rpyld=str(rpyld)))
		print "state added : " + str(num_of_states)
		if level_dict.get(current_level+1) is None:
			level_dict[current_level+1] = [str(num_of_states)]
		else:
			level_dict[current_level+1].append(str(num_of_states))
		
		state_found = 1 # for dfs
		logging.info("[+] [port no. %d] State " % sport + dst_state + " added with transition " + t_label)

		# transition edit later
		# sm.add_transition(t_label, source = crnt_state, dest = dst_state)


def compare_ordered_dict(dict1, dict2):
	for i,j in zip(dict1.items(), dict2.items()):
		if i != j:
			return False
		else:
			continue

	return True

def compare_ftp_packet(pkt1, pkt2):
	# Compare two packets by looking at the FTP load
	if pkt1.getlayer("TCP").seq == pkt2.getlayer("TCP").seq:
		return True
	else:
		return False

def filter_tcp_ans(ans):
	result_list = []
	for sr in ans:
		# TCP layer in sr
		if sr[1].haslayer("TCP"):
			result_list.append(sr)
		else:
			continue

	return result_list

#################################################
################ MAIN PART #####################

#Crate ftp machine and assign protocol model
ftpmachine = generate_ftp_model()

if mode == 'm':
	while True:
		rp = handshake_init(dst_ip, dport, sport)
		#Next Ack no. calculation : last seq + prev. tcp payload len
		ftp_ack = generate_ftp_ack(rp)
		send(ftp_ack)
		
		for i in range(100) :
			payload = raw_input("[!] payload? : ")
			if payload == "quit":
				disconnect_ftp(rp)
				sport = sport + 1
				break
			p = generate_ftp_msg(payload, rp)
			#logging.info(p.getlayer("Raw").show())
			"""
			if raw_input("[ ] Send Packet? (y/n) : ") != 'y' :
				# Disconnect with pretty FIN ANK

				print "[+] Program ends... \n"
				break
			"""
			ans, unans = sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
			ans = filter_tcp_ans(ans)
			
			for sp, rcv in ans:
				if rcv.haslayer("Raw"):
					# FTP packet received
					#logging.info("[+] FTP PACKET :::\n")
					#logging.info("[+] RESPONSE FTP PAYLOAD : \n", rcv.getlayer("Raw").load) # this is protocol response message
					print str(rcv.getlayer("Raw").load)
					rp = rcv
					ack_p = generate_ftp_ack(rp)
					send(ack_p, verbose=False)


elif mode == 'p':
	# pruning
	with open("./tokenfile/total_tokens.txt") as f:
		token_db = pickle.load(f)

	with open("./args/total_args.txt") as a:
		args_db = pickle.load(a)

	while True:
		start_time = time.time()
		print 'send total tokens in level ' + str(current_level)

		level_state_list = level_dict.get(current_level, [])
		if level_state_list == []: # program 
			break

		### Expansion ###
		is_pruning = 0
		for current_state in level_state_list:
			cur_state = current_state
			print "current_state : " + str(cur_state)
			move_state_msg =[]
			target_state = cur_state
			
			while True:
				current_parent = state_list.find_state(target_state).parent
				if current_parent is not None:
					move_state_msg.append(state_list.find_state(target_state).spyld)
					target_state = current_parent
					continue
				else: # root node
					break
			
			move_state_msg.reverse()

			# --------- Find command with single command  ---------
			mul_start = 0
			single_cnt = 0
			for token in token_db:
				token = str(token)
				single_cnt = single_cnt + 1
				if single_cnt == 1001:
					break
				if token == "quit":
					continue

				#Start with 3WHS
				rp = handshake_init(dst_ip, dport, sport)

				#If handshake finished, the server sends response.
				# Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)

				# Go to the target state
				for cmd in move_state_msg:
					handshake_rp = rp
					rp = send_receive_ftp(rp, cmd)

				# set state
				ftpmachine.set_state(str(cur_state))

				# Send message and listen
				rp = send_receive_ftp(rp, token)

				# Finish TCP connection
				disconnect_ftp(rp)

				#Initialize current state as 0
				cs = 0

				sport = sport + 1
				if sport > 60000:
					sport = 1000
				
			# --------- Find valid message with multiple keywords  ---------
			mul_start = 1
			single_cmds = []
			multiple_msg_db = []

			for child_state_numb in level_dict.get(current_level+1):
				child_state = state_list.find_state(child_state_numb)
				if child_state.parent == cur_state:
					child_spyld = child_state.spyld
					single_cmds.append(child_spyld)
					print "Single Commands are:"
					print child_spyld
			
			for cmd in single_cmds:
				for args in args_db:
					args = str(args[0])
					msg = cmd + ' ' + args
					multiple_msg_db.append(msg)


			time.sleep(2)

			for msg in multiple_msg_db:
				if msg == "quit":
					continue
					
				#Start with 3WHS	
				rp = handshake_init(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)

				for mv_msg in move_state_msg:
					handshake_rp = rp
					#logging.info("[+] [port no. %d] (State moving) Parent msg : " % sport + str(mv_msg))
					rp = send_receive_ftp(rp, mv_msg)

				# set state
				ftpmachine.set_state(str(cur_state))

				temp_rp = rp
				# Send multiple message and listen
				#logging.info("[+] [port no. %d] (MM) msg : " % sport + str(msg))
				rp = send_receive_ftp(rp, msg)

				# Finish TCP connection
				disconnect_ftp(rp)

				#Initialize current state as 0
				cs = 0

				sport = sport + 1
				if sport > 60000:
					sport = 1000


		### Pruning ###
		is_pruning = 1

		# states in the last level to be tested for pruning
		states_candidate = level_dict.get(current_level+1, [])
		if states_candidate == []: # there is no valid sub state. last level.
			break

		valid_states = []	
		invalid_states = []

		# child_state : every sub state to be pruned (deepest states)
		for child_state in states_candidate:
			print 'pruning in ' + str(child_state)
			logging.info("\n[+] [port no. %d] PRUNING starts in state " % sport + str(child_state) +"\n")

			# Get the parent name of the child state
			parent_numb = state_list.find_state(child_state).parent

			# parent_sr_msg_dict : parent node -> child node sent and received message ( key : payload sent. value : resposnses )
			parent_sr_msg_dict = OrderedDict()
			for state in states_candidate:
				child = state_list.find_state(state)
				if child.parent == parent_numb:
					parent_sr_msg_dict[child.spyld] = child.rpyld

			# For each state, store every message to get to the state itself.
			prune_move_state_msg =[]
			prune_current_state = child_state
			prune_target_state = prune_current_state
			child_sr_dict = OrderedDict()
			
			while True:
				prune_current_parent = state_list.find_state(prune_target_state).parent
				if prune_current_parent is not None:
					prune_move_state_msg.append(state_list.find_state(prune_target_state).spyld)
					prune_target_state = prune_current_parent
					continue
				else: # root node
					break
			
			# Change the order
			prune_move_state_msg.reverse()

			parent_spyld = parent_sr_msg_dict.keys()

			# every payload sent in parent nodes
			for msg_sent in parent_spyld:
				if msg_sent == "quit":
					continue

				#Start with 3WHS
				rp = handshake_init(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)
				#logging.info("[+] [MAIN] AFTER SEND")

				for msg in prune_move_state_msg:
					msg_with_dlm = msg + '\r\n'
					logging.info("[+] [port no. %d] Prune Move (depth %d -> %d) msg : " % (sport, current_level, current_level+1) + str(msg))
					rp = send_receive_ftp(rp, msg_with_dlm)

				# Send message and listen
				logging.info("[+] [port no. %d] Prune Send msg : " % sport + str(msg_sent))

				origin_rp = rp
				rp = send_receive_ftp(rp, msg_sent)
				
				# if normal, add to child_sr_dict
				if compare_ftp_packet(rp, origin_rp) is False:
					child_sr_dict[str(msg_sent)] = rp.getlayer("Raw").load.replace('\r\n', '')

				# Finish TCP connection
				disconnect_ftp(rp)

				#Initialize current state as 0
				cs = 0

				sport = sport + 1
				if sport > 60000:
					sport = 1000

				if sport % 1000 == 0 :
					elapsed_time = time.time() - g_start_time
					print "[+] Port No. : %d | " % sport, "Time Elapsed :", elapsed_time, "s"
					graphname = "diagram/level_" + str(current_level) + "_port_" + str(sport) + ".png"
					ftpmachine.model.graph.draw(graphname, prog='dot')
					
			if compare_ordered_dict(parent_sr_msg_dict, child_sr_dict) == True: # same state, prune state
				invalid_states.append(child_state)
				logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(child_state))
			else: # different state
				# add transition here
				valid_states.append(child_state)
				logging.debug("[!] [port no. %d] Parent != Child. Refer the dict below !" % sport)
				logging.debug("[+] parent_sr_msg_dict : \n")
				logging.info(json.dumps(parent_sr_msg_dict, indent=4))
				logging.debug("[+] child_sr_dict : \n")
				logging.info(json.dumps(child_sr_dict, indent=4))

		for invalid_state_numb in invalid_states:
			invalid_state = state_list.find_state(invalid_state_numb)
			if invalid_state is not None:
				# print str(temp_numb) + " / " + str(current_state)
				ftpmachine.add_transition(invalid_state.spyld + " / " + str(parent_sr_msg_dict.get(invalid_state.spyld, None) + "\n"), source = str(invalid_state.parent), dest = str(invalid_state.parent))
				print "invalid state : " + str(invalid_state_numb) + " in level " + str(current_level+1)
				state_list.remove_state(state_list.find_state(invalid_state_numb))
				level_dict[current_level+1].remove(str(invalid_state_numb))

		for valid_state_numb in valid_states:
			valid_state = state_list.find_state(valid_state_numb)
			if valid_state is not None:
				print "valid state : " + str(valid_state_numb) + " in level " + str(current_level+1)
				ftpmachine.add_states(str(valid_state_numb))
				ftpmachine.add_transition(valid_state.spyld + " / " + str(parent_sr_msg_dict.get(valid_state.spyld, None)), source = str(valid_state.parent), dest = str(valid_state_numb))
	
		elapsed_time = time.time() - g_start_time
		print "[+] Level %d | Port No. %d | " % (current_level, sport), "Time Elapsed :", elapsed_time, "s"
		graphname = "diagram/level_" + str(current_level) + "_port_" + str(sport) + ".png"
		ftpmachine.model.graph.draw(graphname, prog='dot')
		current_level = current_level + 1
		print '[+] Move to level ' + str(current_level)

	elapsed_time = time.time() - g_start_time
	print "Total elapsed time : ", elapsed_time, "\n"
	# Program normally ends.
	ftpmachine.model.graph.draw("diagram/prune_bfs_state_fin.png", prog='dot')
	logging.info(transition_info)
	img = mplotimg.imread("diagram/prune_bfs_state_fin.png")
	plt.imshow(img)
	plt.show()
	sys.exit()

else :
	print "[-] Invalid Input... exit...\n"
	sys.exit()
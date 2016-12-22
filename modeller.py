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

sport = 3000 # find sport here

dst_ip = sys.argv[1]
if len(sys.argv) == 3:
	sport = int(sys.argv[2])

#These informations are prerequisite.
dport = 21

delimiter = "\r\n"
exit_label = "QUIT / 221 Goodbye.\n"
num_of_states = 0
g_start_time = 0
mul_start = 0
new_state = []
myiface = "enp0s8"
is_pruning = 0
is_moving = 0

level_dict = {1 : ['0']}
cur_state = '0'
timeout = 0.01
sniff_timeout = 5
long_timeout = 15
current_level = 1

if not os.path.exists('./diagram'):
	os.makedirs('./diagram')

#Mode Selection
mode = raw_input("[ ] Manual? or Auto? ( \'m\' - for testing / \'a\' - auto mode /) : ")

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
	def __init__(self, numb, parent=None, spyld=None, rpyld=None, group=None, child_dict=None, sr_dict=None):
		self.numb = numb
		self.parent = parent
		self.spyld = spyld
		self.rpyld = rpyld
		self.group = group
		self.child_dict = child_dict
		self.sr_dict = sr_dict

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

	def print_state(self):
		print "state list length : " + str(len(self.state_list))
		for state in self.state_list:
			print state.numb,


state_list = StateList([State('0')])

def handshake_init(dst_ip, dport, sport):
	#Initiate TCP connection - 3 handshaking
	global skt
	SYN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = "S") # SYN
	SYN_ACK = skt.sr1(SYN, verbose=False, retry=-1) # Listen ACK
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=SYN_ACK.ack, ack=SYN_ACK.seq + 1, flags = "A") # SYN - ACK
	RESPONSE = skt.sr1(ACK, verbose=False, retry=-1) # Send ACK, Listen FTP Response

	return RESPONSE # This is FTP Response from server


def disconnect_ftp(rp):
	# Send Req. QUIT (c) -> Get Resp Goodbye (s) -> get FIN-ACK (s) -> send ACK (c) -> Send FIN-ACK (c) -> get ACK
	start_time = time.time()
	global timeout, skt, finack_timeout, sniff_timeout

	temp_rp = rp
	p = generate_ftp_msg("quit", rp)
	# Listen FIN-ACK
	ans, unans = skt.sr(p, multi=1, timeout=timeout*5, verbose=False) # SEND -> GET RESPONSE (normal case) -> GET FINACK
	#ans, x = filter_tcp_ans(ans, None)

	FIN_ACK = None

	# Found FINACK in 2 or 3 packets
	for sp, rp in ans:
		if rp.getlayer("TCP").flags == 0x11:
			FIN_ACK = rp

	# Second barrier
	if FIN_ACK is None:
		rp = sniff(filter = "tcp", iface = myiface, timeout = timeout*20, count = 10)
		for pkt in rp:
			if pkt.haslayer("TCP"):
				if pkt.getlayer("TCP").flags == 0x11:
					FIN_ACK = pkt 

	# Third barrier, Timeout checker
	while True:
		if FIN_ACK is not None:
			break
		else:
			rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 1)
			if len(rp) == 0:
				# Timeout (Internal server error). No FINACK at all
				logging.warning("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all" % sport)
				for sp, rp in ans:
					if rp.haslayer("TCP"):
						FIN_ACK = rp # not FINACK
				# SUCKS!
				logging.warning("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all. No answered in sr." % sport)
				FIN_ACK = temp_rp
			elif rp[0].getlayer("TCP").flags == 0x11:
				# FIN_ACK found
				FIN_ACK = rp[0]
			else:
				continue
	
	# Send ack to fin-ack
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq, flags = "A") # SYN - ACK
	skt.send(ACK)
	
	# Finally, send FIN, ACK to the server
	FIN_ACK = generate_ftp_fin_ack(FIN_ACK)
	skt.send(FIN_ACK)
		
def send_receive_ftp(rp, payload):
	# SEND Req. -> Get ACK -> GET Rep. -> Send ACK (normal TCP-based protocol)
	global skt, timeout, sniff_timeout, long_timeout, mul_start, myiface, sport
	prev_ftp_packet = None
	origin_rp = rp
	last_rp = None
	start_time = time.time()

	# Generate message from tokens
	p = generate_ftp_msg(payload, rp)

	# Send Req, then get 1. ACK and 2. FTP response
	ans, unans = skt.sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
	ans, prev_ftp_packet = filter_tcp_ans(ans, prev_ftp_packet)

	if len(ans) == 0:
		logging.debug("[!] [port no. %d] Answer length is 0. Listening for 2 packets." % sport)
		
		rp = sniff(filter = "tcp", iface = myiface, timeout = 5, count = 3)
		if len(rp) < 2:
			# Timeout (Internal server error). Pass to disconnect.
			logging.warning("[!] [port no. %d] Listened for %d packets in %d sec. Timeout. Check wireshark." % (sport, len(rp), long_timeout))
		# Good 2 packets expected.

		return process_ftp_response_rp(rp, p, origin_rp)

	elif len(ans) == 1:
		logging.debug("[ ] [port no. %d] Answer length is 1." % sport)

		# FTP reponse -> ACK (Strange, but normal)
		for sp, rp in ans:
			if rp.haslayer("Raw") and origin_rp.seq != rp.seq:
				last_rp = rp
		if last_rp is not None:
			return send_ftp_ack_build(p, last_rp)

		# Maybe waiting for the FTP response
		rp = sniff(filter = "tcp", iface = myiface, timeout = long_timeout, count = 1)
		rp, prev_ftp_packet = filter_tcp_rp(rp, prev_ftp_packet)

		# FTP response obtained (Good)
		# ACK -> FTP response (Auth)
		if len(rp) > 0 and rp[0].haslayer("Raw") and origin_rp.seq != rp.seq :
			# It is normal FTP.
			return send_ftp_ack_build(p, rp[0])

		# No packet after ACK
		else:
			logging.debug("[+] [port no. %d] Waited for 15 seconds... Timeout!" % sport)
			# Manually build
			build_state_machine(ftpmachine, ftpmachine.model.state, p.getlayer("Raw"),load.replace('\r\n', ''), "Timeout")
			# Poceed with the first response packet
			return ans[0][1]

	else:
		return process_ftp_response_ans(ans, p, origin_rp)

	logging.debug("[!] [port no. %d] Sucks! What can we do? no process in if. Answer length is %d." % (sport, len(ans)))
	return origin_rp

def send_ftp_ack_build(sp, rp):
	global skt, ftpmachine, mul_start
	sentpayload = sp.getlayer("Raw").load.replace('\r\n', '')
	rcvdpayload = rp.getlayer("Raw").load.replace('\r\n', '')
	ack_p = generate_ftp_ack(rp)				
	skt.send(ack_p)
	build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
	return rp

def process_ftp_response_ans(ans, p, origin_rp):
	global skt, timeout, sniff_timeout, long_timeout, mul_start, myiface, sport
	logging.debug("[!] [port no. %d] PROCESSFTPRESPONSE_ANS Answer length is %d. finding FTP Response." % (sport, len(ans)))
	for sp, rp in ans:
		if rp.haslayer("Raw") and origin_rp.seq != rp.seq:
			last_rp = rp
			# return the last ftp packet. Scapy bug.
	if last_rp is not None:
		return send_ftp_ack_build(p, last_rp)

	# Second barrier s - r ftp
	logging.debug("[!] [port no. %d] Answer length is %d. not yet found FTP Response." % (sport, len(ans)))
	rp = sniff(filter = "tcp", iface = myiface, timeout = timeout, count = 10)
	rp, prev_ftp_packet = filter_tcp_rp(rp, prev_ftp_packet)
	for pkt in rp:
		if pkt.haslayer("Raw") and origin_rp.seq != pkt.seq:
			last_rp = pkt

	if last_rp is not None:
		return send_ftp_ack_build(p, last_rp)	

def process_ftp_response_rp(rp, p, origin_rp):
	global skt, timeout, sniff_timeout, long_timeout, mul_start, myiface, sport
	logging.debug("[!] [port no. %d] PROCESSFTPRESPONSE_RP Answer length is %d. finding FTP Response." % (sport, len(rp)))
	for pkt in rp:
		if pkt.haslayer("Raw") and origin_rp.seq != pkt.seq:
			last_rp = pkt
			# return the last ftp packet. Scapy bug.
	if last_rp is not None:
		return send_ftp_ack_build(p, last_rp)

	# Second barrier s - r ftp
	logging.debug("[!] [port no. %d] Answer length is %d. not yet found FTP Response." % (sport, len(rp)))
	rp = sniff(filter = "tcp", iface = myiface, timeout = timeout, count = 10)
	rp, prev_ftp_packet = filter_tcp_rp(rp, prev_ftp_packet)
	for pkt in rp:
		if pkt.haslayer("Raw") and origin_rp.seq != pkt.seq:
			last_rp = pkt

	if last_rp is not None:
		return send_ftp_ack_build(p, last_rp)	

def check_ftp_resp(pkt):
	global start_time
	if pkt.haslayer(Raw) :
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
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = "A")
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
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = 0x18)/(payload+delimiter)
	return p

def build_state_machine(sm, crnt_state, spyld, rpyld):
	# sm : state machine, crnt_state : current state, payload : response packet payload 
	# Build and fix a state machine based on the response
	global num_of_states, transition_info, state_list, cur_state, new_state, is_pruning, is_moving, mul_start, current_level

	send_payload = spyld.replace('\r\n', '')
	command = send_payload.split()[0]
	#Check if the response already seen before
	if mul_start == 0:
		# search each transition label in transition info data structure
		for t in transition_info.keys(): # No!
			if transition_info[t][0] == crnt_state:
				if re.search(rpyld, t):
					# if it is already seen,
					# - No need to make new state
					# - Find the corresponding src & dst state
					# - Add input counts for each seen transition
					transition_info[t][2] = transition_info[t][2] + 1
					return

	# if long payload, abbreviate
	if rpyld == "Timeout" and len(send_payload) > 15:
		abbr_spyld = send_payload[0:15] + "-abbr"
	
	#If not seen before,
	# - Add a new state
	# - Add a new transition from current state
	if is_pruning == 0 and is_moving == 0:
		num_of_states = num_of_states + 1
		dst_state = str(num_of_states)

	# In case of timeout with huge inputs, store full send/receive label in transition_info
	# but store abbrebiated send/receive label in transition model (as well as state machine diagram)
	if len(send_payload) > 100:
		abbr_spyld = send_payload[0:15] + "-abbr"
		t_label = abbr_spyld + " / " + rpyld
	else:
		t_label = send_payload + " / " + rpyld

	if is_pruning == 0 and is_moving == 0:

		if mul_start == 0:
			transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info
		else:
			mul_transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info

		state_list.add_state(State(str(num_of_states), parent=str(cur_state), spyld=str(send_payload), rpyld=str(rpyld), group=str(command)))
		print "[+} State added : " + str(num_of_states)
		if level_dict.get(current_level+1) is None:
			level_dict[current_level+1] = [str(num_of_states)]
		else:
			level_dict[current_level+1].append(str(num_of_states))
		
		logging.info("[+] [port no. %d] State " % sport + dst_state + " added with transition " + t_label)

def compare_ordered_dict(dict1, dict2):
	for i,j in zip(dict1.items(), dict2.items()):
		if i != j:
			return False
		else:
			continue
	return True

def compare_ftp_packet(pkt1, pkt2):
	# Compare two packets by looking at the FTP load
	p1 = pkt1.getlayer("TCP")
	p2 = pkt2.getlayer("TCP")
	if pkt1.haslayer("Raw") and pkt2.haslayer("Raw"):
		if p1.seq == p2.seq and p1.ack == p2.ack:
			return True
		else:
			return False
	else:
		return False

def filter_tcp_ans(ans, prev_ftp_resp):
	result_list = []
	for sr in ans:
		# TCP layer in sr
		if sr[1].haslayer("TCP"):
			# If first FTP response found, store and go to the next packet.
			if prev_ftp_resp is None and sr[1].haslayer("Raw"):
				prev_ftp_resp = sr[1]
				result_list.append(sr)
				continue
			# Exclude TCP retransmission packet
			# if the FTP packet received is previously seen, filter out.
			if prev_ftp_resp is not None and compare_ftp_packet(sr[1], prev_ftp_resp) is True:
				#print "[!] Retransmission found in port no. %d. Skip this packet..." % sport
				continue
			else:
				result_list.append(sr)
		else:
			continue

	new_ftp_resp = prev_ftp_resp
	return result_list, new_ftp_resp

def filter_tcp_rp(rp, prev_ftp_resp):
	result_list = []
	for p in rp:
		# TCP layer in sr
		if p.haslayer("TCP"):
			# If first FTP response found, store and go to the next packet.
			if prev_ftp_resp is None and p.haslayer("Raw"):
				prev_ftp_resp = p
				result_list.append(p)
				continue
			# Exclude TCP retransmission packet
			# if the FTP packet received is previously seen, filter out.
			if prev_ftp_resp is not None and compare_ftp_packet(p, prev_ftp_resp) is True:
				# print "[!] Retransmission found in port no. %d. Skip this packet..." % sport
				continue
			else:
				result_list.append(p)
		else:
			continue

	new_ftp_resp = prev_ftp_resp
	return result_list, new_ftp_resp

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
			ans, unans = sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
			#ans = filter_tcp_ans(ans)
			
			for sp, rcv in ans:
				if rcv.haslayer("Raw"):
					# FTP packet received
					print str(rcv.getlayer("Raw").load)
					rp = rcv
					ack_p = generate_ftp_ack(rp)
					send(ack_p, verbose=False)

elif mode == 'a' or mode == 'A':
	# get all command candidates
	with open("./tokenfile/total_tokens.txt") as f:
		token_db = pickle.load(f)
		#token_db = ['data', 'user', 'pass', 'opts']

	# get all argument candidates
	with open("./args/total_args.txt") as a:
		args_db = pickle.load(a)
		#args_db = [['anonymous'], ['510123124512'], ['/'], ['127.0.0.1']]
	while True:
		start_time = time.time()
		print '[+] Send total tokens in level ' + str(current_level)

		level_state_list = level_dict.get(current_level, [])
		if level_state_list == []: # program end
			break

		### Expansion ###
		is_pruning = 0
		for current_state in level_state_list:
			cur_state = current_state
			print "[+] Current_state : " + str(cur_state)
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
				#if single_cnt == 1001:
				#	break
				if token == "quit":
					continue

				#Start with 3WHS
				rp = handshake_init(dst_ip, dport, sport)

				#If handshake finished, the server sends response.
				# Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)

				# Go to the target state
				is_moving = 1
				for cmd in move_state_msg:
					handshake_rp = rp
					rp = send_receive_ftp(rp, cmd)
				is_moving = 0

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
					sport = 3000
				
			# --------- Find valid message with multiple keywords  ---------
			mul_start = 1
			single_cmds = []
			multiple_msg_db = []

			for child_state_numb in level_dict.get(current_level+1):
				child_state = state_list.find_state(child_state_numb)
				if child_state.parent == cur_state:
					child_single_cmds = child_state.group
					if child_single_cmds not in single_cmds:
						single_cmds.append(child_single_cmds)
			print "[+] Single Commands are:"
			print single_cmds
			# for cmd in single_cmds:
			# 	for args in args_db:
			# 		msg = cmd + ' ' + str(args[0])
			# 		multiple_msg_db.append(msg)
			
			for msg in single_cmds: # group name
				for args in args_db: # argument
					if msg == "quit":
						continue
					
					multiple_msg = msg + ' ' + str(args[0])

					#Start with 3WHS	
					rp = handshake_init(dst_ip, dport, sport)

					#If handshake finished, the server sends response. Send ack and get the last req packet info.
					ftp_ack = generate_ftp_ack(rp)
					skt.send(ftp_ack)

					is_moving = 1
					for mv_msg in move_state_msg:
						handshake_rp = rp
						rp = send_receive_ftp(rp, mv_msg)
					is_moving = 0

					# set state
					ftpmachine.set_state(str(cur_state))

					temp_rp = rp
					# Send multiple message and listen
					rp = send_receive_ftp(rp, multiple_msg)

					# Finish TCP connection
					disconnect_ftp(rp)

					#Initialize current state as 0
					cs = 0

					sport = sport + 1
					if sport > 60000:
						sport = 3000


		### Pruning ###
		is_pruning = 1

		# states in the last level to be tested for pruning
		states_candidate = level_dict.get(current_level+1, [])
		if states_candidate == []: # there is no valid sub state. last level.
			break

		valid_states = []
		invalid_states = []
		to_be_removed_states = []

		# child_state_numb : every sub state to be pruned (deepest states)
		for child_state_numb in states_candidate:
			child_state = state_list.find_state(child_state_numb)
			print '[+] Pruning in ' + str(child_state_numb)
			logging.info("[+] === [port no. %d] PRUNING starts in state " % sport + str(child_state_numb) + " ===")

			# Get the parent name of the child state
			parent_numb = child_state.parent

			# parent_sr_msg_dict : parent node -> child node sent and received message ( key : payload sent. value : resposnses )
			parent_sr_msg_dict = OrderedDict()
			for state in states_candidate:
				child = state_list.find_state(state)
				if child.parent == parent_numb:
					parent_sr_msg_dict[child.spyld] = child.rpyld

			state_list.find_state(parent_numb).sr_dict = parent_sr_msg_dict

			# For each state, store every message to get to the state itself.
			prune_move_state_msg =[]
			prune_current_state = child_state_numb
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

				for msg in prune_move_state_msg:
					logging.info("[+] [port no. %d] Prune Move (depth %d -> %d) msg : " % (sport, current_level, current_level+1) + str(msg))
					rp = send_receive_ftp(rp, msg)

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
					sport = 3000
					
				if sport % 1000 == 0 :
					elapsed_time = time.time() - g_start_time
					print "[+] Port No. : %d | " % sport, "Time Elapsed :", elapsed_time, "s"
					graphname = "diagram/level_" + str(current_level) + "_port_" + str(sport) + ".png"
					ftpmachine.model.graph.draw(graphname, prog='dot')
			
			# After searching all the parent's s/r
			# Check below for merging

			state_list.find_state(child_state_numb).sr_dict = child_sr_dict
			# STEP1. Parent
			# - Compare child dict with parent dict
			# - If differnt, let it be alive.
			# If same merge with parent.
			if compare_ordered_dict(parent_sr_msg_dict, child_sr_dict) == True: # same state, prune state
				print "[+] -> Same as parent. Merge with state " + parent_numb
				invalid_states.append([child_state_numb, parent_numb, parent_numb, child_state.spyld + " / " + child_state.rpyld])
				logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(child_state_numb))
			else: 
				print "[-] -> Differnt from parent. Now check with siblings!"
				# STEP2. Sibling
				# - Compare its child dict with other childs' dict
				# - If different with all the childs' dict (or first), let it be alive
				# - If any same dict found, merge with the child
				unique_in_step_2 = True

				child_level = current_level + 1
				for sibling_state_numb, src_state, dst_state, vs_payload in valid_states:

					if sibling_state_numb == child_state.numb:
						continue
										
					sibling_state = state_list.find_state(sibling_state_numb)
					if sibling_state.parent == child_state.parent and sibling_state.group == child_state.group: # same group
						# compare child_dict between sibling and current state
						if compare_ordered_dict(sibling_state.sr_dict, child_state.sr_dict) == True: # same state! Merge with sibling!
							invalid_states.append([child_state_numb, parent_numb, sibling_state_numb, child_state.spyld + " / " + child_state.rpyld])
							unique_in_step_2 = False
							print "[+] -> Same as " + sibling_state_numb + ". Merge with state " + sibling_state_numb
							logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(child_state_numb))
							break
						else:
							continue
					else:
						continue

				# I am unique! different from parent and other siblings!
				# But we have to compare it with other relatives...
				# Step 3
				# Compare with the other relatives
				if unique_in_step_2:
					parent_level = current_level
					currently_unique = True
					if parent_level > 1:
						currently_unique = False
					else: # state in level 2
						currently_unique = True

					while True:
						# get all parents in previous level
						for parent_numb_in_level in level_dict[parent_level]:
							# validition
							# compare with other parents
							if parent_numb_in_level != child_state.parent:
								print "[-] -> compare state " + child_state.numb + " with ancestor state " + parent_numb_in_level
								parent_state_in_level = state_list.find_state(parent_numb_in_level)
								# compare child_dict between prev and current state
								if compare_ordered_dict(parent_state_in_level.sr_dict, child_state.sr_dict) == True: # same state! Add transition to parent_state_in_level!
									invalid_states.append([child_state_numb, child_state.parent, parent_numb_in_level, child_state.spyld + " / " + child_state.rpyld])
									print "[+] -> Same as " + parent_state_in_level.numb + ". Add transitions to state " + parent_state_in_level.numb
									logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(child_state_numb))
									currently_unique = False
									break
								else:
									print "[-] -> Differnt from relative state " + parent_numb_in_level
									currently_unique = True
									continue
						
						if currently_unique == True: # valid yet
							parent_level = parent_level - 1
							print "[-] target parent level : " + str(parent_level)
							if parent_level == 0:
								break
							else:
								continue
						else:
							break


					if currently_unique == True: # real valid state
						print "[+] -> Unique state " + child_state_numb + " found!!!"
						valid_states.append([child_state_numb, child_state.parent, child_state_numb, child_state.spyld + " / " + child_state.rpyld])
		
		# state validation
		# add valid states
		for self_numb, src_state, dst_state, vs_payload in valid_states:
			self_state = state_list.find_state(self_numb)
			ftpmachine.add_state(self_numb)
			ftpmachine.add_transition(vs_payload + "\n", source = self_state.parent, dest = self_numb)
			print "[+] Valid state " + self_numb + " in level " + str(current_level) + " added"

		# remove invalid states
		for self_numb, src_state, dst_state, vs_payload in invalid_states:
			child_state = state_list.find_state(self_numb)
			ftpmachine.add_transition(vs_payload + "\n", source = src_state, dest = dst_state)
			level_dict[current_level+1].remove(self_numb)
			state_list.remove_state(child_state)
			print "[+] Invalid state " + self_numb + " in level " + str(current_level) + " removed"
					
		elapsed_time = time.time() - g_start_time
		graphname = "diagram/level_" + str(current_level) + "_port_" + str(sport) + ".png"
		ftpmachine.model.graph.draw(graphname, prog='dot')
		current_level = current_level + 1
		print "[+] Level %d | Port No. %d | " % (current_level, sport), "Time Elapsed :", elapsed_time, "s"
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
#! /usr/bin/env python
import os
import sys
import pickle
import logging
import time
import re
import json
import matplotlib.pyplot as plt
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

#These informations are prerequisite.
dport = 21
sport = 3000 # find sport here
delimiter = "\r\n"
exit_label = "QUIT / 221 Goodbye.\n"
num_of_states = 0
g_start_time = 0
mul_start = 0
new_state = []
myiface = "ens34"
is_pruning = False
is_moving = False

cur_state = '0'
timeout = 0.01
slowresp_timeout = 10
long_timeout = 45
current_level = 1

skip_msg_list = ['USER ANONYMOUS', 'PASS ', 'PASV'] # for shortcut
#skip_msg_list = ['USER ANONYMOUS', 'PASS ', 'PORT 1000'] # for shortcut

if not os.path.exists('./diagram'):
	os.makedirs('./diagram')

#Mode Selection
mode1 = raw_input("[ ] Manual? or Auto? ( \'m\' - for testing / \'a\' - auto mode /) : ")
print skip_msg_list
if len(skip_msg_list) > 0:
	mode2 = raw_input("[ ] Take shortcut? ( \'y\' / \'n\' ) : ")

dst_ip = sys.argv[1]
if len(sys.argv) == 3:
	sport = int(sys.argv[2])

# It will contain trasition info like 
# trigger as key (string) : [src_state (string), dest_state (string), cnt]
transition_info = {}
mul_transition_info = {}

g_start_time = time.time()
skt = conf.L3socket(iface = myiface)

#Contains a FTP Protocol model
class ProtoModel(object):
	def __init__(self, name):
		self.name = name

class State:
	def __init__(self, numb, level, parent = None, spyld=None, rpyld=None, group=None, child_sr_dict=None):
		self.numb = numb
		self.level = level
		self.parent = parent
		self.spyld = spyld
		self.rpyld = rpyld
		self.group = group
		self.child_sr_dict = child_sr_dict

class StateList:
	def __init__(self, state_list=[]):
		self.state_list = state_list

	def add_state(self, state):
		self.state_list.append(state)

	def remove_state(self, state):
		self.state_list.remove(state)

	def get_state_by_num(self, numb):
		for state in self.state_list:
			if state.numb == numb:
				return state
		return None

	def get_states_by_level(self, level):
		states_list = []
		for state in self.state_list:
			if state.level == level:
				states_list.append(state.numb)
		return states_list

	def print_state(self):
		print "state list length : " + str(len(self.state_list))
		for state in self.state_list:
			print state.numb,


state_list = StateList([State('0', 1)])
level_dict = {1 : ['0']} # contains states for each level

def three_handshake(dst_ip, dport, sport):
	#Initiate TCP connection - 3 handshaking
	global skt
	SYN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = "S") # SYN
	SYN_ACK = skt.sr1(SYN, verbose=False, retry=-1) # Listen ACK
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=SYN_ACK.ack, ack=SYN_ACK.seq + 1, flags = "A") # SYN - ACK
	RESPONSE = skt.sr1(ACK, verbose=False, retry=-1) # Send ACK, Listen FTP Response

	return RESPONSE # This is FTP Response from server

def generate_state_machine():
	pmodel = ProtoModel("Protocol Model")
	pmachine = Machine(model = pmodel, states = ['0'], initial = '0', auto_transitions=False)
	pmachine.add_transition(exit_label, source = '0', dest = '0')
	return pmachine

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
	# Generate ack to the normal tcp (ack to the ack)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq, flags = "A")
	return p

def generate_ftp_fin_ack(rp):
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+1, flags = 0x11)
	return p

def generate_ftp_msg(payload, rp) :
	tcp_seg_len = get_tcp_seg_len(rp)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = 0x18)/(payload+delimiter)
	return p


def expand_states(states_in_the_level, token_db, args_db):
	global mode2, sport, dport, dst_ip, is_moving, is_pruning, mul_start, cur_state

	is_pruning = False
	for current_state in states_in_the_level:
		print "[+] Current_state : " + str(current_state)
		cur_state = str(current_state)
		
		move_state_msg = find_path_of_the_state(current_state)

		# --------- Find command with single command  ---------
		mul_start = 0
		for token in token_db:
			token = str(token)

			if token == "quit":
				continue

			#Start with 3WHS
			rp = three_handshake(dst_ip, dport, sport)

			# In case of FTP,
			# If handshake finished, the server sends response.
			# Send ack and get the last req packet info.
			ftp_ack = generate_ftp_ack(rp)
			skt.send(ftp_ack)

			
			# Take shortcut
			if mode2 == 'y':
				rp, res = shortcut(rp, skip_msg_list)
				# Check if end in shortcut
				if res == 1:
					continue

			# Go to the target state
			is_moving = True
			for move_msg in move_state_msg:
				handshake_rp = rp
				rp, res = send_receive(rp, move_msg)
				# if res == 1: # Over while moving
				# 	is_moving = False
				# 	continue
			is_moving = False

			# res is 0, which means it is not over.

			# set state
			pm.set_state(str(current_state))

			# Send message and listen
			rp, res = send_receive(rp, token)

			if res == 0:
				disconnect_ftp(rp)
			
		# --------- Find valid message with multiple keywords  ---------
		mul_start = 1
		single_cmds = []
		multiple_msg_db = []

		for child_state_numb in state_list.get_states_by_level(current_level+1):
			child_state = state_list.get_state_by_num(child_state_numb)
			if child_state.parent == current_state:
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
				
				multiple_msg = msg + ' ' + str(args)

				#Start with 3WHS
				rp = three_handshake(dst_ip, dport, sport)

				# In case of FTP,
				# If handshake finished, the server sends response.
				# Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)

				# Take shortcut
				if mode2 == 'y':
					rp, res = shortcut(rp, skip_msg_list)
					# Check if end in shortcut
					if res == 1:
						continue

				# Go to the target state
				is_moving = True
				for move_msg in move_state_msg:
					handshake_rp = rp
					rp, res = send_receive(rp, move_msg)
					if res == 1: # Over while moving
						is_moving = False
						continue
				is_moving = False

				# res is 0, which means it is not over.

				# set state
				pm.set_state(str(current_state))

				# Send message and listen
				rp, res = send_receive(rp, multiple_msg)

				if res == 0:
					disconnect_ftp(rp)

def disconnect_ftp(rp):
	# Send Req. QUIT (c) -> Get Resp Goodbye (s) -> get FIN-ACK (s) -> send ACK (c) -> Send FIN-ACK (c) -> get ACK
	start_time = time.time()
	global timeout, skt, cs, sport, finack_timeout, sniff_timeout

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
			rp = sniff(filter = "tcp", iface = myiface, timeout = slowresp_timeout, count = 1)
			if len(rp) == 0:
				# Timeout (Internal server error). No FINACK at all
				logging.warning("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all" % sport)
				for sp, rp in ans:
					if rp.haslayer("TCP"):
						FIN_ACK = rp # not FINACK
				# SUCKS!
				logging.warning("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all. No answered in sr." % sport)
				FIN_ACK = temp_rp
			#elif rp[0].getlayer("TCP").flags == 0x11:
				# FIN_ACK found
			#	FIN_ACK = rp[0]
			else:
				continue
	
	# Send ack to fin-ack
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq, flags = "A") # SYN - ACK
	skt.send(ACK)
	
	# Finally, send FIN, ACK to the server
	FIN_ACK = generate_ftp_fin_ack(FIN_ACK)
	skt.send(FIN_ACK)

	#Initialize current state as 0
	cs = 0

	sport = sport + 1
	if sport > 60000:
		sport = 3000

def send_receive(rp, payload):
	# SEND Req. -> Get ACK -> GET Rep. -> Send ACK (normal TCP-based protocol)
	global skt, timeout, sniff_timeout, long_timeout, mul_start, myiface, sport
	origin_rp = rp
	
	# Generate message with tokens
	p = generate_ftp_msg(payload, rp)
	ans, unans = skt.sr(p, multi=1, timeout=timeout, verbose=False)
	
	# Filter out only TCP packets
	ans = filter_tcp_ans(ans)
	return process_response(p, ans, origin_rp)

def process_response(p, ans, origin_rp):
	# e
	global skt, timeout, sniff_timeout, long_timeout, mul_start, myiface, sport

	"""
	There could be 3 cases of response in case of FTP.
	* : Dealt with in process_response
	Case 1. (Normal Ping-Pong)
	C                S
	  -> MSG send ->
	  <-    ACK   <- *
	  <- MSG send <- *
	  ->    ACK   -> 

	Case 2. (Abrupt disconnection from Server)
	C                S
	  -> MSG send ->
	  <- MSG send <- *
	  <- FIN, ACK <- *

	Case 3. (Slow response)
	C                S
	  -> MSG send ->
	  <-    ACK   <- *
	  <- MSG send <- * (slow)
	  ->    ACK   -> 

	Case 4. (No response. Possibly crash)
	C                S
	  -> MSG send ->
	    No response  *
	"""

	resp_list = []
	if len(ans) == 0:
		# Listen again in short time (save time!)
		resp_list = sniff(filter = "tcp", iface = myiface, timeout = timeout, count = 10)
	else:
		# Convert send-reponse pair to only responses
		for s, r in ans:
			resp_list.append(r)

	# Wait for MSG from server
	raw_resp = None
	finack_resp = None
	for resp in resp_list:
		# return the last ftp packet. Scapy bug.
		if resp.haslayer("TCP") and resp.haslayer("Raw"):
			raw_resp = resp
		# check if finack
		elif resp.haslayer("TCP") and resp.getlayer("TCP").flags == 0x11:
			finack_resp = resp

	if raw_resp is None and finack_resp is None:
		#Case3.
		#Slow response.
		resp_list = sniff(filter = "tcp", iface = myiface, timeout = slowresp_timeout, count = 2)
		for resp in resp_list:
			# return the last ftp packet. Scapy bug.
			# print resp.show()
			if resp.haslayer("TCP") and resp.haslayer("Raw"):
				raw_resp = resp
			# check if finack
			elif resp.haslayer("TCP") and resp.getlayer("TCP").flags == 0x11:
				finack_resp = resp

	if raw_resp is not None:
		# MSG (Raw) packet found
		sentpayload = p.getlayer("Raw").load.replace('\r\n', '')
		rcvdpayload = raw_resp.getlayer("Raw").load.replace('\r\n', '')
		if finack_resp is None:
			#print "case1"
			# Case 1.
			# Send ACK and disconnect
			ack_p = generate_ftp_ack(raw_resp)
			skt.send(ack_p)
			if mode1 == 'm':
				print rcvdpayload
				return raw_resp, 0
			else:
				build_state_machine(pm, pm.model.state, sentpayload, rcvdpayload, 1)
				return raw_resp, 0 # needs to disconnect later
		else:
			print "case2"
			# Case 2.
			# Send ACK and FINACK
			ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=finack_resp.ack, ack=finack_resp.seq, flags = "A") # SYN - ACK
			skt.send(ACK)

			if mode1 == 'm':
				print rcvdpayload
			else:
				build_state_machine(pm, pm.model.state, sentpayload, rcvdpayload, 2)
			
			# Finally, send FIN, ACK to the server
			FIN_ACK = generate_ftp_fin_ack(finack_resp)
			skt.send(FIN_ACK)

			sport = sport + 1
			if sport > 60000:
				sport = 3000

			return FIN_ACK, 1

	else:
		# Crash?
		print "case4"
		logging.debug("[!] [port no. %d] No raw response. Possibly crash." % (sport))
		if len(resp_list) == 0:
			rp = origin_rp
		else:
			for resp in resp_list:
				rp = resp
		disconnect_ftp(rp)
		return rp, 1

def build_state_machine(sm, crnt_state, spyld, rpyld, case_num):
	# sm : state machine, crnt_state : current state, payload : response packet payload 
	# Build and fix a state machine based on the response
	global num_of_states, transition_info, state_list, cur_state, new_state, is_pruning, is_moving, mul_start, current_level, skip_msg_list

	send_payload = spyld.replace('\r\n', '')
	command = send_payload.split()[0]

	#In case of shortcut, ignore the shortcut messages
	for msg in skip_msg_list:
		if send_payload == msg:
			return

	# Check if the response already seen before
	# We separate two cases: Single, Multiple.
	# That is, if the response already seen in the single once,
	# It ignore in the single case.
	# Compare among single, among multiple
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

	else:
		# search each transition label in transition info data structure
		for t in mul_transition_info.keys(): # No!
			if mul_transition_info[t][0] == crnt_state:
				if re.search(rpyld, t):
					# if it is already seen,
					# - No need to make new state
					# - Find the corresponding src & dst state
					# - Add input counts for each seen transition
					mul_transition_info[t][2] = mul_transition_info[t][2] + 1
					return

	# if long payload, abbreviate
	if rpyld == "Timeout" and len(send_payload) > 15:
		abbr_spyld = send_payload[0:15] + "-abbr"

	#If not seen before,
	# - Add a new state
	# - Add a new transition from current state
	if is_pruning == False and is_moving == False:
		num_of_states = num_of_states + 1
		dst_state = str(num_of_states)

	# In case of timeout with huge inputs, store full send/receive label in transition_info
	# but store abbrebiated send/receive label in transition model (as well as state machine diagram)
	if len(send_payload) > 100:
		abbr_spyld = send_payload[0:15] + "-abbr"
		t_label = abbr_spyld + " / " + rpyld
	else:
		t_label = send_payload + " / " + rpyld

	if case_num == 2:
		# Abrupt disconnection from server case
		# Set transition from this state to initial state
		dst_state = '0'
		transition_info[t_label] = [crnt_state, dst_state, 1]
		logging.info("[+] [port no. %d] State " % sport + dst_state + " added with transition " + t_label + "(Case 2)")
		pm.add_transition(t_label + "\n", source = crnt_state, dest = dst_state)
		return

	if is_pruning == False and is_moving == False:

		if mul_start == 0:
			transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info
		else:
			mul_transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info

		# Add child state for each parent
		state_list.add_state(State(str(num_of_states), current_level+1, parent=str(cur_state), spyld=str(send_payload), rpyld=str(rpyld), group=str(command)))
		print "[+] State added (%s -> %d) : " % (cur_state, num_of_states) + str(num_of_states)
		logging.info("[+] [port no. %d] State (%s -> %d)" % (sport, cur_state, num_of_states) + " added with transition " + t_label)


		# if level_dict.get(current_level+1) is None:
		# 	level_dict[current_level+1] = [str(num_of_states)]
		# else:
		# 	level_dict[current_level+1].append(str(num_of_states))
		


def compare_ordered_dict(dict1, dict2):
	# cnt = 0
	# min_len = min(len(dict1), len(dict2))

	# for i in dict1.items():
	# 	for j in dict2.items():
	# 		s1, r1 = i
	# 		s2, r2 = j
	# 		if len(i) > 40 and len(r2) > 40:
	# 			i = (s1, r1[0:41])
	# 			j = (s2, r2[0:41])

	# 		if i == j:
	# 			cnt = cnt + 1
	
	# if cnt == min_len:
	# 	return True
	# else:
	# 	return False

	for i,j in zip(dict1.items(), dict2.items()):
		s1, r1 = i
		s2, r2 = j
		if s1.find("stat") >= 0 and s2.find("stat") >= 0 :
			continue
		if len(r1) > 40 and len(r2) > 40:
			i = (s1, r1[0:41])
			j = (s2, r2[0:41])
			#print i, j
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

def filter_tcp_ans(ans):
	result_list = []
	for sr in ans:
		# TCP layer in sr
		if sr[1].haslayer("TCP"):
			result_list.append(sr)
		else:
			continue

	return result_list

def filter_tcp_rp(rp):
	result_list = []
	for r in rp:
		# TCP layer in sr
		if r.haslayer("TCP"):
			result_list.append(r)
		else:
			continue

	return result_list


def shortcut(rp, skip_msg_list):
	# Take messages to skip. Using the messages, 
	# it goes to the new starting point fast.
	
	# There is not shortcut
	if len(skip_msg_list) == 0:
		return
	
	for msg in skip_msg_list:
		handshake_rp = rp
		rp, res = send_receive(rp, msg)

	return rp, res

def find_path_of_the_state(target_state_numb):

	global state_list

	move_state_msg = []
	target_state = target_state_numb
	while True:
		parent_state = state_list.get_state_by_num(target_state).parent
		if parent_state is not None:
			move_state_msg.append(state_list.get_state_by_num(target_state).spyld)
			target_state = parent_state
			continue
		else: # root node
			break
	
	move_state_msg.reverse()

	return move_state_msg


# target means something to be compared!!!!!!!!!
def move_and_find_sr(target_state_numb, target_sr_dict):

	# Set state moving message for current state

	move_state_msg = find_path_of_the_state(target_state_numb)

	child_sr_dict = OrderedDict()

	parent_spyld = target_sr_dict.keys()

	for msg in parent_spyld:
		msg = str(msg)

		if msg == "quit":
			continue

		#Start with 3WHS
		rp = three_handshake(dst_ip, dport, sport)

		# In case of FTP,
		# If handshake finished, the server sends response.
		# Send ack and get the last req packet info.
		ftp_ack = generate_ftp_ack(rp)
		skt.send(ftp_ack)
		
		# Take shortcut
		# if mode2 == 'y':
		# 	rp, res = shortcut(rp, skip_msg_list)
		# 	# Check if end in shortcut
		# 	if res == 1:
		# 		continue

		# Go to the target state
		is_moving = True
		for move_msg in move_state_msg:
			handshake_rp = rp
			rp, res = send_receive(rp, move_msg)
			# if res == 1: # Over while moving
			# 	is_moving = False
			# 	continue
		is_moving = False

		# res is 0, which means it is not over.

		# set state
		# pm.set_state(str(current_state))

		# Send message and listen
		rp, res = send_receive(rp, msg)

		child_sr_dict[msg] = rp.getlayer("Raw").load.replace('\r\n', '')

		if res == 0:
			disconnect_ftp(rp)

	return child_sr_dict


#################################################
################ MAIN PART #####################

#Crate protocol state machine
pm = generate_state_machine()

if mode1 == 'm':
	while True:
		rp = three_handshake(dst_ip, dport, sport)
		#Next Ack no. calculation : last seq + prev. tcp payload len
		ftp_ack = generate_ftp_ack(rp)
		send(ftp_ack)
		print "[ ] Enter message. If you want to stop, type \"quit\""
		
		for i in range(100) :
			payload = raw_input("[!] payload? : ")
			if payload == "quit":
				disconnect_ftp(rp)
				break
			p = generate_ftp_msg(payload, rp)
			ans, unans = sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
			#ans = filter_tcp_ans(ans)
			
			rp, garbage = process_response(p, ans, rp)

		isquit = raw_input("[!] Are you sure to quit the program? (y/n)")
		if isquit == "y":
			print "Goodbye..."
			break
		else :
			print "Start from the beginning..."

elif mode1 == 'a' or mode == 'A':
	# get all command candidates
	with open("./tokenfile/total_tokens.txt") as f:
		#token_db = pickle.load(f)
		token_db = ['retr', 'data', 'type', 'get', 'size', 'list', 'help', 'mode', 'user', 'port', 'pass', 'opts', 'pwd', 'cwd', 'rest', 'stat', 'acct', 'prot', 'noop', 'pasv', 'site']
		#token_db = ['user', 'pass', 'pasv', 'opts']

	# get all argument candidates
	with open("./args/total_args.txt") as a:
		#args_db = pickle.load(a)
		args_db = ['anonymous', 'example', '/']

	while True: # for each level
		start_time = time.time()
		print '[+] Send total %d tokens in level ' % len(token_db) + str(current_level)

		# states in the last level to be tested for pruning
		states_in_the_level = state_list.get_states_by_level(current_level)
		if len(states_in_the_level) == 0: # there is no valid sub state. last level.
			break

		### Phase 1. Expansion ###
		expand_states(states_in_the_level, token_db, args_db)

		### Pruning ###
		is_pruning = True

		# states in the last level to be tested for pruning
		states_candidate_for_prune = state_list.get_states_by_level(current_level+1)
		if len(states_candidate_for_prune) == 0: # there is no valid sub state. last level.
			break

		valid_states = [] # state to be added
		invalid_states = [] # state to be removed

		# state_tobe_pruned_num : every sub state to be pruned (deepest states)
		for state_tobe_pruned_num in states_candidate_for_prune:
			state_tobe_pruned = state_list.get_state_by_num(state_tobe_pruned_num)
			cur_state = str(state_tobe_pruned_num)
			print '[+] Pruning in ' + str(state_tobe_pruned_num) + " port [%d]" % sport
			logging.info("[+] === [port no. %d] PRUNING starts in state " % sport + str(state_tobe_pruned_num) + " ===")

			# Get the parent name of the child state
			parent_numb = state_tobe_pruned.parent

			# parent_sr_msg_dict : parent node -> child node sent and received message ( key : payload sent. value : resposnses )
			parent_sr_msg_dict = OrderedDict()
			for child_num in states_candidate_for_prune:
				child = state_list.get_state_by_num(child_num)
				if child.parent == parent_numb:
					parent_sr_msg_dict[child.spyld] = child.rpyld

			state_list.get_state_by_num(parent_numb).child_sr_dict = parent_sr_msg_dict
			
			prune_target_state = state_tobe_pruned_num
			child_sr_dict = OrderedDict()

			# For each state, store every message to get to the state itself.
			prune_move_state_msg = find_path_of_the_state(prune_target_state)
			
			parent_spyld = parent_sr_msg_dict.keys()

			# every payload sent in parent nodes
			for msg_sent in parent_spyld:
				if msg_sent == "quit":
					continue
					
				#Start with 3WHS
				rp = three_handshake(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)

				# Take shortcut
				if mode2 == 'y':
					rp, res = shortcut(rp, skip_msg_list)

					# Check if end in shortcut
					if res == 1:
						continue

				for msg in prune_move_state_msg:
					logging.info("[+] [port no. %d] Prune Move (depth %d -> %d) msg : " % (sport, current_level, current_level+1) + str(msg))
					rp, res = send_receive(rp, msg)

				# Send message and listen
				logging.info("[+] [port no. %d] Prune Send msg : " % sport + str(msg_sent))

				origin_rp = rp
				rp, res = send_receive(rp, msg_sent)

				if res == 0:
					disconnect_ftp(rp)
				
				# if normal, add to child_sr_dict
				if compare_ftp_packet(rp, origin_rp) is False:
					child_sr_dict[str(msg_sent)] = rp.getlayer("Raw").load.replace('\r\n', '')

				#Initialize current state as 0
				cs = 0

				# sport = sport + 1
				# if sport > 60000:
				# 	sport = 3000
					
				if sport % 1000 == 0 :
					elapsed_time = time.time() - g_start_time
					print "[+] Port No. : %d | " % sport, "Time Elapsed :", elapsed_time, "s"
					graphname = "diagram/level_" + str(current_level) + "_port_" + str(sport) + ".png"
					pm.model.graph.draw(graphname, prog='dot')
			
			# After searching all the parent's s/r
			# Check below for merging

			state_list.get_state_by_num(state_tobe_pruned_num).child_sr_dict = child_sr_dict
			#print child_sr_dict

			# STEP1. Parent
			# - Compare child dict with parent dict
			# - If differnt, let it be alive.
			# If same merge with parent.
			if compare_ordered_dict(parent_sr_msg_dict, child_sr_dict) == True: # same state, prune state
				print "[+] -> Same as parent. Merge with state " + parent_numb
				invalid_states.append([state_tobe_pruned_num, parent_numb, parent_numb, state_tobe_pruned.spyld + " / " + state_tobe_pruned.rpyld])
				logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(state_tobe_pruned_num))
			else: 
				print "[-] -> Different from parent. Now check with siblings!"
				# print "parent_sr_msg_dict : "
				# print parent_sr_msg_dict
				# print "child_sr_dict : "
				# print child_sr_dict 

				# STEP 2. Sibling
				# - Compare its child dict with other childs' dict
				# - If different with all the childs' dict (or first), let it be alive
				# - If any same dict found, merge with the child
				unique_in_step_2 = True

				#rint valid_states

				for valid_state_numb, src_state, dst_state, vs_payload in valid_states:
					

					sibling_state = state_list.get_state_by_num(valid_state_numb)
					if sibling_state.parent == state_tobe_pruned.parent: # siblings which have same parent
						# compare child_dict between sibling and current state
						if compare_ordered_dict(sibling_state.child_sr_dict, state_tobe_pruned.child_sr_dict) == True: # same state! Merge with sibling!
							invalid_states.append([state_tobe_pruned_num, parent_numb, valid_state_numb, state_tobe_pruned.spyld + " / " + state_tobe_pruned.rpyld])
							unique_in_step_2 = False
							print "[+] -> Same as sibling" + valid_state_numb + ". Merge with state " + valid_state_numb
							logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(state_tobe_pruned_num))
							break
						else:
							# print "sibling_state_sr_dict : "
							# print sibling_state.child_sr_dict
							# print "child_sr_dict : "
							# print state_tobe_pruned.child_sr_dict

							continue
					else:
						continue

				# I am unique! different from parent and other siblings!
				# But we have to compare it with other relatives...
				# Step 3
				# Compare with the other relatives
				if unique_in_step_2:
					print "[ ] -> No same siblings, compare it with other relatives..."
					target_level = current_level + 1
					currently_unique = True
					if target_level > 2:
						currently_unique = False
					else: # state in level 2
						currently_unique = True

					while True:
						if target_level == current_level + 1:
							for valid_state_numb, src_state, dst_state, vs_payload in valid_states:
								first_cousin = state_list.get_state_by_num(valid_state_numb)
								if first_cousin.parent != state_tobe_pruned.parent: # siblings which have different parent
									print "[-] -> compare state " + state_tobe_pruned.numb + " with other sibling state " + str(valid_state_numb) + " in same level"
									# compare child_dict between sibling and current state

									# print "[!!!] MOVE AND FIND SR starts in sachon... Port : %d" % sport
									# print state_tobe_pruned.child_sr_dict
									first_cousin.child_sr_dict = move_and_find_sr(valid_state_numb, state_tobe_pruned.child_sr_dict)

									if compare_ordered_dict(first_cousin.child_sr_dict, state_tobe_pruned.child_sr_dict) == True: # same state! Merge with sibling!
										invalid_states.append([state_tobe_pruned_num, state_tobe_pruned.parent, valid_state_numb, state_tobe_pruned.spyld + " / " + state_tobe_pruned.rpyld])
										currently_unique = False
										print "[+] -> Same as " + valid_state_numb + " in Step 3. Merge with state " + valid_state_numb
										logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(state_tobe_pruned_num))
										break
									else:
										currently_unique = True
										continue
								else:
									currently_unique = True
									continue
							
							if len(valid_states) == 0:
								currently_unique = True

						else:
							# get all parents in previous level
							for target_numb_in_level in state_list.get_states_by_level(target_level-1):
								# validition
								# compare with other parents
								if target_numb_in_level != state_tobe_pruned.parent:
									print "[-] -> compare state " + state_tobe_pruned.numb + " with ancestor state " + target_numb_in_level
									parent_state_in_level = state_list.get_state_by_num(target_numb_in_level)

									parent_state_in_level.child_sr_dict = move_and_find_sr(target_numb_in_level, state_tobe_pruned.child_sr_dict)

									# compare child_dict between prev and current state
									if compare_ordered_dict(parent_state_in_level.child_sr_dict, state_tobe_pruned.child_sr_dict) == True: # same state! Add transition to parent_state_in_level!
										invalid_states.append([state_tobe_pruned_num, state_tobe_pruned.parent, target_numb_in_level, state_tobe_pruned.spyld + " / " + state_tobe_pruned.rpyld])
										print "[+] -> Same as " + parent_state_in_level.numb + ". Add transitions to state " + parent_state_in_level.numb
										logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(state_tobe_pruned_num))
										currently_unique = False
										break
									else:
										print "[-] -> Differnt from relative state " + target_numb_in_level
										currently_unique = True
										continue
						

						if currently_unique == True: # valid yet
							target_level = target_level - 1
							#print "[-] target parent level : " + str(target_level) + "done."
							if target_level == 0:
								break
							else:
								continue
						else:
							break

					if currently_unique == True: # real valid state
						print "[+] -> **** Unique state " + state_tobe_pruned_num + " found ****"
						valid_states.append([state_tobe_pruned_num, cur_state, state_tobe_pruned_num, state_tobe_pruned.spyld + " / " + state_tobe_pruned.rpyld])
						# print "mydict : ", state_tobe_pruned.child_sr_dict
						# print "parentdict : ", parent_sr_msg_dict

						time.sleep(10)
		
		# state validation
		# add valid states
		for self_numb, src_state, dst_state, vs_payload in valid_states:
			self_state = state_list.get_state_by_num(self_numb)
			pm.add_state(self_numb)
			pm.add_transition(vs_payload + "\n", source = self_state.parent, dest = self_numb)
			print "[+] Valid state " + self_numb + " in level " + str(current_level) + " added"

		# remove invalid states
		for self_numb, src_state, dst_state, vs_payload in invalid_states:
			child_state = state_list.get_state_by_num(self_numb)
			pm.add_transition(vs_payload + "\n", source = src_state, dest = dst_state)
			#level_dict[current_level+1].remove(self_numb)
			state_list.remove_state(child_state)
			print "[+] Invalid state " + self_numb + " in level " + str(current_level) + " removed"
		
		elapsed_time = time.time() - g_start_time
		graphname = "diagram/level_" + str(current_level) + "_port_" + str(sport) + ".png"
		pm.model.graph.draw(graphname, prog='dot')
		current_level = current_level + 1
		print "[+] Level %d | Port No. %d | " % (current_level, sport), "Time Elapsed :", elapsed_time, "s"
		print '[+] Move to level ' + str(current_level)

	elapsed_time = time.time() - g_start_time
	print "Total elapsed time : ", elapsed_time, "\n"
	# Program normally ends.
	pm.model.graph.draw("diagram/prune_bfs_state_fin.png", prog='dot')
	logging.info(transition_info)
	img = mplotimg.imread("diagram/prune_bfs_state_fin.png")
	plt.imshow(img)
	plt.show()
	sys.exit()

else :
	print "[-] Invalid Input... exit...\n"
	sys.exit()

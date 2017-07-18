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

# 23.23.228.46 www.example.com
# 50.19.84.227 httpbin.org
# 192.168.1.96 Jaesangsin

dst_ip = sys.argv[1]
if len(sys.argv) == 3:
	sport = int(sys.argv[2])

#These informations are prerequisite.
dport = 80
sport = 3000 # find sport here
delimiter = "\r\n"
exit_label = "QUIT / 221 Goodbye.\n"
num_of_states = 0
g_start_time = 0
mul_start = 0
slowresp_timeout = 10
new_state = []
myiface = "enp0s3"
is_pruning = False
is_moving = False

cur_state = '0'
timeout = 0.01
sniff_timeout = 5
long_timeout = 15
current_level = 1

skip_msg_list = ['USER ANONYMOUS', 'PASS '] # for shortcut

if not os.path.exists('./diagram'):
	os.makedirs('./diagram')

#Mode Selection
mode1 = raw_input("[ ] Manual? or Auto? ( \'m\' - for testing / \'a\' - auto mode /) : ")
print skip_msg_list
if len(skip_msg_list) > 0:
	mode2 = raw_input("[ ] Take shortcut? ( \'y\' / \'n\' ) : ")

# It will contain trasition info like 
# trigger as key (string) : [src_state (string), dest_state (string), cnt]
transition_info = {}
mul_transition_info = {}

g_start_time = time.time()
skt = conf.L3socket(iface = myiface)

#Contains a http Protocol model
class ProtoModel(object):
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
level_dict = {1 : ['0']} # contains states for each level

def three_handshake(dst_ip, dport, sport):
	#Initiate TCP connection - 3 handshaking
	global skt
	seq = 0
	SYN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = "S", seq=seq) # SYN
	SYN_ACK = skt.sr1(SYN, verbose=False, retry=-1) # Listen ACK
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=seq + 1, ack=SYN_ACK.seq + 1, flags = "A") # SYN - ACK
	skt.send(ACK) # Send ACK, Listen http Response	
	
	return SYN_ACK # This is http Response from server

def disconnect_http(rp):
	# Send Req. QUIT (c) -> Get Resp Goodbye (s) -> get FIN-ACK (s) -> send ACK (c) -> Send FIN-ACK (c) -> get ACK
	start_time = time.time()
	global timeout, skt, finack_timeout, sniff_timeout, dport, sport

	temp_rp = rp
	# p = generate_http_msg("quit", rp)
	# # Listen FIN-ACK
	# ans, unans = skt.sr(p, multi=1, timeout=timeout*5, verbose=False) # SEND -> GET RESPONSE (normal case) -> GET FINACK
	# #ans, x = filter_tcp_ans(ans, None)

	# FIN_ACK = None

	# # Found FINACK in 2 or 3 packets
	# for sp, rp in ans:
	# 	if rp.getlayer("TCP").flags == 0x11:
	# 		FIN_ACK = rp

	# # Second barrier
	# if FIN_ACK is None:
	# 	rp = sniff(filter = "tcp", iface = myiface, timeout = timeout*20, count = 10)
	# 	for pkt in rp:
	# 		if pkt.haslayer("TCP"):
	# 			if pkt.getlayer("TCP").flags == 0x11:
	# 				FIN_ACK = pkt 

	# # Third barrier, Timeout checker
	# while True:
	# 	if FIN_ACK is not None:
	# 		break
	# 	else:
	# 		rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 1)
	# 		if len(rp) == 0:
	# 			# Timeout (Internal server error). No FINACK at all
	# 			logging.warning("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all" % sport)
	# 			for sp, rp in ans:
	# 				if rp.haslayer("TCP"):
	# 					FIN_ACK = rp # not FINACK
	# 			# SUCKS!
	# 			logging.warning("[!] [port no. %d] DISCONNECT :Timeout (Internal server error). No FINACK at all. No answered in sr." % sport)
	# 			FIN_ACK = temp_rp
	# 		#elif rp[0].getlayer("TCP").flags == 0x11:
	# 			# FIN_ACK found
	# 		#	FIN_ACK = rp[0]
	# 		else:
	# 			continue
	
	# Send ack to fin-ack
	# ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq, flags = "A") # SYN - ACK
	# skt.send(ACK)
	
	# # Finally, send FIN, ACK to the server
	# FIN_ACK = generate_http_fin_ack(FIN_ACK)
	# skt.send(FIN_ACK)

	FIN = IP(dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA", seq=rp.ack, ack=rp.seq + 1)
	FINACK = skt.sr1(FIN, verbose=False)
	LASTACK = IP(dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1)
	response = skt.sr1(LASTACK, verbose=False)
	return response

		
def send_receive(rp, payload):
	# SEND Req. -> Get ACK -> GET Rep. -> Send ACK (normal TCP-based protocol)
	global skt, timeout, sniff_timeout, long_timeout, mul_start, myiface, sport
	origin_rp = rp
	# Generate message with tokens
	p = generate_http_msg(payload, rp)
	ans, unans = skt.sr(p, multi=1, timeout=timeout, verbose=False)
	
	# Filter out only TCP packets
	ans = filter_tcp_ans(ans)
	# return process_response(ans, p, origin_rp)
	return process_response(ans, p, origin_rp)

	logging.debug("[!] [port no. %d] Sucks! What can we do? no process in if. Answer length is %d." % (sport, len(ans)))
	return origin_rp

def process_response(ans, p, origin_rp):
	global skt, timeout, sniff_timeout, long_timeout, mul_start, myiface, sport
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
		# return the last http packet. Scapy bug.
		if resp.haslayer("TCP") and resp.haslayer("Raw"):
			raw_resp = resp
		# check if finack
		elif resp.getlayer("TCP").flags == 0x11:
			finack_resp = resp

	if raw_resp is None and finack_resp is None:
		#Case3.
		print 'Case 3'
		#Slow response.
		resp_list = sniff(filter = "tcp", iface = myiface, timeout = slowresp_timeout, count = 2)
		for resp in resp_list:
			# return the last http packet. Scapy bug.
			# print resp.show()
			if resp.haslayer("TCP") and resp.haslayer("Raw"):
				raw_resp = resp
			# check if finack
			elif resp.getlayer("TCP").flags == 0x11:
				finack_resp = resp

	if raw_resp is not None:
		# MSG (Raw) packet found
		sentpayload = p.getlayer("Raw").load.replace('\r\n', '')
		rcvdpayload = raw_resp.getlayer("Raw").load.replace('\r\n', '')

		if rcvdpayload.find('Connection') != -1:
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Connection')]
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Date')]
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]
		elif rcvdpayload.find('Date') != -1:
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Date')]
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]
		else:
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]

		if finack_resp is None:
			#print "case1"
			# Case 1.
			# Send ACK and disconnect
			ack_p = generate_http_ack(raw_resp)
			skt.send(ack_p)
			if mode1 == 'm':
				print rcvdpayload
			else:
				build_state_machine(pm, pm.model.state, sentpayload, rcvdpayload, 1)
				return raw_resp, 0 # needs to disconnect later
		else:
			# print "Case 2"
			# Case 2.
			# Send ACK and FINACK
			ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=finack_resp.ack, ack=finack_resp.seq, flags = "A") # SYN - ACK
			skt.send(ACK)

			if mode1 == 'm':
				print rcvdpayload
			else:
				build_state_machine(pm, pm.model.state, sentpayload, rcvdpayload, 2)
			
			# Finally, send FIN, ACK to the server
			FIN_ACK = generate_http_fin_ack(finack_resp)
			skt.send(FIN_ACK)

			sport = sport + 1
			if sport > 60000:
				sport = 3000

			return FIN_ACK, 1

	else:
		# Crash?
		print "Case 4"
		logging.debug("[!] [port no. %d] No raw response. Possibly crash." % (sport))
		if len(resp_list) == 0:
			rp = origin_rp
		else:
			for resp in resp_list:
				rp = resp
		disconnect_http(rp)
		return rp, 1


def send_http_ack_build(sp, rp):
	global skt, pm, mul_start, mode1
	sentpayload = sp.getlayer("Raw").load.replace('\r\n', '')
	rcvdpayload = rp.getlayer("Raw").load.replace('\r\n', '')

	if rcvdpayload.find('Connection') != -1:
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Connection')]
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Date')]
			rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]
	elif rcvdpayload.find('Date') != -1:
		rcvdpayload = rcvdpayload[:rcvdpayload.find('Date')]
		rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]
	else:
		rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]

	ack_p = generate_http_ack(rp)
	skt.send(ack_p)
	if mode1 == 'm' :
		print rcvdpayload
	else :
		build_state_machine(pm, pm.model.state, sentpayload, rcvdpayload)
	return rp

def check_http_resp(pkt):
	global start_time
	if pkt.haslayer(Raw):
		return True
	else :
		return False

def check_fin_ack(pkt):
	# Cheeck if it is TCP fin-ack
	if pkt.haslayer(TCP) and pkt[TCP].flags == 0x11 :
		return True
	else :
		return False

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
	
def generate_http_ack(rp):
	# Generates ack message to http Response packet
	tcp_seg_len = get_tcp_seg_len(rp)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = "A")
	return p

def generate_tcp_ack(rp): 
	# Generate ack to the normal tcp (ack to the ack)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq, flags = "A")
	return p

def generate_http_fin_ack(rp):
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+1, flags = 0x11)
	return p

def generate_http_msg(payload, rp):
	tcp_seg_len = get_tcp_seg_len(rp)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq + 1, flags = 'A')/(payload + ' HTTP/1.1' + delimiter + 'Host:' + str(dst_ip) + delimiter + delimiter)
	return p


def build_state_machine(sm, crnt_state, spyld, rpyld, case_num):
	# sm : state machine, crnt_state : current state, payload : response packet payload 
	# Build and fix a state machine based on the response
	global num_of_states, transition_info, state_list, cur_state, new_state, is_pruning, is_moving, mul_start, current_level, skip_msg_list

	send_payload = spyld.replace('\r\n', '')
	send_payload = send_payload[:send_payload.find(' HTTP/1.1')]
	command = send_payload.split()[0]

	#In case of shortcut, ignore the shortcut messages
	for msg in skip_msg_list:
		if send_payload == msg:
			return

	#Check if the response already seen before
	#if mul_start == 0:
	# search each transition label in transition info data structure
	for t in transition_info.keys(): # No!
		if transition_info[t][0] == crnt_state:
			spyld_cmd = spyld.split(' ')[0]
			if re.search(spyld_cmd, t) and re.search(rpyld, t):
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
	if is_pruning == False and is_moving == False and case_num != 2:
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
		logging.info("[+] [port no. %d] State " % sport + dst_state + " added with transition " + t_label + " (Case 2)")
		pm.add_transition(t_label + "\n", source = crnt_state, dest = dst_state)
		return

	if is_pruning == False and is_moving == False:

		if mul_start == 0:
			transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info
		else:
			mul_transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info

		# Add child state for each parent
		# print str(cur_state)
		state_list.add_state(State(str(num_of_states), parent=str(cur_state), spyld=str(send_payload), rpyld=str(rpyld), group=str(command)))
		print "[+] State added (%s -> %d) : " % (cur_state, num_of_states) + str(num_of_states)
		logging.info("[+] [port no. %d] State (%s -> %d)" % (sport, cur_state, num_of_states) + " added with transition " + t_label)

		if level_dict.get(current_level+1) is None:
			level_dict[current_level+1] = [str(num_of_states)]
		else:
			level_dict[current_level+1].append(str(num_of_states))


def compare_ordered_dict(dict1, dict2):
	for i,j in zip(dict1.items(), dict2.items()):
		if i != j:
			return False
		else:
			continue
	return True

def compare_http_packet(pkt1, pkt2):
	# Compare two packets by looking at the http load
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

def filter_tcp_rp(rp, prev_http_resp):
	result_list = []
	for p in rp:
		# TCP layer in sr
		if p.haslayer("TCP"):
			# If first http response found, store and go to the next packet.
			if prev_http_resp is None and p.haslayer("Raw"):
				prev_http_resp = p
				result_list.append(p)
				continue
			# Exclude TCP retransmission packet
			# if the http packet received is previously seen, filter out.
			if prev_http_resp is not None and compare_http_packet(p, prev_http_resp) is True:
				# print "[!] Retransmission found in port no. %d. Skip this packet..." % sport
				continue
			else:
				result_list.append(p)
		else:
			continue

	new_http_resp = prev_http_resp
	return result_list, new_http_resp

def expand_states(states_in_the_level, token_db, args_db):
	global mode2, sport, dport, dst_ip, is_pruning

	is_pruning = False
	for current_state in states_in_the_level:
		print "[+] Current_state : " + str(current_state)
		
		# Set state moving message for current state
		move_state_msg = []
		target_state = current_state
		while True:
			parent_state = state_list.find_state(target_state).parent
			if parent_state is not None:
				move_state_msg.append(state_list.find_state(target_state).spyld)
				target_state = parent_state
				continue
			else: # root node
				break
		
		move_state_msg.reverse()

		# --------- Find command with single command  ---------
		mul_start = 0
		# for token in token_db:
		# 	# token = '/' + str(token)

		# 	if token == "quit":
		# 		continue

		# 	#Start with 3WHS
		# 	rp = three_handshake(dst_ip, dport, sport)

		# 	# In case of http,
		# 	# If handshake finished, the server sends response.
		# 	# Send ack and get the last req packet info.
		# 	# http_ack = generate_http_ack(rp)
		# 	# skt.send(http_ack)

		# 	# Take shortcut
		# 	if mode2 == 'y':
		# 		rp = shortcut(rp, skip_msg_list)

		# 	# Go to the target state
		# 	is_moving = True
		# 	for cmd in move_state_msg:
		# 		handshake_rp = rp
		# 		rp = send_receive(rp, cmd)
		# 	is_moving = False

			
		# 	# set state
		# 	pm.set_state(str(current_state))

		# 	# Send message and listen
		# 	rp = send_receive(rp, token)

		# 	# sport = sport + 1
		# 	# Finish TCP connection
		# 	disconnect_http(rp)

		# 	#Initialize current state as 0
		# 	cs = 0

		# 	sport = sport + 1
		# 	if sport > 60000:
		# 		sport = 3000
			
		# --------- Find valid message with multiple keywords  ---------
		mul_start = 1
		single_cmds = []
		multiple_msg_db = []

		# for child_state_numb in level_dict.get(current_level+1):
		# 	child_state = state_list.find_state(child_state_numb)
		# 	if child_state.parent == current_state:
		# 		child_single_cmds = child_state.group
		# 		if child_single_cmds not in single_cmds:
		# 			single_cmds.append(child_single_cmds)
		# print "[+] Single Commands are:"
		# print single_cmds
		# for cmd in single_cmds:
		# 	for args in args_db:
		# 		msg = cmd + ' ' + str(args[0])
		# 		multiple_msg_db.append(msg)
		
		# for msg in single_cmds: # group name

		for msg in token_db:
			for args in args_db: # argument
				if msg == "quit":
					continue
				
				multiple_msg = msg + ' ' + str(args)

				#Start with 3WHS
				rp = three_handshake(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				# http_ack = generate_http_ack(rp)
				# skt.send(http_ack)

				# Take shortcut
				# rp = shortcut(rp, skip_msg_list)

				is_moving = True
				for mv_msg in move_state_msg:
					handshake_rp = rp
					rp, res = send_receive(rp, mv_msg)
				is_moving = False

				# set state
				pm.set_state(str(current_state))

				temp_rp = rp
				# Send multiple message and listen
				rp, res = send_receive(rp, multiple_msg)

				# Finish TCP connection
				if res == 0:
					disconnect_http(rp)
					sport = sport + 1
					if sport > 60000:
						sport = 3000

				#Initialize current state as 0
				cs = 0


def shortcut(rp, skip_msg_list):
	# Take messages to skip. Using the messages, 
	# it goes to the new starting point fast.
	
	# There is not shortcut
	if len(skip_msg_list) == 0:
		return
	
	for msg in skip_msg_list:
		handshake_rp = rp
		rp, res = send_receive(rp, msg)

	return rp


#################################################
################ MAIN PART #####################

#Crate protocol state machine
pm = generate_state_machine()

if mode1 == 'm':
	while True:
		rp = three_handshake(dst_ip, dport, sport)
		#Next Ack no. calculation : last seq + prev. tcp payload len
		# http_ack = generate_http_ack(rp)
		# send(http_ack)
		print "[ ] Enter message. If you want to stop, type \"quit\""
		
		for i in range(100) :
			payload = raw_input("[!] payload? : ")
			if payload == "quit":
				disconnect_http(rp)
				sport = sport + 1
				break
			p = generate_http_msg(payload, rp)
			ans, unans = sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
			#ans = filter_tcp_ans(ans)
			
			rp = process_response(ans, p, rp)

		isquit = raw_input("[!] Are you sure to quit the program? (y/n)")
		if isquit == "y":
			print "Goodbye..."
			break
		else :
			print "Start from the beginning..."

elif mode1 == 'a' or mode == 'A':
	# get all command candidates
	with open("./tokenfile/total_tokens.txt") as f:
		# token_db = pickle.load(f)
		# token_db = ['retr', 'data', 'type', 'get', 'size', 'list', 'help', 'mode', 'user', 'port', 'pass', 'opts', 'pwd', 'cwd', 'rest', 'stat', 'acct', 'prot', 'noop', 'pasv']
		token_db = ['GET', 'POST', 'HEAD', 'PUT', "DELETE", 'TRACE', 'CONNECT', 'OPTIONS']

	# get all argument candidates
	with open("./args/total_args.txt") as a:
		args_db = pickle.load(a)
		#args_db = [['anonymous'], ['510123124512'], ['/'], ['127.0.0.1']]
		
	while True: # for each level
		start_time = time.time()
		print '[+] Send total %d tokens in level ' % len(token_db) + str(current_level)

		#states_in_the_level : contains states which are present at each level
		states_in_the_level = level_dict.get(current_level, [])
		if states_in_the_level == []: # program end
			break

		### Phase 1. Expansion ###
		expand_states(states_in_the_level, token_db, args_db)
		
		### Pruning ###
		is_pruning = True
		
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

			# print prune_move_state_msg

			parent_spyld = parent_sr_msg_dict.keys()

			# every payload sent in parent nodes
			for msg_sent in parent_spyld:
				# print msg_sent
				if msg_sent == "quit":
					continue
				
				#Start with 3WHS
				rp = three_handshake(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				# http_ack = generate_http_ack(rp)
				# skt.send(http_ack)

				# Take shortcut
				# rp = shortcut(rp, skip_msg_list)

				for msg in prune_move_state_msg:
					logging.info("[+] [port no. %d] Prune Move (depth %d -> %d) msg : " % (sport, current_level, current_level+1) + str(msg))
					rp, res = send_receive(rp, msg)

				# Send message and listen
				logging.info("[+] [port no. %d] Prune Send msg : " % sport + str(msg_sent))

				origin_rp = rp
				rp, res = send_receive(rp, msg_sent)
				
				# if normal, add to child_sr_dict
				if compare_http_packet(rp, origin_rp) is False:
					if rp.getlayer("Raw") is not None:
						rcvdpayload = rp.getlayer("Raw").load.replace('\r\n', '')

						if rcvdpayload.find('Connection') != -1:
								rcvdpayload = rcvdpayload[:rcvdpayload.find('Connection')]
								rcvdpayload = rcvdpayload[:rcvdpayload.find('Date')]
								rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]
						elif rcvdpayload.find('Date') != -1:
							rcvdpayload = rcvdpayload[:rcvdpayload.find('Date')]
							rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]
						else:
							rcvdpayload = rcvdpayload[:rcvdpayload.find('Server')]

						child_sr_dict[str(msg_sent)] = rcvdpayload
					else:
						res = 1
				
				# Finish TCP connection
				if res == 0:
					disconnect_http(rp)

				#Initialize current state as 0
				cs = 0

				sport = sport + 1
				if sport > 60000:
					sport = 3000
					
				if sport % 100 == 0 :
					elapsed_time = time.time() - g_start_time
					print "[+] Port No. : %d | " % sport, "Time Elapsed :", elapsed_time, "s"
					graphname = "diagram/level_" + str(current_level) + "_port_" + str(sport) + ".png"
					pm.model.graph.draw(graphname, prog='dot')
			
			# After searching all the parent's s/r
			# Check below for merging

			state_list.find_state(child_state_numb).sr_dict = child_sr_dict
			# STEP1. Parent
			# - Compare child dict with parent dict
			# - If differnt, let it be alive.
			# If same merge with parent.
			# print parent_sr_msg_dict
			# print '***************************************'
			# print child_sr_dict
			if compare_ordered_dict(parent_sr_msg_dict, child_sr_dict) == True: # same state, prune state
				print "[+] -> Same as parent. Merge with state " + parent_numb
				invalid_states.append([child_state_numb, parent_numb, parent_numb, child_state.spyld + " / " + child_state.rpyld])
				logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(child_state_numb))
			else:
				print "[-] -> Differnt from parent. Now check with siblings!"
				# STEP 2. Sibling
				# - Compare its child dict with other childs' dict
				# - If different with all the childs' dict (or first), let it be alive
				# - If any same dict found, merge with the child
				unique_in_step_2 = True
				
				child_level = current_level + 1
				for valid_state_numb, src_state, dst_state, vs_payload in valid_states:

					sibling_state = state_list.find_state(valid_state_numb)
					if sibling_state.parent == child_state.parent: # siblings which have same parent
						# compare child_dict between sibling and current state
						if compare_ordered_dict(sibling_state.sr_dict, child_state.sr_dict) == True: # same state! Merge with sibling!
							invalid_states.append([child_state_numb, parent_numb, valid_state_numb, child_state.spyld + " / " + child_state.rpyld])
							unique_in_step_2 = False
							print "[+] -> Same as " + valid_state_numb + ". Merge with state " + valid_state_numb
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
					print "[ ] -> No same siblings, but we have to compare it with other relatives..."
					target_level = current_level + 1
					currently_unique = True
					if target_level > 2:
						currently_unique = False
					else: # state in level 2
						currently_unique = True

					while True:
						if target_level == current_level + 1:
							for valid_state_numb, src_state, dst_state, vs_payload in valid_states:
								first_cousin = state_list.find_state(valid_state_numb)
								if first_cousin.parent != child_state.parent: # siblings which have same parent
									print "[-] -> compare state " + child_state.numb + " with other state " + target_numb_in_level + " in same level"
									# compare child_dict between sibling and current state
									if compare_ordered_dict(first_cousin.sr_dict, child_state.sr_dict) == True: # same state! Merge with sibling!
										invalid_states.append([child_state_numb, child_state.parent, valid_state_numb, child_state.spyld + " / " + child_state.rpyld])
										currently_unique = False
										print "[+] -> Same as " + valid_state_numb + " in Step 3. Merge with state " + valid_state_numb
										logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(child_state_numb))
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
							for target_numb_in_level in level_dict[target_level]:
								# validition
								# compare with other parents
								if target_numb_in_level != child_state.parent:
									print "[-] -> compare state " + child_state.numb + " with ancestor state " + target_numb_in_level
									parent_state_in_level = state_list.find_state(target_numb_in_level)
									# compare child_dict between prev and current state
									if compare_ordered_dict(parent_state_in_level.sr_dict, child_state.sr_dict) == True: # same state! Add transition to parent_state_in_level!
										invalid_states.append([child_state_numb, child_state.parent, target_numb_in_level, child_state.spyld + " / " + child_state.rpyld])
										print "[+] -> Same as " + parent_state_in_level.numb + ". Add transitions to state " + parent_state_in_level.numb
										logging.debug("[+] [port no. %d] state number to be pruned : " % sport + str(child_state_numb))
										currently_unique = False
										break
									else:
										print "[-] -> Differnt from relative state " + target_numb_in_level
										currently_unique = True
										continue
						

						if currently_unique == True: # valid yet
							target_level = target_level - 1
							print "[-] target parent level : " + str(target_level)
							if target_level == 0:
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
			pm.add_state(self_numb)
			pm.add_transition(vs_payload + "\n", source = self_state.parent, dest = self_numb)
			print "[+] Valid state " + self_numb + " in level " + str(current_level) + " added"

		# remove invalid states
		for self_numb, src_state, dst_state, vs_payload in invalid_states:
			child_state = state_list.find_state(self_numb)
			pm.add_transition(vs_payload + "\n", source = src_state, dest = dst_state)
			level_dict[current_level+1].remove(self_numb)
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

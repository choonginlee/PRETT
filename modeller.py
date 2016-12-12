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
	global timeout, skt

	p = generate_ftp_msg("QUIT", rp)
	# Listen FIN-ACK
	ans, unans = skt.sr(p, multi=1, timeout=timeout*2, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
	#logging.info("[+] [Diconnect FTP] After sr")

	FIN_ACK = None

	if len(ans) < 2:
		return
	else:
		# 2 or 3 packets as reponse
		# find fin_ack
		for i in range(len(ans)):
			if ans[i][1].haslayer("TCP") and ans[i][1].getlayer("TCP").flags == 0x11:
				FIN_ACK = ans[i][1]
				break

	if FIN_ACK is None:
		print "[disconnect_ftp] which packets are in the ans?"
		for x in ans:
			print x

	# Send ack to fin-ack
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq, flags = "A") # SYN - ACK
	skt.send(ACK)
	#logging.info("[+] [Diconnect FTP] After sending ACK")

	# Finally, send FIN, ACK to the server
	FIN_ACK = generate_ftp_fin_ack(FIN_ACK)
	skt.send(FIN_ACK)
	# next_seq = FIN_ACK.seq + 1
	# print next_seq
	#logging.info("[+] FTP disconnected\n")


def send_receive_ftp(rp, token):
	# SEND Req. -> Get ACK -> GET Rep. -> Send ACK (normal TCP-based protocol)
	global skt, cnt, timeout, sniff_timeout
	temp_rp = rp
	cnt = cnt + 1
	start_time = time.time()

	# Generate message from tokens
	payload = token
	p = generate_ftp_msg(payload, rp)
	#print "[+] Message to be sent \n", p.getlayer("Raw").show()

	# Send Req, then get ACK and Resp of tcp
	#logging.info("[+] [SND RCV FTP] BEFORE SR")
	ans, unans = skt.sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
	#logging.info("[+] [SND RCV FTP] AFTER SR")

	# Temporary unavailable
	# Not a pacekt in short timeout! (even ack)
	# We don't know whether it is normal or not.
	if len(ans) == 0:
		logging.debug("[ ] [port no. %d] No packet in short timeout!" % sport)
		# Listen again.
		rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 2)
		if len(rp) < 2:
			# Internal server error. (TIMEOUT)
			logging.debug("[!] [port no. %d] It takes too long time! Add transition as timeout" % sport)
			build_state_machine(ftpmachine, ftpmachine.model.state, p.getlayer("Raw").load, "Timeout")
			return temp_rp
		else: 
			# Temprary error. Maybe other TCP packet intervened.
			# It should be conducted again!
			#logging.debug("[+] [port no. %d] 2 TCP packets captured. len : " % sport + str(len(rp)) + "|" + "".join(str(x.summary()) for x in rp))
			sentpayload = p.getlayer("Raw").load
			
			# find the ftp packet in responses
			ftp_index = 2
			for i in range(len(rp)):
				if rp[i].haslayer("Raw"):
					ftp_index = i # store the index of ftp pacekts in rp

			if ftp_index == 2:
				logging.debug("[-] [port no. %d] No FTP packet in both packets. Please refer the packets above." % sport)
				return send_receive_ftp(temp_rp, token)
			else:
				pass

			# if found, send ack
			rcvdpayload = rp[ftp_index].getlayer("Raw").load
			logging.debug("[+] [port no. %d] login failed wanted... plz...  /  " % sport + str(rcvdpayload))

			if ftp_index == 1:
				logging.debug("[!] [port no. %d] ftp_index is 1" % sport)
				ack_p = generate_ftp_ack(rp[1])
			else: # ftp packet is in the first packet
				logging.debug("[!] [port no. %d] ftp_index is %d" % sport, ftp_index)
				ack_p = generate_tcp_ack(rp[1]) # generate ack of last tcp packet
			
			skt.send(ack_p)
			build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
			return rp[ftp_index]

	for sp, rp in ans:
		if rp.haslayer("Raw"):
			sentpayload = sp.getlayer("Raw").load
			rcvdpayload = rp.getlayer("Raw").load
			#logging.info("[+] RESPONSE FTP PAYLOAD : " + rcvdpayload) # this is protocol response message
			ack_p = generate_ftp_ack(rp)
			#elapsed_time = time.time() - start_time
			#print "After sniffing and parsing ftp..." + str(elapsed_time) + "\n"
			skt.send(ack_p)
			#logging.info("[+] FTP ACK sent.")
			build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
			#logging.info("[+] [SND RCV FTP] AFTER BUILDING MACHINE")
			return rp

	# Response length > 0 (probably only ack)
	# but there is no FTP. Maybe internal processing takes time.
	# ex) user name -> pass *** 
	# Therefore, it is normal but we listen again.
	rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 1)
	if len(rp) > 0 and rp[0].haslayer("Raw"):
		logging.debug("[!] [port no. %d] internal processing takes time." % sport)
		ack_p = generate_ftp_ack(rp[0])
		skt.send(ack_p)
		# It is normal FTP.
		return rp[0]
	else:
		# TCP (ACK) + TCP (Sniffed) / TCP (ACK) + Timeout 15 sec.
		# Sucks. Manually resolve it/
		print "SUCKS! Find the log!"
		logging.debug("[+] [port no. %d] len : " % sport + str(len(rp)) + "|" + "".join(str(x.summary()) for x in rp))
		return temp_rp

	#logging.debug("No response FTP packet!")
	#return "no response"
	# sys.exit()
	

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

	
def generate_ftp_ack(rp):
	# Generates ack message to FTP Response packet
	tcp_seg_len = len(rp.getlayer(Raw).load)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = "A")
	#logging.info("[+] [GEN FTP ACK] - PKT GEN OVER.")
	return p

def generate_tcp_ack(rp): 
	# Generate ack to the normal tco (ack to the ack)
	p = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=rp.ack, ack=rp.seq+1, flags = "A")
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
	global skt
	FIN = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, flags = 0x11) # FIN
	FIN_ACK = skt.sr1(FIN, verbose=False, retry=-1)
	ACK = IP(dst=dst_ip)/TCP(sport = sport, dport = dport, seq=FIN_ACK.ack, ack=FIN_ACK.seq + 1, flags = "A")
	skt.send(ACK)
	#logging.info("[+] TCP connection clean ... \n")


def build_state_machine(sm, crnt_state, spyld, rpyld):
	# sm : state machine, crnt_state : current state, payload : response packet payload 
	
	# Build and fix a state machine based on the response
	global num_of_states, transition_info, state_list, cur_state, cnt, state_found, new_state, depth_count, is_pruning, mul_start, current_level

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
	else:
		for t in mul_transition_info.keys():
			if mul_transition_info[t][0] == crnt_state:
				#logging.info("Trigger t : \n", t)
				if rpyld == "Timeout" and len(send_payload) > 15:
					abbr_spyld = send_payload[0:15] + "-abbr"
					break
				if re.search(rpyld, t):
					# if it is already seen,
					# - No need to make new state
					# - Find the corresponding src & dst state
					# - Add input counts for each seen transition
					mul_transition_info[t][2] = mul_transition_info[t][2] + 1
					return


	#If not seen before,
	# - Add a new state
	# - Add a new transition from current state
	if is_pruning == 0:
		num_of_states = num_of_states + 1
		dst_state = str(num_of_states)
		# sm.add_states(dst_state)

	# In case of timeout with huge inputs, store full send/receive label in transition_info
	# but store abbrebiated send/receive label in transition model (as well as state machine diagram)
	if len(send_payload) > 15:
		abbr_spyld = send_payload[0:15] + "-abbr"
		t_label = abbr_spyld + " / " + rpyld
	else:
		t_label = send_payload + " / " + rpyld

	if is_pruning == 0:

		if mul_start == 0:
			transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info
		else:
			mul_transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info

		state_list.add_state(State(str(num_of_states), parent=str(cur_state), spyld=str(send_payload), rpyld=str(rpyld)))
		print "state added : " + str(num_of_states)
		if level_dict.get(current_level+1) is None:
			level_dict[current_level+1] = [str(num_of_states)]
		else:
			level_dict[current_level+1].append(str(num_of_states))
		
		state_found = 1 # for dfs
		logging.info("[+] [port no. %d] State " % sport + crnt_state + " added with transition " + t_label)
		logging.info("[+] [port no. %d] State " % sport + dst_state + " added with transition " + t_label)

		# transition edit later
		# sm.add_transition(t_label, source = crnt_state, dest = dst_state)


#################################################
################ MAIN PART #####################

logging.basicConfig(level=logging.DEBUG, filename="ptmsg_log", filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")

dst_ip = sys.argv[1]

#These informations are prerequisite.
dport = 21
sport = 1000 # find sport here
delimiter = "\r\n"
exit_label = "QUIT / 221 Goodbye."

num_of_states = 0
g_start_time = 0
state_found = 0
mul_start = 0
new_state = []
myiface = "enp0s8"
# next_seq = 0
is_pruning = 0

level_dict = {1 : ['0']}
cur_state = '0'
state_list = StateList([State('0')])
timeout = 0.01
sniff_timeout = 5
depth_count = 0
current_level = 1

if not os.path.exists('./diagram'):
	os.makedirs('./diagram')

#Mode Selection
mode = raw_input("[!] Manual? or Auto(BFS, DFS)? ( \'m\' - for testing / \'b\' - bfs mode / \'d\' - dfs mode / \'p\' - prune mode /) : ")

#Crate ftp machine and assign protocol model
ftpmachine = generate_ftp_model()

# It will contain trasition info like 
# trigger as key (string) : [src_state (string), dest_state (string), cnt]
transition_info = {}
mul_transition_info = {}

cnt = 0
unique_cnt = 0

# Disable Kernel's RST in iptable
os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
g_start_time = time.time()
skt = conf.L3socket(iface = myiface)

if mode == 'm':
	rp = handshake_init(dst_ip, dport, sport)
	#Next Ack no. calculation : last seq + prev. tcp payload len
	ftp_ack = generate_ftp_ack(rp)
	send(ftp_ack)
	
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
				#logging.info("[+] RESPONSE FTP PAYLOAD : \n", rcv.getlayer("Raw").load) # this is protocol response message
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

		# expansion
		is_pruning = 0
		for current_state in level_state_list:
			cur_state = current_state
			print "current_state : " + str(cur_state)
			move_state_token =[]
			target_state = cur_state
			
			while True:
				current_parent = state_list.find_state(target_state).parent
				if current_parent is not None:
					move_state_token.append(state_list.find_state(target_state).spyld)
					target_state = current_parent
					continue
				else: # root node
					break
			
			move_state_token.reverse()

			mul_start = 0
			# Simple message format ( 1 word )
			single_cnt = 0
			for token in token_db:
				single_cnt = single_cnt + 1
				if single_cnt == 1001:
					break
				if token == "quit":
					continue
				sport = sport + 1
				if sport > 60000:
					sport = 1000

				#Start with 3WHS
				rp = handshake_init(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)
				#logging.info("[+] [MAIN] AFTER SEND")

				for tk in move_state_token:
					temp = rp
					rp = send_receive_ftp(rp, tk)
					if rp == "error":
					     print 'rp error when find state'

				# set state
				ftpmachine.set_state(str(cur_state))
				unique_cnt = unique_cnt + 1

				temp_rp = rp
				# Send message and listen
				rp = send_receive_ftp(rp, token)
				
				if rp == "error":
					print 'rp error before disconnect'
					disconnect_ftp(temp_rp)
				else:
					# Finish TCP connection
					disconnect_ftp(rp)

				#Initialize current state as 0
				cs = 0
				
				if unique_cnt % 1000 == 0 :
					elapsed_time = time.time() - g_start_time
					print "[+] COUNT OF TRIALS : %d | " % unique_cnt, "Time Elapsed :", elapsed_time, "s"
					graphname = "diagram/prune_bfs_state" + str(unique_cnt) + ".png"
					ftpmachine.model.graph.draw(graphname, prog='dot')

			mul_start = 1
			# multiple token stage
			children_tokens = []
			multiple_token_db = []

			for child_state_numb in level_dict.get(current_level+1):
				child_state = state_list.find_state(child_state_numb)
				if child_state.parent == cur_state:
					child_spyld = child_state.spyld
					children_tokens.append(child_spyld)
					print child_spyld
			
			for tok in children_tokens:
				for args in args_db:
					multiple_token = tok.replace('\r\n', '') + ' ' + args[0] + '\r\n'
					multiple_token_db.append(multiple_token)

			print len(multiple_token_db)
			for token in multiple_token_db:
				if token == "quit":
					continue
				sport = sport + 1
				if sport > 60000:
					sport = 1000
					
				#Start with 3WHS	
				rp = handshake_init(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)
				#logging.info("[+] [MAIN] AFTER SEND")

				for tk in move_state_token:
					temp = rp
					mul_tk = tk + '\r\n'
					logging.info("[+] [port no. %d] (State moving) Parent token : " % sport + str(mul_tk))
					rp = send_receive_ftp(rp, mul_tk)
					if rp == "error":
					     print 'rp error when find state'

				# set state
				ftpmachine.set_state(str(cur_state))
				unique_cnt = unique_cnt + 1

				temp_rp = rp
				# Send message and listen
				logging.info("[+] [port no. %d] (Multiple MSG Send) token : " % sport + str(token))
				rp = send_receive_ftp(rp, token)
				
				if rp == "error":
					print 'rp error before disconnect'
					disconnect_ftp(temp_rp)
				else:
					# Finish TCP connection
					disconnect_ftp(rp)

				#Initialize current state as 0
				cs = 0
				
				if unique_cnt % 1000 == 0 :
					elapsed_time = time.time() - g_start_time
					print "[+] COUNT OF TRIALS : %d | " % unique_cnt, "Time Elapsed :", elapsed_time, "s"
					graphname = "diagram/prune_bfs_state" + str(unique_cnt) + ".png"
					ftpmachine.model.graph.draw(graphname, prog='dot')

			# pruning stage
			is_pruning = 1

			next_state_list = level_dict.get(current_level+1, [])

			if next_state_list == []: # no valid states found
				break

			valid_states = []	
			invalid_states = []

			for child_state in next_state_list:

				print 'prune start in state ' + str(child_state)

				parent_numb = state_list.find_state(child_state).parent
				parent_sr_dict = {}
				for next_state_numb in next_state_list:
					next_state = state_list.find_state(next_state_numb)
					if next_state.parent == parent_numb:
						parent_sr_dict[next_state.spyld] = next_state.rpyld
				

				prune_move_state_token =[]
				prune_current_state = child_state
				prune_target_state = prune_current_state
				child_sr_dict = {}
				
				while True:
					prune_current_parent = state_list.find_state(prune_target_state).parent
					if prune_current_parent is not None:
						prune_move_state_token.append(state_list.find_state(prune_target_state).spyld)
						prune_target_state = prune_current_parent
						continue
					else: # root node
						break
				
				prune_move_state_token.reverse()

				parent_spyld = parent_sr_dict.keys()
				# Simple message format ( 1 word )
				for token in parent_spyld:
					if token == "quit":
						continue
					sport = sport + 1
					if sport > 60000:
						sport = 1000

					#Start with 3WHS
					rp = handshake_init(dst_ip, dport, sport)

					#If handshake finished, the server sends response. Send ack and get the last req packet info.
					ftp_ack = generate_ftp_ack(rp)
					skt.send(ftp_ack)
					#logging.info("[+] [MAIN] AFTER SEND")

					for tk in prune_move_state_token:
						temp = rp
						tk_dlm = tk + '\r\n'
						logging.info("[+] [port no. %d] Prune Move tokens : " % sport + str(tk))
						rp = send_receive_ftp(rp, tk_dlm)
						if rp == "error":
						     print 'rp error when find state in pruning'

					# set state
					# ftpmachine.set_state(str(prune_current_state))
					unique_cnt = unique_cnt + 1

					temp_rp = rp
					# Send message and listen
					logging.info("[+] [port no. %d] Prune Send token : " % sport + str(token))
					rp = send_receive_ftp(rp, token)
					
					if rp == "error":
						print 'rp error before disconnect'
						disconnect_ftp(temp_rp)
					else:
						child_sr_dict[str(token).replace('\r\n', '')] = rp.getlayer("Raw").load
						# Finish TCP connection
						disconnect_ftp(rp)

					#Initialize current state as 0
					cs = 0

					if unique_cnt % 1000 == 0 :
						elapsed_time = time.time() - g_start_time
						print "[+] COUNT OF TRIALS : %d | " % unique_cnt, "Time Elapsed :", elapsed_time, "s"
						graphname = "diagram/prune_bfs_state" + str(unique_cnt) + ".png"
						ftpmachine.model.graph.draw(graphname, prog='dot')
				
				if cmp(parent_sr_dict, child_sr_dict) == 0: # same state, prune state
					invalid_states.append(child_state)
				else: # different state
					# add transition here
					valid_states.append(child_state)

			for invalid_state_numb in invalid_states:
				invalid_state = state_list.find_state(invalid_state_numb)
				if invalid_state is not None:
					# print str(temp_numb) + " / " + str(current_state)
					ftpmachine.add_transition(invalid_state.spyld + " / " + str(parent_sr_dict.get(invalid_state.spyld, None)), source = str(invalid_state.parent), dest = str(invalid_state.parent))
					print "invalid state : " + str(invalid_state_numb) + " in level " + str(current_level+1)
					state_list.remove_state(state_list.find_state(invalid_state_numb))
					level_dict[current_level+1].remove(str(invalid_state_numb))

			for valid_state_numb in valid_states:
				valid_state = state_list.find_state(valid_state_numb)
				if valid_state is not None:
					print "valid state : " + str(valid_state_numb) + " in level " + str(current_level+1)
					ftpmachine.add_states(str(valid_state_numb))
					ftpmachine.add_transition(valid_state.spyld + " / " + str(parent_sr_dict.get(valid_state.spyld, None)), source = str(valid_state.parent), dest = str(valid_state_numb))
		

			elapsed_time = time.time() - start_time
			print "Level %d elapsed time : " % current_level, elapsed_time, "\n"	
			current_level = current_level + 1
			print 'move to level ' + str(current_level)

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
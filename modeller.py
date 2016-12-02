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
	def __init__(self, numb, parent=None, token=None, token_index=0, child_list=[], depth=0, children=[], child_dict={}, next_child_idx=0):
		self.numb = numb
		self.parent = parent
		self.token = token
		self.token_index = token_index
		self.child_list = child_list
		self.depth = depth
		self.children = children
		self.child_dict = child_dict
		self.next_child_idx = next_child_idx


class StateList:
	def __init__(self, state_list=[]):
		self.state_list = state_list

	def add_state(self, state):
		self.state_list.append(state)

	def find_state(self, numb):
		for state in self.state_list:
			if state.numb == numb:
				return state
		return None

	def remove_state(self, state):
		self.state_list.remove(state)


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
	ans, unans = skt.sr(p, multi=1, timeout=timeout, verbose=False) # SEND -> GET ACK -> GET RESPONSE (normal case)
	#logging.info("[+] [Diconnect FTP] After sr")

	if len(ans) < 2:
		return
	FIN_ACK = ans[1][1]

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

	if len(ans) == 0:
		logging.debug("No packet in short timeout!")
		# It takes long time to get... sniff single tcp packet and determine...
		rp = sniff(filter = "tcp", iface = myiface, timeout = sniff_timeout, count = 1)
		if len(rp) == 0:
			logging.debug("[!] Count : " + str(cnt) + " | It takes too long time! Add transition as timeout")
			build_state_machine(ftpmachine, ftpmachine.model.state, p.getlayer("Raw").load, "Timeout")
			return temp_rp
		else:
			logging.debug("[+] 1+ TCP packet captured. " + str(len(rp)) + "".join(str(x.summary()) for x in rp))
			sentpayload = p.getlayer("Raw").load
			if rp[0].getlayer("Raw") is None:
				return "error"
			rcvdpayload = rp[0].getlayer("Raw").load
			#logging.info("[+] RESPONSE FTP PAYLOAD : " + rcvdpayload) # this is protocol response message
			ack_p = generate_ftp_ack(rp[0])
			#logging.info("[+] [SND RCV FTP] AFTER FTP MSG 2 FUNC")

			#elapsed_time = time.time() - start_time
			#print "After sniffing and parsing ftp..." + str(elapsed_time) + "\n"
			
			skt.send(ack_p)
			#logging.info("[+] FTP ACK sent.")
			build_state_machine(ftpmachine, ftpmachine.model.state, sentpayload, rcvdpayload)
			#logging.info("[+] [SND RCV FTP] AFTER BUILDING MACHINE")
			return rp[0]

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

	logging.debug("No response FTP packet!")
	return "error"
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
	global state_numb_list
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
	global num_of_states, transition_info, state_numb_list, state_list, current_state, cnt, state_found, new_state, depth_count, is_pruning

	#Check if the response already seen before
	for t in sm.get_triggers(crnt_state):
		#logging.info("Trigger t : \n", t)
		if rpyld == "Timeout" and len(spyld) > 15:
			abbr_spyld = spyld[0:15] + "-abbr"
			break
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
	if is_pruning == 0:
		num_of_states = num_of_states + 1
		dst_state = str(num_of_states)
		sm.add_states(dst_state)

	# In case of timeout with huge inputs, store full send/receive label in transition_info
	# but store abbrebiated send/receive label in transition model (as well as state machine diagram)
	if len(spyld) > 15:
		abbr_spyld = spyld[0:15] + "-abbr"
		t_label = abbr_spyld + " / " + rpyld
	else:
		t_label = spyld + " / " + rpyld

	if is_pruning == 0:

		transition_info[t_label] = [crnt_state, dst_state, 1] # add transition info
		state_numb_list.append(str(num_of_states))
		state_list.add_state(State(num_of_states, parent=current_state, token=str(spyld), depth=depth_count))
		state_list.find_state(current_state).children.append(num_of_states)
		state_list.find_state(current_state).child_dict[str(spyld)] = str(rpyld)

		state_found = 1
		logging.info("[+] Count : " + str(cnt) + " | State " + crnt_state + " added with transition " + t_label)
		logging.info("[+] Count : " + str(cnt) + " | State " + dst_state + " added with transition " + t_label)

		sm.add_transition(t_label, source = crnt_state, dest = dst_state)


#################################################
################ MAIN PART #####################

logging.basicConfig(level=logging.DEBUG, filename="ptmsg_log", filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")

dst_ip = sys.argv[1]

#These informations are prerequisite.
dport = 21
sport = 30000 # find sport_here
delimiter = "\r\n"
exit_label = "QUIT / 221 Goodbye."

num_of_states = 0
g_start_time = 0
state_found = 0
new_state = []
myiface = "enp0s8"
# next_seq = 0
is_pruning = 0

state_numb_list = ['0']
current_state = 0
state_list = StateList()
init_state = State(0)
state_list.add_state(init_state)
timeout = 0.004
sniff_timeout = 5
depth_count = 0

if not os.path.exists('./diagram'):
	os.makedirs('./diagram')

#Mode Selection
mode = raw_input("[!] Manual? or Auto(BFS, DFS)? ( \'m\' - for testing / \'b\' - bfs mode / \'d\' - dfs mode / \'p\' - prune mode /) : ")

#Crate ftp machine and assign protocol model
ftpmachine = generate_ftp_model()

# It will contain trasition info like 
# trigger as key (string) : [src_state (string), [dest_state (string)]]
transition_info = {}

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
				move_state_token.append(state_list.state_list[target_state].token)
				target_state = current_parent
				continue
			else: # root node
				break
				
		move_state_token.reverse()

		# Simple message format ( 1 word )
		for token in token_db:
			if token == "quit":
				continue
			sport = sport + 1
			if sport > 60000:
				sport = 1000

			#Start with 3WHS
			logging.info("[+] MSG Send Trial : %d" % cnt)
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
					rp = temp
			
			# set state
			ftpmachine.set_state(str(current_state))
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
				graphname = "diagram/bfs_state" + str(unique_cnt) + ".png"
				ftpmachine.model.graph.draw(graphname, prog='dot')
				#img = mplotimg.imread("diagram/sample_state.png")
				#plt.imshow(img)
				#plt.show()

		'''
		# validation check
		valid_tokens = []
		for state in state_list.state_list:
			if state.parent == current_state: # get child node
				valid_tokens.append(state.token)

		for token in valid_tokens:
			sport = sport + 1

			#Start with 3WHS
			rp = handshake_init(dst_ip, dport, sport)
			global skt

			#If handshake finished, the server sends response. Send ack and get the last req packet info.
			ftp_ack = generate_ftp_ack(rp)
			send(ftp_ack, verbose=False)

			# set state
			ftpmachine.set_state(str(current_state))

			# Send message and listen
			rp = send_receive_ftp(rp, token[0])

			# Finish TCP connection
			disconnect_ftp(rp)
		'''

		current_state = current_state + 1

		if current_state > num_of_states:
			break
	
	elapsed_time = time.time() - g_start_time
	print "Total elapsed time : ", elapsed_time, "\n"
	# Program normally ends.
	ftpmachine.model.graph.draw("diagram/bfs_state_fin.png", prog='dot')
	logging.info(transition_info)
	img = mplotimg.imread("diagram/bfs_state_fin.png")
	plt.imshow(img)
	plt.show()
	sys.exit()

elif mode == 'd':
	# dfs
	with open("./tokenfile/total_tokens.txt") as f:
		token_db = pickle.load(f)

	while True:

		current_token_index = state_list.state_list[current_state].token_index

		# search all states and tokens
		if current_token_index == len(token_db) -1 and state_list.state_list[current_state].parent is None:
			break

		move_state_token =[]
		target_parent = state_list.state_list[current_state].parent
		target_state = current_state

		while True:
			current_parent = state_list.state_list[target_state].parent
			if current_parent is not None:
				move_state_token.append(state_list.state_list[target_state].token)
				target_state = current_parent
				continue
			else: # root node
				break
				
		move_state_token.reverse() # very important in dfs

		# Simple message format ( 1 word )
		for i in range(current_token_index, len(token_db)):
		# for token in token_db:
			state_list.state_list[current_state].token_index = i
			# print token_db[i]
			if token_db[i] == "quit":
				continue
			sport = sport + 1
			if sport > 60000:
				sport = 1000
				
			#Start with 3WHS
			rp = handshake_init(dst_ip, dport, sport)

			#If handshake finished, the server sends response. Send ack and get the last req packet info.
			ftp_ack = generate_ftp_ack(rp)
			skt.send(ftp_ack)

			for tk in move_state_token:
				temp = rp
				rp = send_receive_ftp(rp, tk)
				if rp == "error":
					print 'rp error when find state'

			# set state
			ftpmachine.set_state(str(current_state))

			temp_rp = rp
			# Send message and listen
			rp = send_receive_ftp(rp, token_db[i])
			unique_cnt = unique_cnt + 1

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
				print "[+] COUNT OF TRIALS : %d" % unique_cnt, "Time Elapsed :", elapsed_time, "s"
				graphname = "diagram/dfs_state" + str(unique_cnt) + ".png"
				ftpmachine.model.graph.draw(graphname, prog='dot')
				#img = mplotimg.imread("diagram/sample_state.png")
				#plt.imshow(img)
				#plt.show()

			# found a new state
			if state_found == 1:
				state_found = 0
				if depth_count == 2: # max depth
					continue
				else:
					depth_count = depth_count + 1
					current_state = num_of_states
					break

		if state_list.state_list[current_state].token_index == len(token_db)-1:
			# end for (token end)
			current_state = target_parent
			depth_count = depth_count - 1
			ftpmachine.set_state(str(current_state))

			if current_state is None:
				break
			

	elapsed_time = time.time() - g_start_time
	print "Total elapsed time : ", elapsed_time, "\n"
	# Program normally ends.
	ftpmachine.model.graph.draw("diagram/dfs_state_fin.png", prog='dot')
	logging.info(transition_info)
	img = mplotimg.imread("diagram/dfs_state_fin.png")
	plt.imshow(img)
	plt.show()
	sys.exit()

elif mode == 'p':
	# pruning
	with open("./tokenfile/total_tokens.txt") as f:
		token_db = pickle.load(f)

	while True:

		print 'send total tokens'

		if current_state > num_of_states:
			break
		
		move_state_token =[]
		target_state = current_state
		
		while True:
			current_parent = state_list.state_list[target_state].parent
			if current_parent is not None:
				move_state_token.append(state_list.state_list[target_state].token)
				target_state = current_parent
				continue
			else: # root node
				break
		
		move_state_token.reverse()

		is_pruning = 0

		# Simple message format ( 1 word )
		for token in token_db:
			if token == "quit":
				continue
			sport = sport + 1
			if sport > 60000:
				sport = 1000

			#Start with 3WHS
			logging.info("[+] MSG Send Trial : %d" % cnt)
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
			ftpmachine.set_state(str(current_state))
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


		prune_children = state_list.find_state(current_state).children
		temp_children = []

		print 'prune start in state ' + str(current_state)

		is_pruning = 1
		# pruning stage
		for child_numb in prune_children:
			prune_move_state_token =[]
			prune_current_state = child_numb
			prune_target_state = prune_current_state
			
			while True:
				prune_current_parent = state_list.state_list[prune_target_state].parent
				if prune_current_parent is not None:
					prune_move_state_token.append(state_list.state_list[prune_target_state].token)
					prune_target_state = prune_current_parent
					continue
				else: # root node
					break
			
			prune_move_state_token.reverse()
			prune_parent_child_dict = state_list.find_state(current_state).child_dict

			temp_prune_parent_child_dict_keys = prune_parent_child_dict.keys()
			# Simple message format ( 1 word )
			for token in temp_prune_parent_child_dict_keys:
				if token == "quit":
					continue
				sport = sport + 1
				if sport > 60000:
					sport = 1000

				#Start with 3WHS
				logging.info("[+] PRUNE MSG Send Trial : %d" % cnt)
				rp = handshake_init(dst_ip, dport, sport)

				#If handshake finished, the server sends response. Send ack and get the last req packet info.
				ftp_ack = generate_ftp_ack(rp)
				skt.send(ftp_ack)
				#logging.info("[+] [MAIN] AFTER SEND")

				for tk in prune_move_state_token:
					print tk + " prune move tokens "
					temp = rp
					rp = send_receive_ftp(rp, tk)
					if rp == "error":
						while True:
							print 'rp error when find state'
							rp = temp
							rp = send_receive_ftp(rp, tk)
							if rp == "error":
								continue
							else:
								break

				# set state
				ftpmachine.set_state(str(prune_current_state))
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


			prune_child_dict = state_list.find_state(child_numb).child_dict
			if cmp(prune_parent_child_dict, prune_child_dict) == 0: # same state, prune state
				temp_children.append(child_numb)
			else: # different state
				pass

		for temp_numb in temp_children:
			temp_state = state_list.find_state(temp_numb)
			if temp_state is not None:
				print str(temp_numb) + " / " + str(current_state)
				ftpmachine.add_transition(temp_state.token + " / " + str(prune_parent_child_dict.get(temp_state.token, None)), source = str(current_state), dest = str(current_state))

		for temp_numb in temp_children:
			temp_state = state_list.find_state(temp_numb)
			if temp_state is not None:
				print str(temp_numb) + " / " + str(current_state)
				# del ftpmachine.states[str(temp_numb)]
				ftpmachine.states.pop(str(temp_numb), None)
				state_list.remove_state(state_list.find_state(temp_numb))
				state_list.find_state(current_state).children.remove(temp_numb)
			# state_list.find_state(current_state).child_dict

		print 'move state'

		# move state
		curs = state_list.find_state(current_state)
		if curs.children is not []: # has some children
			if curs.next_child_idx < len(curs.children):
				tars = curs.children[curs.next_child_idx]
				curs.next_child_idx = curs.next_child_idx + 1
			else: # no child
				tars = curs.parent
				if tars == None: # no additional nodes
					break
				else:
					targets = state_list.find_state(tars)
					tars = targets.children[targets.next_child_idx]
					targets.next_child_idx = targets.next_child_idx + 1

			current_state = tars
			
		else: # no child
			tars = curs.parent
			if tars == None: # no additional nodes
				break
			else:
				targets = state_list.find_state(tars)
				tars = targets.children[targets.next_child_idx]
				targets.next_child_idx = targets.next_child_idx + 1

			current_state = tars
	
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
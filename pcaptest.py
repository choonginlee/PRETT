#!/usr/bin/python

import dpkt
import re
import glob
import pickle

def split_str():
	cmd_list_ftp = []
	cmd_list_smtp = []
	cnt_file = 0
	cnt_session_ftp = 0
	cnt_session_smtp = 0
	cnt_packet_ftp = 0
	cnt_packet_smtp = 0

	for file in glob.glob("./pcap/SMTP/*.pcap"):
		cnt_file = cnt_file + 1
		print file
		f = open(file, 'r')
		pp = dpkt.pcap.Reader(f)

		for ts, buf in pp:
			eth = dpkt.ethernet.Ethernet(buf)

			if not isinstance(eth.data, dpkt.ip.IP):
				continue

			ip = eth.data

			if isinstance(ip.data, dpkt.tcp.TCP):
				tcp = ip.data
				if tcp.dport == 21:
					msg = tcp.data
					if len(msg) > 0:
						# print len(msg)
						cnt_packet_ftp = cnt_packet_ftp + 1
						split_msg = re.split("\r\n| |", msg)
						cmd = split_msg[0]
						if cmd not in cmd_list_ftp:
							cmd_list_ftp.append(cmd)

				elif tcp.dport == 25:
					msg = tcp.data
					if len(msg) > 0:
						# print len(msg)
						cnt_packet_smtp = cnt_packet_smtp + 1
						split_msg = re.split("\r\n| |", msg)
						cmd = split_msg[0]
						if cmd not in cmd_list_smtp:
							cmd_list_smtp.append(cmd)

		#if cnt_file == 2:
		#	break
	
	print "[+] pcap parsing end."
	print "[+] Total pcap file : %d" % cnt_file
	print "Total ftp sessions : %d, Total ftp packets : %d" % (cnt_session_ftp, cnt_packet_ftp)
	print "Total ftp sessions : %d, Total smtp packets : %d" % (cnt_session_smtp, cnt_packet_smtp) 
	return cmd_list_ftp, cmd_list_smtp

def extract_session_ftp():

	cnt_file = 0
	cnt_packet_ftp = 0
	all_session = []
	tmp_session = []
	first_cmd = []

	sport_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	buf_sessions = [[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]]

	for file in glob.glob("./pcap/testing/*.pcap"):
		cnt_file = cnt_file + 1
		print
		print "====== ", file, "======"
		print

		f = open(file, 'rb')
		pp = dpkt.pcap.Reader(f)	

		for ts, buf in pp:
			try:
				eth = dpkt.ethernet.Ethernet(buf)

				if not isinstance(eth.data, dpkt.ip.IP):
					continue

				ip = eth.data

				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data
					if tcp.dport == 21:
						
							msg = tcp.data
							sport = tcp.sport
							if len(msg) > 0:
								split_msg = re.split("\r\n| |", msg)
								cmd = split_msg[0]
								session_index = 0
								for sp in sport_list:
									if sp == sport:
										break
									else:
										session_index = session_index + 1

								# if index is 5, no sport exist in sport_list
								if session_index == len(sport_list):
									for i in range(len(sport_list)):
										if len(buf_sessions[i]) == 0:
											session_index = i
											break

								sport_list[session_index] = sport
								buf_sessions[session_index].append(cmd)
								if cmd == "QUIT" or cmd == "quit":
									all_session.append(buf_sessions[session_index])
									#print sport_list, buf_sessions[session_index]
									buf_sessions[session_index] = []
									sport_list[session_index] = 0
									#print
									#tmp_session = []
			except dpkt.dpkt.NeedData:
				continue

			except NeedData:
				continue

		for i in range(len(sport_list)):
			if sport_list[i] != 0:
				print i, buf_sessions[i]
				all_session.append(buf_sessions[i])
				buf_sessions[i] = []
				sport_list[i] = 0

	for s in all_session:
		cnt_packet_ftp = cnt_packet_ftp + len(s)
		if s[0] not in first_cmd:
			first_cmd.append(s[0])

	print "[+] pcap parsing end."
	print "[+] Total pcap file : %d" % cnt_file
	print "Total ftp sessions : %d, Total ftp packets : %d" % (len(all_session), cnt_packet_ftp)
	# error session print
	for i in range(len(sport_list)):
		if sport_list[i] != 0:
			print i, buf_sessions[i]

	print first_cmd
	return all_session


def extract_session_smtp():

	cnt_file = 0
	cnt_packet_smtp = 0
	all_session = []
	tmp_session = []
	first_cmd = []

	sport_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	buf_sessions = [[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]]
	data_list = ['','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','']
	data_status = [False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False,False]

	for file in glob.glob("./pcap/SMTP/*.pcap"):
		cnt_file = cnt_file + 1
		print
		print "====== ", file, "======"
		print

		f = open(file, 'rb')
		pp = dpkt.pcap.Reader(f)	

		for ts, buf in pp:
			try:
				eth = dpkt.ethernet.Ethernet(buf)

				if not isinstance(eth.data, dpkt.ip.IP):
					continue

				ip = eth.data

				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data
					if tcp.dport == 25:
						
							msg = tcp.data
							sport = tcp.sport
							if len(msg) > 0:
								split_msg = re.split("\r\n| |", msg)
								cmd = split_msg[0]

								print cmd

								session_index = 0
								for sp in sport_list:
									if sp == sport:
										break
									else:
										session_index = session_index + 1

								# if index is 5, no sport exist in sport_list
								if session_index == len(sport_list):
									for i in range(len(sport_list)):
										if len(buf_sessions[i]) == 0:
											session_index = i
											break

								sport_list[session_index] = sport
								if cmd == "DATA" or cmd == "data":
									data_status[session_index] = True
									buf_sessions[session_index].append(cmd)
									continue
								elif cmd == "QUIT" or cmd == "quit":
									buf_sessions[session_index].append(data_list[session_index][0:10]+"...")
									buf_sessions[session_index].append(cmd)
									all_session.append(buf_sessions[session_index])
									buf_sessions[session_index] = []
									sport_list[session_index] = 0
									data_list[session_index] = ''
									data_status[session_index] = False
									print all_session[-1]
								else:
									if data_status[session_index] == True:
										data_list[session_index] = data_list[session_index] + cmd
									else:
										buf_sessions[session_index].append(cmd)
									continue

			except dpkt.dpkt.NeedData:
				continue

		for i in range(len(sport_list)):
			if sport_list[i] != 0:
				#print i, buf_sessions[i]
				all_session.append(buf_sessions[i])
				buf_sessions[i] = []
				sport_list[i] = 0

	for s in all_session:
		cnt_packet_smtp = cnt_packet_smtp + len(s)
		if len(s) == 0:
			continue
		if s[0] not in first_cmd:
			first_cmd.append(s[0])

	print "[+] pcap parsing end."
	print "[+] Total pcap file : %d" % cnt_file
	print "Total smtp sessions : %d, Total smtp packets : %d" % (len(all_session), cnt_packet_smtp)
	# error session print
	for i in range(len(sport_list)):
		if sport_list[i] != 0:
			print i, buf_sessions[i]

	print first_cmd
	return all_session

def extract_session_http():

	cnt_file = 0
	cnt_packet_ftp = 0
	all_session = []
	tmp_session = []
	first_cmd = []

	sport_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	buf_sessions = [[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]]

	for file in glob.glob("./pcap/testing/*.pcap"):
		cnt_file = cnt_file + 1
		print
		print "====== ", file, "======"
		print

		f = open(file, 'rb')
		pp = dpkt.pcap.Reader(f)	

		for ts, buf in pp:
			try:
				eth = dpkt.ethernet.Ethernet(buf)

				if not isinstance(eth.data, dpkt.ip.IP):
					continue

				ip = eth.data

				if isinstance(ip.data, dpkt.tcp.TCP):
					tcp = ip.data
					if tcp.dport == 80:
						
							msg = tcp.data
							sport = tcp.sport
							if len(msg) > 0:
								split_msg = re.split("\r\n| |", msg)
								cmd = split_msg[0]
								session_index = 0
								for sp in sport_list:
									if sp == sport:
										break
									else:
										session_index = session_index + 1

								# if index is 5, no sport exist in sport_list
								if session_index == len(sport_list):
									for i in range(len(sport_list)):
										if len(buf_sessions[i]) == 0:
											session_index = i
											break

								sport_list[session_index] = sport
								buf_sessions[session_index].append(cmd)
								if cmd == "QUIT" or cmd == "quit":
									all_session.append(buf_sessions[session_index])
									print sport_list, buf_sessions[session_index]
									buf_sessions[session_index] = []
									sport_list[session_index] = 0
									#print
									#tmp_session = []
			except dpkt.dpkt.NeedData:
				continue

		for i in range(len(sport_list)):
			if sport_list[i] != 0:
				#print i, buf_sessions[i]
				all_session.append(buf_sessions[i])
				buf_sessions[i] = []
				sport_list[i] = 0

	for s in all_session:
		cnt_packet_ftp = cnt_packet_ftp + len(s)
		if s[0] not in first_cmd:
			first_cmd.append(s[0])

	print "[+] pcap parsing end."
	print "[+] Total pcap file : %d" % cnt_file
	print "Total ftp sessions : %d, Total ftp packets : %d" % (len(all_session), cnt_packet_ftp)
	# error session print
	for i in range(len(sport_list)):
		if sport_list[i] != 0:
			print i, buf_sessions[i]

	print first_cmd
	return all_session


#ftp_cmds, smtp_cmds = split_str()

"""f2= open("./pcap/outside.pcap")
pp2 = dpkt.pcap.Reader(f2)
sessions = extract_session_smtp(pp2)"""


#ftp_sessions = extract_session_ftp()
#with open("ftp_sessions.txt", "wb") as fp:
#	pickle.dump(ftp_sessions, fp)


#smtp_sessions = extract_session_smtp()
#with open("smtp_sessions.txt", "wb") as fp:
#	pickle.dump(smtp_sessions, fp)

http_sessions = extract_session_http()
with open("http_sessions.txt", "wb") as fp:
	pickle.dump(http_sessions, fp)
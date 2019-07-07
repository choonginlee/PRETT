from collections import Counter
from itertools import izip
import sys
import re
import os
import argparse
import time
import pickle
import random
import glob
import dpkt

outputdir = './args'

ranklist = {}
cnt = 0
g_start_time = time.time()
#most_tokens = ['data', 'so', 'to', 'got', 'end', 'free', 'name', 'version', 'from', 'failed', 'set', 'hh', 'lib', 'main', 'init', 'fini', 'bss', 'dyn', 'ld', 'array']
#user_id = ['anonymous', 'test', 'root']
#ip_addr = ['127.0.0.1', '192.168.0.1', '10.0.0.1']
#file_path = ['/']
#urls = ['http://www.example.com', '/index.php', '/index.html']
#unknown = ['list', 'I', 'A', 'TLS']
rand_numb = []

total_cmd = []
total_arg = []


def check_cmd_args():

	cnt_file = 0
	cnt_packet_ftp = 0

	for file in glob.glob("./pcap/HTTP/*.pcap"):
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
					#if tcp.dport == 21:
					#if tcp.dport == 25:
					if tcp.dport == 80:
			
						msg = tcp.data
						cmd = ""
						arg = ""
						if len(msg) > 0:
							cnt_packet_ftp = cnt_packet_ftp + 1
							split_msg = re.split("\r\n| |", msg)
							cmd = split_msg[0]

							if len(split_msg) > 1: # has more than one arg
								for i in range(1, len(split_msg)-1):
									#print len(split_msg)
									#print split_msg
									if i == len(split_msg)-2:
										arg = arg + split_msg[i]
									else:
										#print i, len(split_msg)
										arg = arg + split_msg[i] + " "
								if arg not in total_arg:
									total_arg.append(arg)

							if cmd not in total_cmd:
								total_cmd.append(cmd)
						

			except dpkt.dpkt.NeedData:
				continue

			#except NeedData:
			#	continue

	print "[+] pcap parsing end."
	print "[+] Total pcap file : %d" % cnt_file
	print "[+] Total ftp packets : %d" %  cnt_packet_ftp
	print "[+] Total commands : %d " % len(total_cmd)
	print total_cmd
	print "[+} Total arguments : %d " % len(total_arg)
	for i in range(len(total_arg)):
		print total_arg[i]
		print


if __name__ == "__main__" :

	start_time = time.time()

	"""
	# rand int generate
	rand_numb.append(str(random.randint(0, 512)))
	rand_numb.append(str(random.randint(513, 65536)))
	rand_numb.append(str(random.randint(65537, 4294967296)))

	# for tok in most_tokens:
	# 	ranklist[tok] = r1
	
	for tok in user_id:
		ranklist[tok] = 1

	#for tok in ip_addr:
	#	ranklist[tok] = 1

	for tok in rand_numb:
		ranklist[tok] = 1

	for tok in file_path:
		ranklist[tok] = 1

	for tok in urls:
		ranklist[tok] = 1

	for tok in unknown:
		ranklist[tok] = 1
	



	print("[+] Plase check the \'args\' directory.")
	print("--- Total %s seconds ---" % (time.time() - start_time))

	# write total tokens in one file
	file_write_total = outputdir + "/all_args.txt"
	with open(file_write_total, "wb") as f:
		pickle.dump(ranklist, f)
	"""
	print 'total_time : ' + str(time.time()-g_start_time)

	check_cmd_args()
from collections import Counter
from itertools import izip
import sys
import re
import os
import argparse
import time
import pickle
import random

outputdir = './args'

ranklist = {}
cnt = 0
g_start_time = time.time()
most_tokens = ['data', 'so', 'to', 'got', 'end', 'free', 'name', 'version', 'from', 'failed',
'set', 'hh', 'lib', 'main', 'init', 'fini', 'bss', 'dyn', 'ld', 'array']
user_id = ['anonymous', 'test', 'root']
ip_addr = ['127.0.0.1', '192.168.0.1', '10.0.0.1']
file_path = ['/']
urls = ['http://www.example.com']
unknown = ['list', 'I', 'A', 'TLS']
rand_numb = []

if __name__ == "__main__" :

	start_time = time.time()

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
	
	print 'total_time : ' + str(time.time()-g_start_time)


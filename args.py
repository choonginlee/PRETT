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
exception_token = ['atuh', 'auati', 'avaui', 'atui', 'auatush', \
					'awavi', 'dh', 'awavauatush', 'hh', 'atush', \
					'ht', 'avati', 'xdh', 'llc', 'awavauati', \
					'uauh' ]
ranklist = {}
cnt = 0
g_start_time = time.time()
most_tokens = ['data', 'so', 'to', 'got', 'end', 'free', 'name', 'version', 'from', 'failed',
'set', 'hh', 'lib', 'main', 'init', 'fini', 'bss', 'dyn', 'ld', 'array']
user_id = ['user', 'admin', 'root', 'guest', 'anonymous']
ip_addr = ['127.0.0.1', '192.168.0.1', '192.168.10.1']
rand_numb = []


def count_token(file) :
	global ranklist
	global cnt
	cnt = cnt + 1
	words = []
	res_file = open(file, 'r')
	for line in res_file.readlines():
		words.append(line.replace('\n', ''))

	tempdic = dict((k,1) for k in words)
	ranklist = Counter(ranklist) + Counter(tempdic)
	print "======== [", cnt, "] Token analysis of file", file, "done.", "========="


def extract_token(path, file) :
	
	file_name, file_ext = os.path.splitext(file)
	file_write = outputdir + "/" + file_name + "_tokens.txt"
	file_read = os.path.join(path, file)

	fr = open(file_read, 'r')
	fw = open(file_write, 'w')

	result = []
	result_first = []
	
	while True :
		string_read = fr.readline()
		if not string_read: break # eol
		
		split_list = []
		split_list = string_read.split()
		for split in split_list:
			result_first = re.findall('^(/.*/)?(?:$|(.+?)(?:(\.[^.]*$)|$))', split)
			for res in result_first:
				if res[0] != '':
					final = res[0] + res[1] + res[2]
					temp_final = final
					final_filter = re.search('[<>,:;]', temp_final)
					if final_filter == None:
						result.append(final)
		

	for res in result:
		fw.write(str(res) + '\n')
		
	result = []
	result_first = []
	url_re = '(http|https):\/\/(([\xA1-\xFEa-z0-9_\-]+\.[\xA1-\xFEa-z0-9:;&#@=_~%\?\/\.\,\+\-]+))'

	while True:
		string_read = fr.readline()
		if not string_read: break #eol

		split_list = []
		split_list = re.split('[<>]', string_read)
		for split in split_list:
			result_first = re.findall(url_re, split)
			for res in result_first:
				result.append(res)
				print res

	for res in result:
		fw.write(str(res) + '\n')
	#fw.write((str(set(result))))

	fw.close()
	
	count_token(file_write)


def extract_token_dir(dir) :

	if not os.path.exists(outputdir) :
		os.makedirs(outputdir)

	for root, dirs, files in os.walk(dir):
		for file in files:
			extract_token(root, file)

if __name__ == "__main__" :

	start_time = time.time()

	parser = argparse.ArgumentParser(description = "Extract meaningful tokens from text messages of re-engeered binary.")
	parser.add_argument("target", help="Extract tokens from the binary specified")
	#parser.add_argument("-d", "--directory", help="Extract tokens from binaries in the specified folder")
	args = parser.parse_args()
	inputpath = args.target

	if os.path.isdir(inputpath) :
		extract_token_dir(inputpath)
		print "[+] Jobs Done. (Directory specified)"

	elif os.path.isfile(inputpath) :
		root = os.path.dirname(os.path.abspath(inputpath))
		extract_token(root, inputpath)
		print "[+] Jobs Done. (Single file specified)"

	else :
		print "[-] Nothing to be done."
		sys.exit()

	# rand int generate
	rand_numb.append(str(random.randint(0, 512)))
	rand_numb.append(str(random.randint(513, 65536)))
	rand_numb.append(str(random.randint(65537, 4294967296)))

	for tok in most_tokens:
		ranklist[tok] = ranklist[tok] + 1

	for tok in user_id:
		ranklist[tok] = ranklist[tok] + 1

	for tok in ip_addr:
		ranklist[tok] = ranklist[tok] + 1

	for tok in rand_numb:
		ranklist[tok] = ranklist[tok] + 1


	print("[+] Plase check the \'args\' directory.")
	print("--- Total %s seconds ---" % (time.time() - start_time))

	# write total tokens in one file
	file_write_total = outputdir + "/all_tokens.txt"
	with open(file_write_total, "wb") as f:
		pickle.dump(ranklist.most_common(), f)
	
	print "[+] total unique tokens :", len(ranklist.most_common())
	print 'total_time : ' + str(time.time()-g_start_time)


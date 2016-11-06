from collections import Counter
from itertools import izip
import sys
import re
import os
import argparse
import time
import pickle

outputdir = './tokenfile'
exception_token = ['atuh', 'auati', 'avaui', 'atui', 'auatush', \
					'awavi', 'dh', 'awavauatush', 'hh', 'atush', \
					'ht', 'avati', 'xdh', 'llc', 'awavauati', \
					'uauh' ]
ranklist = {}
cnt = 0

def count_token(file) :
	global ranklist
	global cnt
	cnt = cnt + 1
	words = re.findall(r'\w+', open(file).read().lower())
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
		split_list = re.split('[:.-/_\s]+', string_read)
		for split in split_list:
			result_first = re.findall('[A-Za-z]{2,}', split)
			for res in result_first:
				result.append(res)

	fw.write((str(set(result))))

	fw.close

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

	print("[+] Plase check the \'tokenfile\' directory.")
	print("--- Total %s seconds ---" % (time.time() - start_time))

	# write total tokens in one file
	file_write_total = outputdir + "/total_tokens.txt"
	with open(file_write_total, "wb") as f:
		pickle.dump(ranklist.most_common(), f)


	print "[+] total unique tokens :", len(ranklist.most_common())





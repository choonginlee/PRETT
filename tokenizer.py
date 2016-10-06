from collections import Counter
from itertools import izip
import sys
import re
import os
import argparse
import time

outputdir = '../tokenfile'
exception_token = ['atuh', 'auati', 'avaui', 'atui', 'auatush', \
					'awavi', 'dh', 'awavauatush', 'hh', 'atush', \
					'ht', 'avati', 'xdh', 'llc', 'awavauati', \
					'uauh' ]
ranklist = {}

def count_token(file) :
	global ranklist
	words = re.findall(r'\w+', open(file).read().lower())
	tempdic = dict((k,1) for k in words)
	#c = Counter(tempdic).most_common()
	#print c 
	ranklist = Counter(ranklist) + Counter(tempdic)
	print "======== Token analysis of file", file, "done.", "========="

def extract_token(path, file) :

	file_name, file_ext = os.path.splitext(file)
	file_write = outputdir + "/" + file_name + "_tokens.txt"
	file_read = os.path.join(path, file)

	fr = open(file_read, 'r')
	fw = open(file_write, 'w')

	#fr_lines = sum(1 for line in fr) # line no of the file read 

	result = []
	result_first = []

	while True :
		string_read = fr.readline()
		if not string_read: break # eol
		if(re.search('\w[_]\w', string_read)): # underbar: func or val
			continue
		if(re.search('\w[/]\w', string_read)): # slash: path
			continue # file path
		if(re.search('\w[.]\w', string_read)): # dot : path
			continue # file zpath

		"""		result = re.findall('[a-zA-Z]{2,}', string_read)
		for extoken in exception_token :
			for token in result :
				if extoken == token.lower():
					result.remove(token)

		if result : # ignore empty string
			#fw.write(str(result)+'\n')
			result_first.append(result[0])
		"""
		result = re.findall('[a-zA-Z]{2,}', string_read)
		if result :
			for extoken in exception_token :
				if extoken == result[0].lower() :
					result.remove(result[0])
					break

		if result :
			result_first.append(result[0].lower()) #insert first element

	fw.write((str(set(result_first))))

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

	print("[+] Plase check the \'tokenfile\' directory.")
	print("--- Total %s seconds ---" % (time.time() - start_time))

	print "[+] total unique tokens :", len(ranklist.most_common())
	for k in ranklist.most_common() :
		print k

	"""
	cnt = 0
	printlist = []

	for k in ranklist.most_common():
		if cnt % 5 == 4 :
			index = cnt - 4
			print printlist[index:]
			cnt = cnt + 1
		else :
			printlist.append(k)
			cnt = cnt + 1
	"""





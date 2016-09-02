from collections import Counter
import sys
import re
import os
import argparse
import time

outputdir = '../tokenfile'
exception_token = ['atuh', 'auati', 'avaui', 'atui', 'auatush', \
					'awavi', 'dh', 'awavauatush', 'hh', 'atush', \
					'ht', 'avati', 'xdh', 'llc', 'awavauati']

def count_token(file) :
	words = re.findall(r'\w+', open(file).read().lower())
	c = Counter(words).most_common(10)
	print "======== Token Analysis of file", file, "========="
	print c[0:5]
	print c[5:10]
	print

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

		result = re.findall('[a-zA-Z]{2,}', string_read)
		for extoken in exception_token :
			for token in result :
				if extoken == token.lower():
					result.remove(token)

		if result : # ignore empty string
			#fw.write(str(result)+'\n')
			result_first.append(result[0]) #insert first element

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
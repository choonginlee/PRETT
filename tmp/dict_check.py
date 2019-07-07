import urllib
import BeautifulSoup
import pickle
import time


abbreviation_url = "http://www.abbreviations.com/"
g_start_time = time.time()

if __name__ == "__main__":

	result = []
	cnt = 0
	abbre_count = 0
	def_count = 0

	with open("./tokenfile/all_tokens.txt") as f:
		token_db = pickle.load(f)

	for tk in token_db:

		if cnt % 100 == 0:
			elapsed_time = time.time() - g_start_time
			with open("./tokenfile/dict_token/total_" + str(cnt) + "_tokens.txt", "wb") as f:
				pickle.dump(result, f)
			print str(cnt) + ' count time : ' + str(elapsed_time)
		
		print 'current ' + str(cnt+1) + ', ' + str(len(token_db) - (cnt+1)) + ' left'
		try:

			data = urllib.urlopen(abbreviation_url + tk[0])
			soup = BeautifulSoup.BeautifulSoup(data)

		except:
			time.sleep(1.21)
			data = urllib.urlopen(abbreviation_url + tk[0])
			soup = BeautifulSoup.BeautifulSoup(data)

		cnt = cnt + 1

		no_items = soup.findAll('div', attrs={'class' : 'no-items rc5 row'})
		if len(no_items) == 0:
			result.append(tk[0])
			abbre_count = abbre_count + 1
			print 'abbre/' + tk[0]
		else:
			defs_row = soup.findAll('div', attrs={'class' : 'defs row'})
			if len(defs_row) == 0:
				continue
			else:
				result.append(tk[0])
				def_count = def_count + 1
				print 'def/' + tk[0]

	with open("./tokenfile/dict_token/total_tokens.txt", "wb") as f:
		pickle.dump(result, f)

	print 'total_time : ' + str(time.time() - g_start_time)
	print 'abbre : ' + str(abbre_count)
	print 'def : ' + str(def_count)
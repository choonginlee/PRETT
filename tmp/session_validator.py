import pickle

current_state = 0
is_valid = True
true_count = 0
false_count = 0

ftp_dict_prete = {0:{'user': 1, 'opts': 0, 'pass': 0, 'retr': 0, 'rest': 0, 'noop': 0, 'port': 0, 'cwd': 0, 'size': 0, 'type': 0,
				'pwd': 0, 'acct': 0, 'stat': 0, 'syst': 0, 'prot': 0, 'quit': 4},
			1:{'user': 1, 'opts': 1, 'pass': 2, 'retr': 1, 'size': 1, 'type': 1, 'syst': 1, 'quit': 4, 'get': 5},
			2:{'quit': 4, 'user': 2, 'opts': 2, 'pass': 2, 'retr': 2, 'rest': 2, 'noop': 2, 'port': 2, 'cwd': 2, 'size': 2, 'type': 2,
				'mode': 2, 'pwd': 2, 'acct': 2, 'stat': 2, 'syst': 2, 'prot': 2, 'help': 2, 'list': 2, 'nlst': 2, 'stor': 2, 'pasv': 3, 'get': 5},
			3:{'quit': 4, 'user': 3, 'opts': 3, 'pass': 3, 'retr': 3, 'rest': 3, 'noop': 3, 'cwd': 3, 'size': 3, 'type': 3,
				'mode': 3, 'pwd': 3, 'acct': 3, 'stat': 3, 'syst': 3, 'prot': 3, 'help': 3, 'list': 3, 'nlst': 3, 'stor': 3, 'pasv': 3, 'port': 2, 'get': 5}}

http_dict_prete = {0:{'get': 0, 'post': 0, 'put': 0, 'delete': 0, 'options': 0, 'connect': 0, 'head': 0, 'trace': 0}}

smtp_dict_prete = {0:{'data': 0, 'ehlo': 0, 'helo': 0, 'rcpt': 0, 'auth': 0, 'mail': 1, 'rset': 0, 'vrfy': 0, 'get': 4, 'quit': 5},
			 1:{'data': 1, 'ehlo': 0, 'helo': 0, 'rcpt': 2, 'auth': 1, 'mail': 1, 'rset': 1, 'vrfy': 0, 'get': 4, 'quit': 5},
			 2:{'data': 3, 'ehlo': 0, 'helo': 0, 'rcpt': 2, 'auth': 2, 'mail': 2, 'vrfy': 2, 'rset': 0, 'get': 4, 'quit': 5},
			 3:{'go_to_the_state_2'}}

smtp_dict_cho = {0:{'elho': 1, 'helo': 1, 'quit': 2},
				1:{'mail': 3, 'helo': 0, 'ehlo': 0, 'rset': 0},
				3:{'quit': 2, 'rcpt': 4},
				4:{'helo': 1, 'helo': 1, 'rset': 1, 'quit': 2, 'data': 5},
				5:{'go_to_the_state_2'}}

# return True or False
# if a session is valid, return True
# else, return False
def validate_ftp_session(session, ftp_dict):

	global is_valid
	global current_state

	for cmd in session:
		# states ends, but commands are not over yet
		if current_state not in ftp_dict:
			is_valid = False
			break

		# lowercase
		if cmd.lower() not in ftp_dict[current_state]:
			is_valid = False
			print cmd, current_state
			break
		else:
			current_state = ftp_dict[current_state][cmd.lower()]
			continue

	current_state = 0
	return is_valid


def validate_http_session(session):

	global current_state
	global http_dict_prete

	for cmd in session:
		
		# lowercase
		if cmd.lower() not in http_dict_prete[current_state]:
			is_valid = False
			break
		else:
			current_state = http_dict_prete[current_state][cmd.lower()]
			continue

	current_state = 0
	return is_valid


def validate_smtp_session(session, smtp_dict):

	global is_valid
	global current_state

	for cmd in session:
		# states ends, but commands are not over yet
		if current_state not in smtp_dict:
			is_valid = False
			break

		if current_state == 3:
			current_state = 2
			continue
			
		# lowercase
		if cmd.lower() not in smtp_dict[current_state]:
			is_valid = False
			break
		else:
			current_state = smtp_dict[current_state][cmd.lower()]
			continue

	current_state = 0
	return is_valid

def validate_smtp_session_cho(session, smtp_dict):

	global is_valid
	global current_state

	for cmd in session:
		if current_state == 2:
			is_valid = True
			break
			
		# states ends, but commands are not over yet
		if current_state not in smtp_dict:
			is_valid = False
			break

		if current_state == 5:
			current_state = 2
			continue
			
		# lowercase
		if cmd.lower() not in smtp_dict[current_state]:
			is_valid = False
			break
		else:
			current_state = smtp_dict[current_state][cmd.lower()]
			continue

	current_state = 0
	return is_valid

if __name__ == "__main__":
	#use your protocol type, and command list
		
	f = open("ftp_sessions.txt")
	ftp_sessions = pickle.load(f)
	cnt = 0
	for s in ftp_sessions:
		res = validate_ftp_session(s, ftp_dict_prete)
		if res == False:
			is_valid = True
			print cnt, s
			cnt += 1

	print cnt, "/", len(ftp_sessions)
	

	f = open("smtp_sessions.txt")
	smtp_sessions = pickle.load(f)

	cnt = 0
	for s in smtp_sessions:
		res = validate_smtp_session(s, smtp_dict_prete)
		if res == False:
			is_valid = True
			#ssprint cnt, s
			cnt += 1

	print cnt, "/", len(smtp_sessions)

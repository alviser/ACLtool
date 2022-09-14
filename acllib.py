import ipaddress
import socket				# used for port name-to-number translation

def consumePort(tokens):
	if len(tokens) == 0:
		return (tokens,{'start-port': 'any','end-port': 'any','plain-string':'none'})

	base = tokens[0].strip()

	if base == "eq":
		sp = tokens[1].strip()
		if not sp.isnumeric():
			sp = socket.getservbyname(sp)
		else:
			sp = int(sp)

		return (tokens[2:],{'start-port':sp,'end-port':sp,'plain-string':'none'})
	elif base == "gt":
		sp = tokens[1].strip()
		if not sp.isnumeric():
			sp = socket.getservbyname(sp)
		else:
			sp = int(sp)

		return (tokens[2:],{'start-port':sp,'end-port': 65535,'plain-string':'none'})
	elif base == "range":
		sp = tokens[1].strip()
		if not sp.isnumeric():
			sp = socket.getservbyname(sp)
		else:
			sp = int(sp)

		ep = tokens[2].strip()
		if not ep.isnumeric():
			ep = socket.getservbyname(ep)
		else:
			ep = int(ep)

		return (tokens[3:],{'start-port':sp,'end-port':ep,'plain-string':'none'})
	elif base in ["redirect","echo","echo-reply","unreachable","established"]:
		return(tokens[1:],{'start-port':'none','end-port':'none','plain-string':base})
	else:
		return(tokens,{'start-port': 'any','end-port': 'any','plain-string':'none'})

def consumeNXSAddress(tokens):
	base = tokens[0].strip()

	if base == "any":
		source	= ipaddress.ip_network(u'0.0.0.0/0')
		(rest,port) = consumePort(tokens[1:])

		return (rest,{'address': source, 'start-port': port['start-port'], 'end-port': port['end-port'], 'plain-string':port['plain-string']})
	
	else:
		source	= ipaddress.ip_network(u''+base)
		(rest,port) = consumePort(tokens[1:])

		return (rest,{'address': source, 'start-port': port['start-port'], 'end-port': port['end-port'], 'plain-string':port['plain-string']})

def consumeIOSAddress(tokens):
	base = tokens[0].strip()

	if base == "any":
		source	= ipaddress.ip_network(u'0.0.0.0/0')
		(rest,port) = consumePort(tokens[1:])

		return (rest,{'address': source, 'start-port': port['start-port'], 'end-port': port['end-port'], 'plain-string':port['plain-string']})
	
	elif base == "host":
		source	= ipaddress.ip_network(u''+tokens[1].strip()+'/32')
		(rest,port) = consumePort(tokens[2:])

		return (rest,{'address': source, 'start-port': port['start-port'], 'end-port': port['end-port'], 'plain-string':port['plain-string']})

	else:
		source	= ipaddress.ip_network(u''+tokens[0].strip()+'/'+tokens[1].strip())
		(rest,port) = consumePort(tokens[2:])

		return (rest,{'address': source, 'start-port': port['start-port'], 'end-port': port['end-port'], 'plain-string':port['plain-string']})

def parseACLFile(f,acl_type="ios"):
	acl = []

	fp = open(f,"r")
	# print("> " + acl['file'])
	for line in fp.readlines():
		token	= line.replace("\t"," ").split(" ")			# handles tabs as spaces
		token	= [item for item in token if item != ''] 	# remove empty tokens
		policy 	= {}
		# let's skip comment lines
		if token[0].strip().lower() in ["deny","permit"]:
			try:
				policy['action']	= token[0]
				policy['protocol']	= token[1]
				if acl_type == "ios":
					(rest,policy['source']) = consumeIOSAddress(token[2:])
					(rest,policy['destination']) = consumeIOSAddress(rest)
				else:
					(rest,policy['source']) = consumeNXSAddress(token[2:])
					(rest,policy['destination']) = consumeNXSAddress(rest)
			except Exception as e:					# this should be thrown only on special cisco masks, that we should handle
				policy['action']	= "invalid"
				policy['message']	= str(e)
				policy['line']		= line

			acl.append(policy)
		else:
			acl.append({'action': "raw", 'line': line})

	fp.close()
	return acl

def ACL2Text(acl,lang="ios"):
	problems 	= []
	text 		= []
	line_num 	= 0

	for line in acl:
		line_num += 1

		if line['action'] == "raw":
			text.append(line['line'].strip())
			continue	# skip to the next line

		try:
			line_to_text = []
			line_to_text.append(line['action'])
			line_to_text.append(line['protocol'])
			
			if lang == "ios":
				if (str(line['source']['address']) == "0.0.0.0/0"):
					line_to_text.append("any")
				else:
					if line['source']['address'].num_addresses == 1:
						line_to_text.append("host " + str(line['source']['address']).split("/")[0])
					else:
						line_to_text.append(str(line['source']['address'].with_hostmask).replace("/"," "))
			else:
				if (str(line['source']['address']) == "0.0.0.0/0"):
					line_to_text.append("any")
				else:
					line_to_text.append(str(line['source']['address']))

			if (str(line['source']['start-port']) not in ["any","none"]):
				if (line['source']['start-port'] != line['source']['end-port']):
					line_to_text.append("range")
					line_to_text.append(str(line['source']['start-port']))
					line_to_text.append(str(line['source']['end-port']))
				else:
					line_to_text.append("eq")
					line_to_text.append(str(line['source']['start-port']))
			elif (str(line['source']['start-port']) == "none"):
				line_to_text.append(line['source']['plain-string'])
			
			if lang == "ios":
				if (str(line['destination']['address']) == "0.0.0.0/0"):
					line_to_text.append("any")
				else:
					if line['destination']['address'].num_addresses == 1:
						line_to_text.append("host " + str(line['destination']['address']).split("/")[0])
					else:
						line_to_text.append(str(line['destination']['address'].with_hostmask).replace("/"," "))
			else:
				if (str(line['destination']['address']) == "0.0.0.0/0"):
					line_to_text.append("any")
				else:
					line_to_text.append(str(line['destination']['address']))

			if (str(line['destination']['start-port']) not in ["any","none"]):
				if (line['destination']['start-port'] != line['destination']['end-port']):
					line_to_text.append("range")
					line_to_text.append(str(line['destination']['start-port']))
					line_to_text.append(str(line['destination']['end-port']))
				else:
					line_to_text.append("eq")
					line_to_text.append(str(line['destination']['start-port']))
			elif (str(line['destination']['start-port']) == "none"):
				line_to_text.append(line['destination']['plain-string'])


			text.append(" ".join(line_to_text))
		except:
			text.append("INVALID: " + line['line'].rstrip("\n") + "(" + line['message'] + ")")
			problems.append({'linenum':line_num,'linetext':str(line)})
	return (text,problems)

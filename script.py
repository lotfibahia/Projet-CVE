#! /bin/usr/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *


class HTTPrequest(Packet):
  name = "HTTP Request"
	http_methods = "^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"
	fields_desc=[StrField("Method", None, fmt="H"),StrField("UserAgent", None, fmt="H")]


	def do_dissect(self, s):
		fields_rfc = ["Method",  "User-Agent"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				if(g=="Method"):
					prog=re.compile(self.http_methods)
				else:
					prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return '\r\n'+"".join(a)


class HTTPresponse(Packet):
	name = "HTTP Response"
	fields_desc=[StrField("Server", None, fmt="H")]

	def do_dissect(self, s):
		fields_rfc = ["Server"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				if(g=="Status-Line"):
					prog=re.compile("^HTTP/((0\.9)|(1\.0)|(1\.1))\ [0-9]{3}.*")
				else:
					prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return '\r\n'+"".join(a)


class HTTP(Packet):
	name="HTTP"
	fields_desc = [StrField("Connection", None, fmt="H")]

	def do_dissect(self, s):
		fields_rfc = ["Connection"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return "\r\n".join(a)
	
	def guess_payload_class(self, payload):
		prog=re.compile("^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)")
		result=prog.search(payload)
		if result:
			return HTTPrequest
		else:
			prog=re.compile("^HTTP/((0\.9)|(1\.0)|(1\.1))\ [0-9]{3}.*")
			result=prog.search(payload)
			if result:
				return HTTPresponse
		return Packet.guess_payload_class(self, payload)


bind_layers(TCP, HTTP)

packet=rdpcap("capture.pcap")



ip=[]


for p in packet.filter(lambda(s): HTTPrequest in s or HTTPresponse in s):

	if p[4].name == "HTTP Request" :

		if p[1].src +'|'+p.UserAgent[:-1] not in ip :

			ip.append( p[1].src +'|'+p.UserAgent[:-1])
	elif p[4].name == "HTTP Response" : 
		if p.Server is None:
			if p[1].src+ '|' not in ip :
				ip.append( p[1].src+ '|')
		else :
			if p[1].src+'|'+p.Server[:-1] not in ip :
				ip.append(p[1].src+'|'+p.Server[:-1])

for case in ip:

	print case


	
	

#!/usr/bin/python3	
import sys, re

NAMESERVER = '8.8.4.4'

#from scapy.all import *
from scapy.all import DNS, DNSQR, IP, UDP, sr1, conf, L3RawSocket

# check for missing arg, valid domain name, => root perms
if len(sys.argv) <= 1:
	use1 = "Usage: sudo python3 dns_query.py <domain_name>\n"
	use2 = "       sudo python3 dns_query.py <domain_name> [<rec_type(A|NS|MX|SOA|ALL)>]"
	exit(use1 + use2)
domain = sys.argv[1]

validdomain = re.compile('^[a-z]\w*(?:\.\w{2,})+$')
validarg2	= re.compile('A|ALL|MX|SOA|NS')

# need to test for valid domain name here 
# (or whatever is being tested for here, LOL)
if validdomain.match(sys.argv[1]) == None:
	exit("Sorry, \"{}\" is not a valid domain name".format(domain))

# test for 2nd arg, what type result
if len(sys.argv) > 2 and validarg2.match(sys.argv[2])==None:
	info = "is not a valid option. Please choose A, NS, or ALL"
	exit("Sorry, \"{}\" {}".format(sys.argv[2], info))
    
# configure raw sockets
conf.L3socket
conf.L3socket=L3RawSocket

# finally ready to start DNS query
i = IP(dst=NAMESERVER)
u = UDP(dport=53)

# what result did the user ask for?
if len(sys.argv) > 2:
	rec = sys.argv[2]

	if rec == 'A' or rec == 'NS':
		resp = sr1(i/u/DNS(rd=1, qd=DNSQR(qname=domain, qtype='A')))
	else:
		resp = sr1(i/u/DNS(rd=1, qd=DNSQR(qname=domain)))

	# print results
	if rec == 'A':
		print("DNS lookup results for {}:\n".format(domain))
		print(resp.an.display())		# print full A rec
	elif rec == 'NS':
		# To Do: check resp.nscount then loop thru and print NS entries
		print("{} Nameservers found for {}:\n".format(resp.nscount, domain))
		print(resp.ns.display())
	elif rec == 'ALL' or rec == 'all':
		#print(resp.getlayer(DNS).display())
		print(resp.display())
else: 	
	resp = sr1(i/u/DNS(rd=1, qd=DNSQR(qname=domain)))
	#print(resp.summary())	# pretty response
	print("IP address for {}: {}".format(domain, resp.an.rdata))



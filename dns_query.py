#!/usr/bin/env python3	
import sys, re
from scapy.all import DNS, DNSQR, IP, UDP, sr1, conf, L3RawSocket

NAMESERVER = sys.argv[3] if len(sys.argv) > 3 else '1.1.1.1'

# check for missing arg, valid domain name
if len(sys.argv) <= 1:
	use1 = "Usage: sudo python3 dns_query.py <domain_name>\n"
	use2 = "       sudo python3 dns_query.py <domain_name> [<rec_type(A|NS|ALL)>]\n"
	use3 = "       sudo python3 dns_query.py <domain_name> A [<nameserver>]"
	exit(use1 + use2 + use3)

# test for valid domain name here 
domain = sys.argv[1]
validdomain = re.compile('^[a-z]\w*(?:\.\w{2,})+$')
if validdomain.match(sys.argv[1]) == None:
	exit("Sorry, \"{}\" is not a valid domain name".format(domain))

# test for 2nd arg, what type result
validarg2 = re.compile('A|ALL|MX|SOA|NS')
if len(sys.argv) > 2 and validarg2.match(sys.argv[2])==None:
	info = "is not a valid option. Please choose A, NS or ALL"
	exit("Sorry, \"{}\" {}".format(sys.argv[2], info))
    
# finally ready to start DNS query
conf.L3socket
conf.L3socket=L3RawSocket

i = IP(dst=NAMESERVER)
u = UDP(dport=53)
resp = sr1(i/u/DNS(rd=1, qd=DNSQR(qname=domain, qtype='A')), verbose=0)

# what result did the user ask for?
if len(sys.argv) > 2:

	if sys.argv[2] == 'A':
		print("Nameserver: {}".format(NAMESERVER))
		print("Name:       {}".format(domain))
		print("Address:    {}".format(resp.an.rdata))

	elif sys.argv[2] == 'NS':
		print("{} Nameservers found for {}:".format(resp.nscount, domain))
		for n in range(0,resp.nscount):
			print(resp.ns[n].rdata.decode('utf-8'))

	elif sys.argv[2] == 'ALL':
		#print(resp.getlayer(DNS).display())
		print(resp.display())
else: 	
	resp = sr1(i/u/DNS(rd=1, qd=DNSQR(qname=domain)), verbose=0)
	#print(resp.summary())	# pretty response
	print("Name:    {}".format(domain))
	print("Address: {}".format(resp.an.rdata))


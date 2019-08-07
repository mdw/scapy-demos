#!/usr/bin/env python3	
import sys, re
from scapy.all import DNS, DNSQR, IP, UDP, sr1, conf, L3RawSocket

# for some reason I'm not getting NS recs reliably from 1.1.1.1
domain		= sys.argv[1] if len(sys.argv) > 1 else 'example.com'
rectype		= sys.argv[2] if len(sys.argv) > 2 else 'A'
NAMESERVER	= sys.argv[3] if len(sys.argv) > 3 else '8.8.4.4'

conf.L3socket
conf.L3socket=L3RawSocket

i = IP(dst=NAMESERVER)
u = UDP(dport=53)

def check_args():
	# check for missing arg, valid domain name, result type
	validdomain = re.compile('^(?:[A-z]\w*\.)+[A-z]{2,}$')
	validarg2 = re.compile('A|ALL|NS')
	if len(sys.argv) <= 1:
		use1 = "Usage: sudo python3 dns_query.py <domain_name>\n"
		use2 = "       sudo python3 dns_query.py <domain_name> [<rec_type(A|NS|ALL)>]\n"
		use3 = "       sudo python3 dns_query.py <domain_name> A [<nameserver>]"
		exit(use1 + use2 + use3)
	if validdomain.match(domain) == None:
		exit("Sorry, \"{}\" is not a valid domain name".format(domain))
	if len(sys.argv) > 2 and validarg2.match(rectype)==None:
		info = "is not a valid option. Please choose A, NS or ALL"
		exit("Sorry, \"{}\" {}".format(sys.argv[2], info))

def main():
	# what result did the user ask for?
	if len(sys.argv) > 2:
		resp = sr1(i/u/DNS(rd=1, qd=DNSQR(qname=domain, qtype='A')), verbose=0)
		if resp.an == None:
			exit("{} was not found".format(domain))
		if rectype == 'A':
			print("Nameserver: {}".format(NAMESERVER))
			print("Name:       {}".format(domain))
			print("Address:    {}".format(resp.an.rdata))
		elif rectype == 'NS':
			print("{} Nameservers found for {}:".format(resp.nscount, domain))
			for n in range(0,resp.nscount):
				print(resp.ns[n].rdata.decode('utf-8'))
		elif rectype == 'ALL':
			#print(resp.getlayer(DNS).display())
			print(resp.display())
	else: 	
		resp = sr1(i/u/DNS(rd=1, qd=DNSQR(qname=domain)), verbose=0)
		#print(resp.summary())	# pretty response
		print("Name:    {}".format(domain))
		print("Address: {}".format(resp.an.rdata))

if __name__ == "__main__":
	check_args()
	main()


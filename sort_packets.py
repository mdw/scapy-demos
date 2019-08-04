#!/usr/bin/python3 

import sys
from scapy.all import *

if len(sys.argv) <= 1:
	use1 = "python3 sort_packets.py <pcap_file>"
	use2 = "       python3 sort_packets.py <pcap_file>"
	exit("Usage: {}\n{}".format(use1, use2))
    
pcap = rdpcap(sys.argv[1])

# using haslayer(), getlayer() to identify all Ethernet/IP/* packets
for p in pcap:
	if p.haslayer(Ether):
		srcmac = p.getlayer(Ether).src
		dstmac = p.getlayer(Ether).dst
		print("\nSource MAC address: {}, dest MAC: {}".format(srcmac, dstmac))

		if p.haslayer(IP):
			print("IP source: {}, dest: {}".format(p.getlayer(IP).src, p.getlayer(IP).dst))
	
			if p.haslayer(TCP):
				sp = p.getlayer(TCP).sport
				dp = p.getlayer(TCP).dport
				flags = p.getlayer(TCP).flags
				print("TCP packet - source port: {}, dest port: {}, flags: {}".format(sp,dp,flags))
			elif p.haslayer(UDP):
				sp = p.getlayer(UDP).sport
				dp = p.getlayer(UDP).dport
				print("UDP packet - source port: {}, dest port: {}".format(sp, dp))

			# let's write the type as string instead of the number
			elif p.haslayer(ICMP):
				if p.getlayer(ICMP).type == 0:
					icmptype = "echo-reply"
				elif p.getlayer(ICMP).type == 3:
					icmptype = "destination unreachable"
				elif p.getlayer(ICMP).type == 5:
					icmptype = "redirect message"
				elif p.getlayer(ICMP).type == 8:
					icmptype = "echo-request"
				elif p.getlayer(ICMP).type == 9:
					icmptype = "router advertisement"
				elif p.getlayer(ICMP).type == 10:
					icmptype = "router solicitation"
				elif p.getlayer(ICMP).type == 11:
					icmptype = "time exceeded"
				elif p.getlayer(ICMP).type == 12:
					icmptype = "bad IP header"
				elif p.getlayer(ICMP).type == 13:
					icmptype = "timestamp"
				elif p.getlayer(ICMP).type == 14:
					icmptype = "timestamp reply"
				else:
					icmptype = "unknown"
				print("ICMP packet: {}".format(icmptype))
			else:
				print("unknown IP packet type")


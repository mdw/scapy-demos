### short python scripts using scapy:

#### dns_query.py - DNS lookup info: A and NS recs
* $ sudo ./dns_query.py \<domain>
* $ sudo ./dns_query.py \<domain> A
* $ sudo ./dns_query.py \<domain> A \<nameserver>
* $ sudo ./dns_query.py \<domain> NS

#### sort_packets.py - for each packet in capture if IP protocol, identify:
* layer 2 source and destination MAC address
* layer 3 source and destination IP address
* transport layer protocol type, ports, TCP flags (TCP, UDP, ICMP only)

usage:<br>
$ ./sort_packets.py \<file.pcap>


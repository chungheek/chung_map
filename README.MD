# chung_map

chung_map.py is a simple python utility that mimics some of the functions in
[nmap](https://nmap.org). It can perform TCP connect scans (-sT) where it establishes
a 3-way handshake, a UDP scan (-sU), an IP protocol scan (-sO) providing which IP protocols
are supported, OS detection (-O). The utility can also read in a file(.txt) of hosts and
supports CIDR addresses. It uses [scapy](https://pypi.org/project/scapy/) to construct packets
and perform the network functionalities.

note: chung_map.py uses a Results class from results.py to store information to later display

Pre-run:
- pip install scapy

Sample Commands:
- python3 chung_map.py -sT -p 20-100, 130-150, 400-500 scanme.nmap.org
- python3 chung_map.py -sU –top-100-ports scanme.nmap.org
- python3 chung_map.py -O scanme.nmap.org
- python3 chung_map.py -sO scanme.nmap.org
- python3 chung_map.py -sT {file.txt} *please use .txt for the file to read. Automatically performs
  -sT scan on ports 20-25*
  - eg. chung_map -sT hosts.txt
- python3 chung_map.py -sT {cidr address} *Make sure host bits are not set. Automatically performs
  -sT scan on ports 20-25*
  - eg. chung_map -sT 192.168.0.0/30
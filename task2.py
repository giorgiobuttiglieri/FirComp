from scapy.all  import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP, ICMP
import matplotlib.pyplot as plt
import csv

def store_ip(_ips = {}):
    def elaborate(_pkt):
        if not _pkt[IP].src in _ips:
            _ips[_pkt[IP].src] = 1
        else:
            _ips[_pkt[IP].src] += 1

        if not _pkt[IP].dst in _ips:
            _ips[_pkt[IP].dst] = 1
        else:
            _ips[_pkt[IP].dst] += 1
    return elaborate

ips = {}
sniff(offline="network_traffic.pcap", store = False, prn=store_ip(ips))
print("Finished to sniff")

top_ip = list()
for i in range(10):
    current_greater_ip = ['0', 0]
    for key, value in ips.items():
        if value > current_greater_ip[1]:
            current_greater_ip[0] = key
            current_greater_ip[1] = value
    ips.pop(current_greater_ip[0])
    top_ip.append((current_greater_ip[0], current_greater_ip[1]))

ip_number = []
ip_count = []

for ip_pair in top_ip:
    ip_number.append(ip_pair[0])
    ip_count.append(ip_pair[1])

with open('top_10_ipt(test).csv', mode = 'w') as ip_file:
    ip_writer = csv.writer(ip_file, delimiter=',')
    for i in range(len(top_ip)):
        ip_writer.writerow([top_ip[i][0], top_ip[i][1]])
plt.figure()
plt.bar(ip_number, ip_count)
plt.show()




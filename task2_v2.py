from scapy.all  import *
import matplotlib.pyplot as plt
import csv

def store_ip(_counter, _ips):
    def elaborate(_pkt):
        _counter[0] += 1
        if not _counter[0] % 2000:
            print(_counter[0],"packets sniffed")
            sys.stdout.write("\033[F")

        if not _pkt[IP].src in _ips:
            _ips[_pkt[IP].src] = 1
        else:
            _ips[_pkt[IP].src] += 1

        if not _pkt[IP].dst in _ips:
            _ips[_pkt[IP].dst] = 1
        else:
            _ips[_pkt[IP].dst] += 1
    return elaborate

print("Sniffing started")
ips = {}
p_counter = [0]
sniff(offline="network_traffic.pcap", store = 0, prn=store_ip(p_counter, ips), count=30000)
print("Sniffing finished")

sort_ip_key = sorted(ips, key= ips.__getitem__, reverse=True)

top_ip = list()
for i in range(10):
    top_ip.append( (sort_ip_key[i], ips[sort_ip_key[i]]) )

ip_number = list()
ip_count = list()

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




from scapy.all  import *
from scapy.layers.inet import IP
import matplotlib.pyplot as plt
import csv
import progressbar
import sys
sys.path.append(".")
from capinfos import * #used to count the number of packets in the pcap file

#count the number of packets
n_packets = capinfos("network_traffic.pcap")["packetscount"]

#setting up the progress bar
widgets = ['SNIFFING: ', progressbar.Percentage(), progressbar.Bar(), progressbar.SimpleProgress(), ' - ', progressbar.Timer(), ', ', progressbar.ETA()]
progress_bar = progressbar.ProgressBar(widgets = widgets, max_value=n_packets)

def store_ip(_ips = {}, counter=[0]):
    def elaborate(_pkt):
        #add the traffic for the src ip of this packet
        if not _pkt[IP].src in _ips:
            _ips[_pkt[IP].src] = _pkt[IP].len
        else:
            _ips[_pkt[IP].src] += _pkt[IP].len
        #add the traffic for the destination ip of this packet
        if not _pkt[IP].dst in _ips:
            _ips[_pkt[IP].dst] = _pkt[IP].len
        else:
            _ips[_pkt[IP].dst] += _pkt[IP].len
        counter[0] += 1
        progress_bar.update(counter[0])
    return elaborate

#dictionary ip_address->amount of traffic
ips = {}

sniff(offline="network_traffic.pcap", store = False, prn=store_ip(ips))
progress_bar.finish()
print("Finished to sniff")

#list of top ten ip addresses
top_ip = list()


for i in range(10):
    #find the ip_addr with the most traffic and remove it from the ips list
    current_greater_ip = ['0', 0]
    for key, value in ips.items():
        if value > current_greater_ip[1]:
            current_greater_ip[0] = key
            current_greater_ip[1] = value
    ips.pop(current_greater_ip[0])
    top_ip.append((current_greater_ip[0], current_greater_ip[1]))

#these lists will contain the parameters to pass to matplotlib in orther to plot the bar
ip_number = []
ip_count = []

for ip_pair in top_ip:
    ip_number.append(ip_pair[0])
    ip_count.append(ip_pair[1])

#writing the csv file
with open('top_10_ipt(test).csv', mode = 'w') as ip_file:
    ip_writer = csv.writer(ip_file, delimiter=',')
    ip_writer.writerow(['ip_addr', 'amount_of_traffic'])
    for i in range(len(top_ip)):
        ip_writer.writerow([top_ip[i][0], top_ip[i][1]])

#plot the bar
plt.figure()
plt.bar(ip_number, ip_count)
plt.xticks(rotation = 'vertical')
plt.tight_layout()
plt.xlabel('IPs')
plt.ylabel('Traffic [Bytes]')
plt.show()




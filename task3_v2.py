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

#this dictionary contains the relevant informations for each ip (ip_address->statistics),
#where statistics is a dictionary (specific_statistic->traffic)
ips_informations = {}

def gather_informations(_source_ports, _destination_ports, _protocols, _total_traffic):

    def elaborate(_pkt):
        #how much data there is in this packet
        _pkt_traffic = _pkt[IP].len

        #increment the traffic of the specified ip
        _total_traffic[0] += _pkt_traffic
        
        #increment the traffic on src and dst ports only if the level 4 is TCP or UDP
        if _pkt.haslayer(TCP) or _pkt.haslayer(UDP):
            if not _pkt.getlayer(2).sport in _source_ports:
                _source_ports[_pkt.getlayer(2).sport] = 0
            _source_ports[_pkt.getlayer(2).sport] += _pkt_traffic

            if not _pkt.getlayer(2).dport in _destination_ports:
                _destination_ports[_pkt.getlayer(2).dport] = 0
            _destination_ports[_pkt.getlayer(2).dport] += _pkt_traffic

        #increment the traffic per protocol anyways
        if not _pkt[IP].proto in _protocols:
            _protocols[_pkt[IP].proto] = 0
        _protocols[_pkt[IP].proto] += _pkt_traffic

    return elaborate

#for each top 10 ip, we filter all the packets by that ip
for _ip, _traffic in top_ip.items():
    
    #this dictionary will contain all relevant statistics (specific statistic -> traffic)
    statistics = {}

    source_ports = {}
    destination_ports = {}
    protocols = {}
    traffic = [0]

    sniff(offline="network_traffic.pcap", filter="ip.src=="+str(_ip)+"or ip.dst==" +str(_ip), prn=gather_informations(source_ports, destination_ports, protocols, total_traffic))

    #we get the biggest element of the dictionary. It will become the most frequent source port, destination port etc...
    statistics['source_port'] = source_ports[sorted(source_ports, key = source_ports.__getitem__, reverse=True)[0]]
    statsitics['destination_ports'] = destination_ports[sorted(destination_ports, key = destination_ports.__getitem__, reverse=True)[0]]
    statistics['protocol'] = protocols[sorted(protocols, key = protocols.__getitem__, reverse=True)[0]]
    statistics['traffic'] = traffic[0]

    ips_informations[_ip] = statistics

#debug
print(ips_informations['147.32.80.13'])


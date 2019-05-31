from scapy.all import *
from scapy.layers.inet import IP
import matplotlib.pyplot as plt
import csv
import progressbar
import sys

sys.path.append(".")
from capinfos import *  # used to count the number of packets in the pcap file

# count the number of packets
n_packets = capinfos("network_traffic.pcap")["packetscount"]

# setting up the progress bar
widgets = ['SNIFFING: ', progressbar.Percentage(), progressbar.Bar(), progressbar.SimpleProgress(), ' - ',
           progressbar.Timer(), ', ', progressbar.ETA()]
progress_bar = progressbar.ProgressBar(widgets=widgets, max_value=n_packets)


def store_ip(_ips={}, counter=[0]):
    def elaborate(_pkt):
        # add the traffic for the src ip of this packet
        if not _pkt[IP].src in _ips:
            _ips[_pkt[IP].src] = _pkt[IP].len
        else:
            _ips[_pkt[IP].src] += _pkt[IP].len
        # add the traffic for the destination ip of this packet
        if not _pkt[IP].dst in _ips:
            _ips[_pkt[IP].dst] = _pkt[IP].len
        else:
            _ips[_pkt[IP].dst] += _pkt[IP].len
        counter[0] += 1
        progress_bar.update(counter[0])

    return elaborate


# dictionary ip_address->amount of traffic
ips = {}

sniff(offline="network_traffic.pcap", store=False, prn=store_ip(ips))
progress_bar.finish()
print("Finished to sniff")

# list of top ten ip addresses
top_ip = list()

for i in range(10):
    # find the ip_addr with the most traffic and remove it from the ips list
    current_greater_ip = ['0', 0]
    for key, value in ips.items():
        if value > current_greater_ip[1]:
            current_greater_ip[0] = key
            current_greater_ip[1] = value
    ips.pop(current_greater_ip[0])
    top_ip.append((current_greater_ip[0], current_greater_ip[1]))

# this dictionary contains the relevant informations for each ip (ip_address->statistics),
# where statistics is a dictionary (specific_statistic->traffic)
ips_informations = {}


def get_pkts_topip(_packets_topip, _topip, counter=[0]):
    def getpkts(_pkt):

        #fetching packets generated and received by top IPs
        if IP in _pkt:
            if _pkt[IP].src in _topip:
                if not _pkt[IP].src in _packets_topip:
                    _packets_topip[_pkt[IP].src] = list()
                _packets_topip[_pkt[IP].src].append(_pkt)
            if _pkt[IP].dst in _topip:
                if not _pkt[IP].dst in _packets_topip:
                    _packets_topip[_pkt[IP].dst] = list()
                _packets_topip[_pkt[IP].dst].append(_pkt)

        #update progress bar
        progress_bar.update(counter[0])

    return getpkts




def gather_informations(_source_ports, _destination_ports, _protocols, _total_traffic):
    def elaborate(_pkt):
        # how much data there is in this packet
        _pkt_traffic = _pkt[IP].len

        # increment the traffic of the specified ip
        _total_traffic[0] += _pkt_traffic

        # increment the traffic on src and dst ports only if the level 4 is TCP or UDP
        if _pkt.haslayer(TCP) or _pkt.haslayer(UDP):
            if not _pkt.getlayer(2).sport in _source_ports:
                _source_ports[_pkt.getlayer(2).sport] = 0
            _source_ports[_pkt.getlayer(2).sport] += _pkt_traffic

            if not _pkt.getlayer(2).dport in _destination_ports:
                _destination_ports[_pkt.getlayer(2).dport] = 0
            _destination_ports[_pkt.getlayer(2).dport] += _pkt_traffic

        # increment the traffic per protocol anyways
        if not _pkt[IP].proto in _protocols:
            _protocols[_pkt[IP].proto] = 0
        _protocols[_pkt[IP].proto] += _pkt_traffic

    return elaborate


packets_topip = {}
widgets = ['FILTERING PACKETS BY IP: ', progressbar.Percentage(), progressbar.Bar(), progressbar.SimpleProgress(), ' - ',
           progressbar.Timer(), ', ', progressbar.ETA()]
progress_bar = progressbar.ProgressBar(widgets=widgets, max_value=n_packets)
sniff(offline="network_traffic.pcap", prn=get_pkts_topip(packets_topip, [ip[0] for ip in top_ip]), store=0)

# for each top 10 ip, we filter all the packets by that ip
for _ip, _traffic in top_ip:
    # this dictionary will contain all relevant statistics (specific statistic -> traffic)
    statistics = {}

    source_ports = {}
    destination_ports = {}
    protocols = {}
    total_traffic = [0]
    for _pkt in packets_topip[_ip]:
        gather_informations(source_ports, destination_ports, protocols, total_traffic)(_pkt)

    # we get the biggest element of the dictionary. It will become the most frequent source port, destination port etc...
    main_source_port = sorted(source_ports, key=source_ports.__getitem__, reverse=True)[0]
    statistics['source_port'] = (main_source_port, source_ports[main_source_port])

    main_destination_port = sorted(destination_ports, key=destination_ports.__getitem__, reverse=True)[0]
    statistics['destination_port'] = (main_destination_port, destination_ports[main_destination_port])

    main_protocol = sorted(protocols, key=protocols.__getitem__, reverse=True)[0]
    statistics['protocol'] = (main_protocol,protocols[main_protocol])

    statistics['traffic'] = total_traffic[0]

    ips_informations[_ip] = statistics

# writing csv
with open('task_3.csv', mode = 'w') as csv_file:
    csv_writer = csv.writer(csv_file, delimiter=',')

    csv_writer.writerow(['ip_addr', 'amount_of_total_traffic', 'protocol', 'amount_of_traffic_for_specific_protocol',
                         'source_port', 'amount_for_spec_source_port', 'destination_port', 'amount_for_spec_destination_port'])
    for _ip, _statistics in ips_informations.items():
        csv_writer.writerow([_ip, str(_statistics['traffic']), str(_statistics['protocol'][0]), str(_statistics['protocol'][1]),
                             str(_statistics['source_port'][0]), str(_statistics['source_port'][1]), str(_statistics['destination_port'][0]),
                             str(_statistics['destination_port'][1])])


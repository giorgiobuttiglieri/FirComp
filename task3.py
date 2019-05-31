from scapy.all  import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP, ICMP
import csv

#this object holds an Ip address with all relevant statistics for this task
class IpAddress:
    def __init__(self, ip_address, traffic):
        self.ip_address = ip_address
        self.traffic = traffic
        self.protocols = {}
        self.source_ports = {}
        self.destination_ports = {}
        
        #most frequent protocols, source port and destination port, with the associated traffic
        self.frequent_protocol = [-1,-1]
        self.frequent_source_port = [-1, -1]
        self.frequent_destination_port = [-1, -1]

    def update_protocols(self, protocol):
        if not protocol in self.protocols:
            self.protocols[protocol] = 1
        else:
            self.protocols[protocol] += 1


    def update_source_port(self, source_port):
        if not source_port in self.source_ports:
            self.source_ports[source_port] = 1
        else:
            self.source_ports[source_port] += 1

    def update_destination_port(self, destination_port):
        if not destination_port in self.destination_ports:
            self.destination_ports[destination_port] = 1
        else:
            self.destination_ports[destination_port] += 1

    def gather_statistics(self):
        for key, value in self.protocols.items():
            if value > self.frequent_protocol[1]:
                self.frequent_protocol[0] = key
                self.frequent_protocol[1] = value

        for key, value in self.source_ports.items():
            if value > self.frequent_source_port[1]:
                self.frequent_source_port[0] = key
                self.frequent_source_port[1] = value

        for key, value in self.destination_ports.items():
            if value > self.frequent_destination_port[1]:
                self.frequent_destination_port[0] = key
                self.frequent_destination_port[1] = value


def gather_information(_top_ips):
    def elaborate(_pkt):
        for _ip in _top_ips:
            if _ip.ip_address == _pkt[IP].src:
                _ip.update_protocols(_pkt[IP].proto)
                if _pkt.haslayer(TCP) or _pkt.haslayer(UDP):
                    _ip.update_source_port(_pkt.getlayer(2).sport)
                    _ip.update_destination_port(_pkt.getlayer(2).dport)
                break
        for _ip in _top_ips:
            if _ip.ip_address == _pkt[IP].dst:
                _ip.update_protocols(_pkt[IP].proto)
                if _pkt.haslayer(TCP) or _pkt.haslayer(UDP):
                    _ip.update_source_port(_pkt.getlayer(2).sport)
                    _ip.update_destination_port(_pkt.getlayer(2).dport)
                break

    return elaborate

top_ips = []
with open('top_10_ipt(test).csv') as top_ip_file:
    csv_reader = csv.reader(top_ip_file, delimiter = ',')
    for row in csv_reader:
        if len(row) == 2:
            top_ips.append(IpAddress(row[0], row[1]))

sniff(offline="network_traffic.pcap", store = False, count = 170000, prn = gather_information(top_ips))

for _ip in top_ips:
    _ip.gather_statistics()
    print(_ip.ip_address + ":")
    print("\tProtocols: " + str(_ip.frequent_protocol))
    print("\tSource Ports: " + str(_ip.frequent_source_port))
    print("\tDestination Ports: " + str(_ip.frequent_destination_port))



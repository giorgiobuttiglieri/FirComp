from scapy.all import *
import csv
standard_ports = list(range(1200)) #list of standard ports

traffic_counter = {}
for port in standard_ports:
    pkts = sniff(offline="network_traffic.pcap", filter="port " + str(port))
    for pkt in pkts:
        if traffic_counter.get(port):
            traffic_counter[port] += 1
        else:
            traffic_counter[port] = 1

print(traffic_counter)
from scapy.all import *
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

standard_ports = [1, 2, 3, 7, 8, 9, 13, 17, 19, 20, 21, 22, 23, 25, 53, 67, 68, 69, 70,
                 79, 80, 88, 104, 110, 113, 119, 123, 137, 138, 139, 143, 161, 162, 389,
                  411, 443, 445, 465, 502, 514, 554, 563, 587, 591, 631, 636, 666, 993, 995]

#dictionary port_number->value
traffic_counter = {}
counter = 0

#for eache port, we count the amount of traffic and update the dictionary
for port in standard_ports:
    pkts = sniff(offline="network_traffic.pcap", filter="port " + str(port))
    for pkt in pkts:
        if traffic_counter.get(port):
            traffic_counter[port] += pkt[IP].len
        else:
            traffic_counter[port] = pkt[IP].len
    counter += 1
    progress_bar.update(counter)
progress_bar.finish()

#exporting to csv
with open('task_1.csv', mode = 'w') as csv_file:
    csv_writer = csv.writer(csv_file, delimiter=',')

    csv_writer.writerow(['port_number', 'amount_of_traffic'])
    for key, value in traffic_counter.items():
        csv_writer.writerow([key, value])
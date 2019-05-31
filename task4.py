from scapy.all  import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP, ICMP
import matplotlib.pyplot as plt
import csv


def GetMinMaxMean(_stats):
    _stats["N_PACKS"] = 0
    def elaborate(_pkt):
        _stats["N_PACKS"] += 1
        if not _stats["N_PACKS"] % 2000:
            print(_stats["N_PACKS"], "packets sniffed")
            sys.stdout.write("\033[F")

        _ttl = _pkt[IP].ttl
        if(_ttl < _stats["MIN"]):
            _stats["MIN"] = _ttl
        elif(_ttl > _stats["MAX"]):
             _stats["MAX"] = _ttl
        _stats["SUM"] += _ttl
    return elaborate


def GetVariance(_stats):
    _stats["N_PACKS"] = 0
    def elaborate(_pkt):
        _stats["N_PACKS"] += 1
        if not _stats["N_PACKS"] % 2000:
            print( "Calculating variance...", _stats["N_PACKS"])
            sys.stdout.write("\033[F")
        
        _ttl = _pkt[IP].ttl
        _stats["VARIANCE"] += pow(_ttl - _stats["AVG"], 2)
    return elaborate


print("Sniffing started")
stats = {"N_PACKS":0, "MIN":9999, "MAX":0, "SUM":0, "VARIANCE":0}
sniff(offline="network_traffic.pcap", store = 0, prn=GetMinMaxMean(stats))
stats["AVG"] = stats["SUM"]/stats["N_PACKS"]
sniff(offline="network_traffic.pcap", store = 0, prn=GetVariance(stats))
stats["VARIANCE"] /= stats["N_PACKS"] - 1
print("")
print("Sniffing finished")

with open('task4.csv', mode = 'w') as ip_file:
    ip_writer = csv.writer(ip_file, delimiter=',')
    ip_writer.writerow(['min', 'max', 'average', 'variance'])
    ip_writer.writerow([stats["MIN"], stats["MAX"], stats["AVG"], stats["VARIANCE"]])


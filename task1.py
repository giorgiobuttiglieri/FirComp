from scapy.all  import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP, ICMP


def count_pakcet(_pkt, _ports):
    if TCP in _pkt:
        if not _pkt.getlayer(TCP).dport in _ports:
            _ports[_pkt.getlayer(TCP).dport] = 1
        else:
            _ports[_pkt.getlayer(TCP).dport] += 1
    elif UDP in _pkt:
        if not _pkt.getlayer(UDP).dport in _ports:
            _ports[_pkt.getlayer(UDP).dport] = 1
        else:
            _ports[_pkt.getlayer(UDP).dport] += 1

def count_layers(_pkt, _layers):
    layer_id = 0
    while True:
        if not _pkt.getlayer(layer_id):
            break;
        if not layer_id in _layers:
            _layers[layer_id]  = 1
        else:
            _layers[layer_id]  += 1
        layer_id += 1

def count_protocols(_pkt, _proto):
    if TCP in _pkt:
        if not 'TCP' in _proto:
            _proto['TCP'] = 1
        else:
            _proto['TCP'] += 1
    elif UDP in _pkt:
       if not 'UDP' in _proto:
            _proto['UDP'] = 1
       else:
            _proto['UDP'] += 1  

    elif ICMP in _pkt:
       if not 'ICMP' in _proto:
            _proto['ICMP'] = 1
       else:
            _proto['ICMP'] += 1 
    else:
        print(_pkt.summary())

def count_port_traffic(_pkt, _ports = {}, get_results = False):
    if get_results:
        return _ports

    if not _pkt.sport in _ports:
        _ports[_pkt.sport] = 1
    else:
        _ports[_pkt.sport] += 1
    if not _pkt.dport in _ports:
        _ports[_pkt.dport] = 1
    else:
        _ports[_pkt.dport] += 1


##################################################  Main Code   ############################################################################

sniff(offline="network_traffic.pcap", count = 100, prn = count_port_traffic)
print("File loaded")
ports = count_port_traffic(get_results = True)
print(ports)




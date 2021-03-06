# coding=utf-8
from scapy.all  import *
import matplotlib.pyplot as plt
import progressbar
import sys
sys.path.append(".")
from capinfos import *


n_packets = capinfos("network_traffic.pcap")["packetscount"]

widgets = ['SNIFFING: ', progressbar.Percentage(), progressbar.Bar(), progressbar.SimpleProgress(), ' - ', progressbar.Timer(), ', ', progressbar.ETA()]
bar = progressbar.ProgressBar(widgets = widgets, max_value=n_packets)

def GetConnections(_counter, _conn):
    def elaborate(_pkt):
        _counter[0] += 1
        if not _counter[0] % 500:
            bar.update(_counter[0])

        if TCP in _pkt:
            if not (_pkt[IP].src, _pkt[IP].dst) in _conn:
                _conn[ (_pkt[IP].src, _pkt[IP].dst) ] = list()
            _conn[ (_pkt[IP].src, _pkt[IP].dst) ].append(_pkt)
    return elaborate

print("Sniffing started")
conn = {}
counter = [0]
sniff(offline="network_traffic.pcap", store = 0, prn=GetConnections(counter, conn), count=10000)
bar.finish()
print("Sniffing finished")

localip_conns = []

# return /n where 0<=n<=32
def get_common_netmask(ip1,ip2):
    r = ip1^ip2
    i = 1<<31
    flag = r&i
    mask = 0
    while not flag and i:
        i >>= 1
        flag = r & i
        mask += 1
    return mask


def ip_strtoint(ipstr):
    strbytes =ipstr.split('.')
    return (int(strbytes[0])<<24) + (int(strbytes[1])<<16) + (int(strbytes[2])<<8) + int(strbytes[3])


def ip_inttostr(ipstr):
    s1 = str(ipstr>>24)
    s2 = str( (ipstr&(255<<16))>>16 )
    s3 = str( (ipstr&(255<<8))>>8 )
    s4 = str(ipstr&255)
    return f'{s1}.{s2}.{s3}.{s4}'


def get_biggest_common_net(_ip, _conn_dict):
    netmask = 32
    LOCALNET_IP = ( ("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16) )
    for conn_ips, pkts in _conn_dict.items():
        if netmask < 8:
            break

        #check for local IPs
        f_ip_islocal = False
        for lip in LOCALNET_IP:
            if get_common_netmask( ip_strtoint(conn_ips[0]), ip_strtoint(lip[0]) ) >= lip[1]:
                f_ip_islocal = True
            if get_common_netmask( ip_strtoint(conn_ips[1]), ip_strtoint(lip[0]) ) >= lip[1]:
                f_ip_islocal = True

        if(f_ip_islocal):
            localip_conns.append(conn_ips)
        else:
            r1 = get_common_netmask(_ip, ip_strtoint(conn_ips[0]))
            r2 = get_common_netmask(_ip, ip_strtoint(conn_ips[1]))
            netmask = min(max(r1, r2), netmask)
    return netmask

def get_net_name(_ip, _mask):
    _ans_ip = 0
    for i in range(0, _mask):
        _ans_ip += _ip&1<<(31-i)
    return _ans_ip

#find internal internet subnet (estimated)
nm1 = get_biggest_common_net( ip_strtoint(next(iter(conn))[0]), conn)
nm2 = get_biggest_common_net( ip_strtoint(next(iter(conn))[1]), conn)
if(nm1 > nm2):
    privatenet_mask = nm1
    privatenet_ip = get_net_name(ip_strtoint(next(iter(conn))[0]), privatenet_mask)
else:
    privatenet_mask = nm2
    privatenet_ip = get_net_name(ip_strtoint(next(iter(conn))[1]), privatenet_mask)

#analize local network, "internal" intenet subnet, external net (internet)
n_local_conn = len(localip_conns)
n_privatenet_conn = 0
n_external_conn = 0
n_local_traffic = len(localip_conns)
n_privatenet_traffic = 0
n_external_traffic = 0
for conn_ips, pkts in conn.items():

    #get traffic generated by the connection (sum of packets size)
    traffic = 0
    for p in pkts:
        if IP in p:
            traffic+= p[IP].len
    if conn_ips in localip_conns:
        n_local_conn += 1
        n_local_traffic += traffic
    elif get_common_netmask(ip_strtoint(conn_ips[0]), privatenet_ip)>=privatenet_mask and get_common_netmask(ip_strtoint(conn_ips[1]), privatenet_ip)>=privatenet_mask:
        n_privatenet_conn += 1
        n_privatenet_traffic += traffic
    else:
        n_external_conn += 1
        n_external_traffic += traffic


print(f"The internal internet subnet is {ip_inttostr(privatenet_ip)}/{privatenet_mask} (estimated)")
print("LOCAL NETWORK:")
print("     Number of connections(unidirectional):", n_local_conn)
print("     Traffic generated:", n_local_traffic)
print("PRIVATE INTERNAL NET:")
print("     Number of connections(unidirectional):", n_privatenet_conn)
print("     Traffic generated:", n_privatenet_traffic)
print("EXTERNAL CONNECTIONS TOWARDS INTERNET:")
print("     Number of connections(unidirectional):", n_external_conn)
print("     Traffic generated:", n_external_traffic)

fig, (ax1, ax2) = plt.subplots(2)
fig.suptitle(f"The internal internet subnet is {ip_inttostr(privatenet_ip)}/{privatenet_mask} (estimated)")

x = list(range(3))

conn_list = [n_local_conn, n_privatenet_conn, n_external_conn]
traffic_list = [n_local_traffic, n_privatenet_traffic, n_external_traffic]
plt.sca(ax1)
plt.bar(x, height=conn_list)

for i, _height in enumerate(conn_list):
    plt.text(i, _height + .1, str(_height), color='red')
plt.xticks(list(range(3)), ['local ip network connections', 'private internal subnet connections', 'connections towards internet'])
plt.sca(ax2)
for i, _height in enumerate(traffic_list):
    plt.text(i, _height  + .1, str(_height), color='red')
plt.bar(x, height=traffic_list)
plt.xticks(list(range(3)), ['local ip network connections', 'private internal subnet connections', 'connections towards internet'])
plt.show()

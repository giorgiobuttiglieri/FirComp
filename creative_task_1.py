<<<<<<< HEAD
from scapy.all  import *
import matplotlib.pyplot as plt
import pandas as pd
import geopandas as gpd
from shapely.geometry import Point, LineString
import progressbar
import sys
sys.path.append(".")
from capinfos import *

n_packets = capinfos("network_traffic.pcap")["packetscount"]

widgets = ['SNIFFING: ', progressbar.Percentage(), progressbar.Bar(), progressbar.SimpleProgress(), ' - ', progressbar.Timer(), ', ', progressbar.ETA()]
bar = progressbar.ProgressBar(widgets = widgets, max_value=n_packets)

#_conn is a dictionary that holds every tcp conversation (ip tuple -> list of packets)
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
sniff(offline="network_traffic.pcap", store = 0, prn=GetConnections(counter, conn))
bar.finish()
print("Sniffing finished")

#dictionary that contains tuples of ips with corresponding errors 
conn_errors = {}

#Counting amount of repeated ack for each connection
for conn_ips, pkts in conn.items():
    #dictionary that associate the ack number to the number of times that ack has been resent
    n_ack = {}
    for p in pkts:
        ACK_BITMASK = 0x10 
        #if we have a valid ACK flag
        if p[TCP].flags & ACK_BITMASK:
            if not p[TCP].ack in n_ack:
                n_ack[p[TCP].ack] = 0
            n_ack[p[TCP].ack] += 1

    #we consider an error in the connection if more than 3 ack are resent
    for ack, ack_counter in n_ack.items():
        if ack_counter > 3:
            if not conn_ips in conn_errors:
                conn_errors[conn_ips] = 0
            conn_errors[conn_ips] += 1


#this dictionary merge the two directional channels of connections. Every tuple of ip is associated with one and only one conversation
bidirectional_conn_errors = {}

for conn_ips, n_errors in conn_errors.items():
    if conn_ips in bidirectional_conn_errors: 
        bidirectional_conn_errors[conn_ips] += n_errors
    elif conn_ips[::-1] in bidirectional_conn_errors:
        bidirectional_conn_errors[conn_ips[::-1]] += n_errors
    else:
        bidirectional_conn_errors[conn_ips] = n_errors

#finding the biggest value for errors (it will be important for the line color)
max_errors_conn = -1
for conn_ips, n_errors in bidirectional_conn_errors.items():
    if n_errors > max_errors_conn:
        max_errors_conn = n_errors


#Retriving ip addresses with location and load them in a pd Dataframe
ip_loc_df = pd.read_csv('real.csv')
ip_loc_df = ip_loc_df.set_index('ip')

index = pd.MultiIndex.from_tuples(list(bidirectional_conn_errors.keys()), names=['ip1', 'ip2'])
conn_df = pd.DataFrame(list(bidirectional_conn_errors.values()), columns=['errors'], index = index)

lines = []
for row in conn_df.index.tolist():
    #Some ip in the pcap file are not present in the ip_location file (for example 111.81.72.250 (destination))
    try:
        lines.append(LineString((Point(ip_loc_df.loc[row[0]][::-1]), Point(ip_loc_df.loc[row[1]][::-1]))))
    except:
        lines.append(LineString(( Point((0,0)), Point((0,0)) )) )for row in conn_df.index.tolist():






#loading the map
world_map = gpd.read_file('TM_WORLD_BORDERS-0.3.shp')

#setting coordinates type
crs = {'init':'epsg:4326'}

fig, ax = plt.subplots(figsize = (15, 15))

#creating a geo dataframe with information on the lines to plot
geo_df = gpd.GeoDataFrame(conn_df, crs = crs, geometry = lines)
world_map.plot(ax = ax)


#plot lines with color rapresenting the quality of the connection
for ips, n in bidirectional_conn_errors.items():
    if n < 3:
        _color = (n/2, (2-n)/2, 0, 0.85)
    else:
        _color = (1-(0.4*n+0.6*max_errors_conn-3)/(max_errors_conn-3),(0.4*n+0.6*max_errors_conn-3)/(max_errors_conn-3),0,0.95)
    geo_df.loc[[ips[0], ips[1]], 'geometry'].plot(ax = ax, color = _color)
plt.show()






=======
from scapy.all  import *
import matplotlib.pyplot as plt
import pandas as pd
import geopandas as gpd
from shapely.geometry import Point, LineString
import progressbar
import sys
sys.path.append(".")
from capinfos import *

n_packets = capinfos("network_traffic.pcap")["packetscount"]

widgets = ['SNIFFING: ', progressbar.Percentage(), progressbar.Bar(), progressbar.SimpleProgress(), ' - ', progressbar.Timer(), ', ', progressbar.ETA()]
bar = progressbar.ProgressBar(widgets = widgets, max_value=n_packets)

#_conn is a dictionary that holds every tcp conversation (ip tuple -> list of packets)
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
sniff(offline="network_traffic.pcap", store = 0, prn=GetConnections(counter, conn))
bar.finish()
print("Sniffing finished")

#dictionary that contains tuples of ips with corresponding errors 
conn_errors = {}

#Counting amount of repeated ack for each connection
for conn_ips, pkts in conn.items():
    #dictionary that associate the ack number to the number of times that ack has been resent
    n_ack = {}
    for p in pkts:
        ACK_BITMASK = 0x10 
        #if we have a valid ACK flag
        if p[TCP].flags & ACK_BITMASK:
            if not p[TCP].ack in n_ack:
                n_ack[p[TCP].ack] = 0
            n_ack[p[TCP].ack] += 1

    #we consider an error in the connection if more than 3 ack are resent
    for ack, ack_counter in n_ack.items():
        if ack_counter > 3:
            if not conn_ips in conn_errors:
                conn_errors[conn_ips] = 0
            conn_errors[conn_ips] += 1


#this dictionary merge the two directional channels of connections. Every tuple of ip is associated with one and only one conversation
bidirectional_conn_errors = {}

for conn_ips, n_errors in conn_errors.items():
    if conn_ips in bidirectional_conn_errors: 
        bidirectional_conn_errors[conn_ips] += n_errors
    elif conn_ips[::-1] in bidirectional_conn_errors:
        bidirectional_conn_errors[conn_ips[::-1]] += n_errors
    else:
        bidirectional_conn_errors[conn_ips] = n_errors

#finding the biggest value for errors (it will be important for the line color)
max_errors_conn = -1
for conn_ips, n_errors in bidirectional_conn_errors.items():
    if n_errors > max_errors_conn:
        max_errors_conn = n_errors


#Retriving ip addresses with location and load them in a pd Dataframe
ip_loc_df = pd.read_csv('real.csv')
ip_loc_df = ip_loc_df.set_index('ip')

index = pd.MultiIndex.from_tuples(list(bidirectional_conn_errors.keys()), names=['ip1', 'ip2'])
conn_df = pd.DataFrame(list(bidirectional_conn_errors.values()), columns=['errors'], index = index)

lines = []
for row in conn_df.index.tolist():
    #Some ip in the pcap file are not present in the ip_location file (for example 111.81.72.250 (destination))
    try:
        lines.append(LineString((Point(ip_loc_df.loc[row[0]][::-1]), Point(ip_loc_df.loc[row[1]][::-1]))))
    except:
        lines.append(LineString(( Point((0,0)), Point((0,0)) )) )






#loading the map
world_map = gpd.read_file('TM_WORLD_BORDERS-0.3.shp')

#setting coordinates type
crs = {'init':'epsg:4326'}

fig, ax = plt.subplots(figsize = (15, 15))

#creating a geo dataframe with information on the lines to plot
geo_df = gpd.GeoDataFrame(conn_df, crs = crs, geometry = lines)
world_map.plot(ax = ax)


#plot lines with color rapresenting the quality of the connection
for ips, n in bidirectional_conn_errors.items():
    if n < 3:
        _color = (n/2, (2-n)/2, 0, 0.85)
    else:
        _color = (1-(0.4*n+0.6*max_errors_conn-3)/(max_errors_conn-3),(0.4*n+0.6*max_errors_conn-3)/(max_errors_conn-3),0,0.95)
    geo_df.loc[[ips[0], ips[1]], 'geometry'].plot(ax = ax, color = _color)
plt.show()






>>>>>>> d6c080daa213b60739533f68c6801a32a6b6c48d

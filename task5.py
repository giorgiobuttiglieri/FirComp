import pandas as pd
import matplotlib.pyplot as plt
import descartes
import geopandas as gpd
from shapely.geometry import Point, Polygon

#loading the map
world_map = gpd.read_file('TM_WORLD_BORDERS-0.3.shp')

#reading ip location
ip_data = pd.read_csv('ips_locations.csv')

#setting coordinates type
crs = {'init':'epsg:4326'}

#creating a list of points with coordinates given by the ip locations
points = [Point(xy) for xy in zip(ip_data["x"], ip_data["y"])]


fig, ax = plt.subplots(figsize = (15, 15))

#creating the geopandas dataframe with proper geometry column
geo_df = gpd.GeoDataFrame(ip_data, crs = crs, geometry = points)

#plot everything
world_map.plot(ax = ax)
geo_df.plot(ax = ax, markersize = 0.1, color = "red", marker = "o")
plt.show()
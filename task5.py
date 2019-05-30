import pandas as pd
import matplotlib.pyplot as plt
import descartes
import geopandas as gpd
from shapely.geometry import Point, Polygon

world_map = gpd.read_file('TM_WORLD_BORDERS-0.3.shp')
ip_data = pd.read_csv('real.csv')
crs = {'init':'epsg:4326'}

points = [Point(xy) for xy in zip(ip_data["y"], ip_data["x"])]
fig, ax = plt.subplots(figsize = (15, 15))

geo_df = gpd.GeoDataFrame(ip_data, crs = crs, geometry = points)

world_map.plot(ax = ax)
geo_df.plot(ax = ax, markersize = 0.1, color = "red", marker = "o")
plt.show()
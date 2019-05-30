import json
import urllib3
import csv
import pandas as pd
import time
import threading

class State:
    #sate 0 --> closed, state 1 --> open
    def __init__(self):
        self.current_state = 1
    def change_state(self, new_state):
        self.current_state = new_state

def listen_interrumpt(state):
    stop = input()
    state.change_state(0)


main_state = State()
thread1 = threading.Thread(target=listen_interrumpt, args=(main_state,))
thread1.daemon =  True
thread1.start()

fake_locations = pd.read_csv('real.csv')
start_index = 0
try:
    f = open("last_row_updated.txt", "r")
    start_index = int(f.read())
    f.close()
except:
    print("NEW UPDATE")
http = urllib3.PoolManager()

counter = start_index
for index, row in fake_locations.iloc[start_index:].iterrows():
    if main_state.current_state == 0:
        f = open("last_row_updated.txt", "w")
        f.write(str(index))
        f.close()
        break
    if index % 100 == 0:
        fake_locations.to_csv('real.csv', index=False)
        f = open("last_row_updated.txt", "w")
        f.write(str(index))
        f.close()
        print("SAVED")
    try:
        print("request " + str(counter) + ": ", end = '')
        request = http.request('GET', 'https://extreme-ip-lookup.com/json/'+str(row['ip']))
        print("Done!")
        data = json.loads(request.data.decode('utf-8'))
        fake_locations.at[index, 'x'] = data['lat']
        fake_locations.at[index, 'y'] = data['lon']
    except:
        fake_locations.at[index, 'x'] = 0
        fake_locations.at[index, 'y'] = 0

        print("Bannato")
    counter += 1
    time.sleep(1.3)

fake_locations.to_csv('real.csv', index=False)



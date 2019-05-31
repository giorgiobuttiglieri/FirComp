import json
import urllib3
import csv
import pandas as pd
import time
import threading

#we use this object to communicate between threads
class State:
    #sate 0 --> closed, state 1 --> open
    def __init__(self):
        self.current_state = 1
    def change_state(self, new_state):
        self.current_state = new_state

#this function listen asynchronously for input by the user
def listen_interrumpt(state):
    stop = input()
    state.change_state(0)

#launching the thread
main_state = State()
thread1 = threading.Thread(target=listen_interrumpt, args=(main_state,))
thread1.daemon =  True
thread1.start()

#reading the file with random values and saving it into a pandas dataframe
random_locations = pd.read_csv('real.csv')

#reading the index of the last row visited by the script (this script has been executed multiple times and
#we had to make sure that each time it continued from the last row checked)
start_index = 0
try:
    f = open("last_row_updated.txt", "r")
    start_index = int(f.read())
    f.close()
except:
    print("NEW UPDATE")

#it takes care of the http request
http = urllib3.PoolManager()

#for each row in the dataframe we send a request to extreme-ip-lookup.com, parse the response and update the dataframe
counter = start_index
for index, row in random_locations.iloc[start_index:].iterrows():
    if main_state.current_state == 0:
        f = open("last_row_updated.txt", "w")
        f.write(str(index))
        f.close()
        break
    #sometimes we save the results in the file
    if index % 100 == 0:
        random_locations.to_csv('real.csv', index=False)
        f = open("last_row_updated.txt", "w")
        f.write(str(index))
        f.close()
        print("SAVED")
    #trying to send the request.
    try:
        print("request " + str(counter) + ": ", end = '')
        request = http.request('GET', 'https://extreme-ip-lookup.com/json/'+str(row['ip']))
        print("Done!")
        data = json.loads(request.data.decode('utf-8'))
        random_locations.at[index, 'x'] = data['lat']
        random_locations.at[index, 'y'] = data['lon']
    except:
        random_locations.at[index, 'x'] = 0
        random_locations.at[index, 'y'] = 0

        print("No response")
    counter += 1
    time.sleep(1.3)

#updating the file
random_locations.to_csv('real.csv', index=False)



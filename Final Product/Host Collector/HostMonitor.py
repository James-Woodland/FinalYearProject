from vcgencmd import Vcgencmd
import os
import psycopg2
from datetime import datetime, timezone
from getmac import get_mac_address as gma
import time
import joblib
from sklearn import *
import json


"""
Collects CPU usage stats
"""
def getCPUStats():
    vcgm = Vcgencmd()
    temp = vcgm.measure_temp()
    volts = vcgm.measure_volts("core")
    freeCpu = str(os.popen("top -b -n1 | awk '/Cpu\(s\):/ {print $8}'").readline().strip(\
    ))
    return(str(100-float(freeCpu)), temp, volts)

"""
Collects statistics related to how many tasks are running
"""
def getTaskStats():
    Tasks = str(os.popen("top -b -n1 | awk '/Tasks\:/ {print $0}'").readline().strip(\
))
    Tasks = Tasks.split(" ")
    return(Tasks)

def getRAMStats():
    p = os.popen('free -t')
    i = 0
    while 1:
        i = i + 1
        line = p.readline()
        if i==4:
            totalMemUsage = line.split()[2]
            totalMem = line.split()[1]
            break
    return(totalMemUsage, totalMem)
    

"""
Calls the functions to collect host statistics
Scales the host data and then predicts whether the data indicates malicious activity or not
Stores the host data and the associated label into the database
"""
def getHostData(conn, cur, Model, Scaler):    
    cpu, temp, volts = getCPUStats()
    tasks = getTaskStats()
    totalMemUsage, totalMem = getRAMStats()
    
    data = [[totalMemUsage, temp, tasks[1], volts, cpu]]
    data = Scaler.transform(data)
    label = Model.predict(data)
    cur.execute("INSERT INTO HOSTDATA (TimeStamp, totalRam, usedRam, cpuPercent, cpuTemp, cpuVolts, totalTasks, runningTasks, sleepingTasks, stoppedTasks, ZombieTasks, mac, label) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (datetime.now(timezone.utc), totalMem, totalMemUsage, cpu, temp, volts, tasks[1], tasks[5],tasks[7],tasks[11],tasks[15], gma(), int(label[0])))
    conn.commit()

"""
Loads in the config file
Set up the connection to the database
Loads in the scaler and Model
starts a loops so that host data collection will over every 5 seconds
"""
if __name__ == "__main__":
    path = os.path.realpath(__file__)
    path  = path.split("/")
    path = "/".join(path[0:-1])
    f = open(path+"/Config.json")

    setup = json.load(f)

    databaseIP = setup["Database"]["databaseIP"]
    print(f)
    postgresPassword = setup["Database"]["postgresPassword"]
    try:        
        conn = psycopg2.connect(
            host=databaseIP,
            database="pulse",
            user="postgres",
            password=postgresPassword)
        print("connection successful")
            
    except Exception as e:
        print(e)        
    cur = conn.cursor()
    
    path = os.path.realpath(__file__)
    path = path.split("/")
    path = path[:-1]
    path = "/".join(path)
    Model = joblib.load(path+"/StackingHost.pkl")
    Scaler = joblib.load(path+"/HostScaler.pkl")
    try:
        while True:
            try:
                start_time = time.time()
                getHostData(conn, cur, Model, Scaler)
                time.sleep(5-(time.time()-start_time))
            except:
                pass
    except Exception as e:
        print(e)
        cur.close()
        conn.close()
        print("program crashed")




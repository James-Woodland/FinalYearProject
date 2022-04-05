from vcgencmd import Vcgencmd
import os
import psycopg2
from datetime import datetime, timezone
from getmac import get_mac_address as gma
import time
import joblib

def getCPUuse():
    freeCpu = str(os.popen("top -b -n1 | awk '/Cpu\(s\):/ {print $8}'").readline().strip(\
    ))
    return(str(100-float(freeCpu)))

def getTaskNum():
    Tasks = str(os.popen("top -b -n1 | awk '/Tasks\:/ {print $0}'").readline().strip(\
))
    Tasks = Tasks.split(" ")
    return(Tasks)

def getHostData(conn, cur, Model):
    vcgm = Vcgencmd()
    temp = vcgm.measure_temp()
    volts = vcgm.measure_volts("core")
    cpu = getCPUuse()
    tasks = getTaskNum()

    p = os.popen('free -t')
    i = 0
    while 1:
        i = i + 1
        line = p.readline()
        if i==4:
            totalMemUsage = line.split()[2]
            totalMem = line.split()[1]
            break

    label = Model.predict([[totalMemUsage, temp, tasks[1], volts, cpu]])
    cur.execute("INSERT INTO HOSTDATA (TimeStamp, totalRam, usedRam, cpuPercent, cpuTemp, cpuVolts, totalTasks, runningTasks, sleepingTasks, stoppedTasks, ZombieTasks, mac, label) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (datetime.now(timezone.utc), totalMem, totalMemUsage, cpu, temp, volts, tasks[1], tasks[5],tasks[7],tasks[11],tasks[15], gma(), int(label[0])))
    conn.commit()
    

try:        
    conn = psycopg2.connect(
        host="192.168.0.11",
        database="flare",
        user="postgres",
        password="test123")
        #print("Connection Successfull")
except Exception as e:
    print(e)
        
cur = conn.cursor()
#l = task.LoopingCall(getHostData)
#l.start(5.0)
#reactor.run()
path = os.path.realpath(__file__)
path = path.split("/")
path = path[:-1]
path = "/".join(path)
Model = joblib.load(path+"/HostDataModel.pkl")
try:
    while True:
        start_time = time.time()
        getHostData(conn, cur, Model)
        time.sleep(5-(time.time()-start_time))
except Exception as e:
    print(e)
    cur.close()
    conn.close()
    print("program finished")




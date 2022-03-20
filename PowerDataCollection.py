import asyncio
import time
import socket
import nmap
from kasa import Discover, SmartPlug
from scapy.all import *
import psycopg2
from datetime import datetime
async def getPowerConsumption(ip):
    plug = SmartPlug(ip)
    await plug.update()
    consumption = await plug.current_consumption()
    return consumption

IPList = ["192.168.0.15","192.168.0.18","192.168.0.19","192.168.0.20"]
try:
    conn = psycopg2.connect("dbname='flare' user='postgres' host='192.168.0.25' password='test123'")
    print("Connection Successful")
except Exception as e:
    print("I am unable to connect to the database")
    print(e)
starttime = time.time()
#while True:
    #for i in IPList:
        #print()
while True:
    print(datetime.now())
    for i in IPList:
        consumption = asyncio.run(getPowerConsumption(i))
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Power (IP, TimeStamp, Power) VALUES(%s, %s, %s)", (i, datetime.now(), consumption))
        conn.commit()
        cursor.close()
    time.sleep(5 - ((time.time() - starttime) % 5))
    

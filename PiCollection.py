import asyncio
import time
import socket
import nmap
from kasa import Discover, SmartPlug
from scapy.all import *
import psycopg2
from datetime import datetime
    
def test(pkt):
    try:
        if (pkt[IP].proto == 17 or pkt[IP].proto == 6 or pkt[IP].proto == 1 or pkt[IP].proto == 2):
            #print("*********************************************************************")
            #print(ls(pkt))
            cursor = conn.cursor()
            cursor.execute("INSERT INTO NetworkData (TimeStamp, SMac, DMac, SIp, DIp, sport, dport,TTL, TOS, ID, IHL, DLen, Proto) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (datetime.now(), pkt.src, pkt.dst, pkt[IP].src
                                                                                                                                                                                              , pkt[IP].dst, pkt.sport, pkt.dport ,
                                                                                                                                                                                              pkt[IP].ttl, pkt[IP].tos, pkt[IP].id, pkt[IP].ihl * 4,
                                                                                                                                                                                              pkt[IP].len, pkt[IP].proto))
            conn.commit() 
            cursor.close()
            
    except Exception as e:
        #print(e)
        pass
        
def main():    
    TPLinkAddr = {}   
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
    CameraAddr = []
    nm = nmap.PortScanner(nmap_search_path = nmap_path)
    
    #print("IoT Scan Started")
    for ip in range(255):
        #print('192.168.137.'+str(ip))
        scan_result = nm.scan(hosts='192.168.137.'+str(ip), arguments='-sn --max-retries 2')
        #print(scan_result)
        result = scan_result["scan"]
        #print(result)
        for i in result.keys():     
            try:
                if result[i]["addresses"]["mac"][0:8] == "DC:A6:32":
                    #print(result[i]["addresses"]["mac"])
                    CameraAddr.append(result[i]["addresses"]["ipv4"])
            except:
                pass
    return CameraAddr
    
    
if __name__ == "__main__":
    CameraAddr = main()
    try:
        conn = psycopg2.connect("dbname='flare' user='postgres' host='192.168.0.11' password='test123'")
        #print("Connection Successful")
    except Exception as e:
        quit()
        #print(e)
        #print("I am unable to connect to the database")
        #print(e)
    #time.sleep(60)
    #CamAddress = list(Links.keys())
    #print("host {}".format(CameraAddr[0]))
    sniff(session=NetflowSession, iface = r"\Device\NPF_{ed755a3b-0df2-4cc4-8242-d1a996dc6d49}", filter=("host {}".format(CameraAddr[0])), prn=test)
    

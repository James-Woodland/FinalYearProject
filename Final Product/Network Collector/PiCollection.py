import asyncio
import time
import socket
import nmap
import requests
from kasa import Discover, SmartPlug
from scapy.all import *
import psycopg2
from datetime import datetime, timezone
import joblib
import sklearn
from grafana_api.grafana_face import GrafanaFace
import json

"""
Function for processing packets once they've been captured
Check what the communication types is, extracts the needed features and predicts whther the oacket is malicious or not
It then stores the packet info and its label in the database. 
"""
def packetProcessing(pkt):
    try:
        if (pkt[IP].proto == 17 or pkt[IP].proto == 6):            
            if "192.168" in pkt[IP].src and "192.168" in pkt[IP].dst:
                internal = 1
            else:
                internal = 0
            features = [[pkt.sport, pkt.dport, internal]]
            features = Scaler.transform(features)
            label = Model.predict(features)            
            cursor = conn.cursor()
            cursor.execute("INSERT INTO NetworkData (TimeStamp, SMac, DMac, SIp, DIp, sport, dport,TTL, TOS, ID, IHL, DLen, Proto, label) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (datetime.now(timezone.utc), pkt.src, pkt.dst, pkt[IP].src
                                                                                                                                                                                              , pkt[IP].dst, pkt.sport, pkt.dport ,
                                                                                                                                                                                              pkt[IP].ttl, pkt[IP].tos, pkt[IP].id, pkt[IP].ihl * 4,
                                                                                                                                                                                              pkt[IP].len, pkt[IP].proto, int(label[0])))
            conn.commit() 
            cursor.close()
            
    except Exception as e:
        print(e)
        pass

"""
Performs the initial device scan
If a fullscan is requested every ip in the range is checked
If a fullscan is not needed and IPs are supplied it will only scan for the given IPs
The MAC address, IP Address and the vendor the MAC belongs to is recorded and returned 
"""
        
def deviceScan(fullScan):      
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
    IPAddr = []
    MACAddr = []
    Vendors = []
    nm = nmap.PortScanner(nmap_search_path = nmap_path)
    if fullScan == True:              
        for ip in range(256):
            scan_result = nm.scan(hosts='192.168.137.'+str(ip), arguments='-sn --max-retries 2')
            result = scan_result["scan"]
            for i in result.keys():     
                try:
                    if result[i]["addresses"]["mac"][0:8] in setup["ScanningSettings"]["OUIs"].keys():
                                            IPAddr.append(result[i]["addresses"]["ipv4"])
                        MACAddr.append(result[i]["addresses"]["mac"])
                        Vendors.append(result[i]["vendor"][result[i]["addresses"]["mac"]])                        
                except:
                    pass
        return IPAddr, MACAddr, Vendors
    elif fullScan == False:        
        IPList = setup["ScanningSettings"]["DeviceIPs"]        
        for ip in IPList:            
            scan_result = nm.scan(hosts=ip, arguments='-sn')
            print(scan_result)
            result = scan_result["scan"]            
            for i in result.keys():     
                try:
                    if result[i]["addresses"]["mac"][0:8] in setup["ScanningSettings"]["OUIs"].keys():                        
                        IPAddr.append(result[i]["addresses"]["ipv4"])
                        MACAddr.append(result[i]["addresses"]["mac"])
                        Vendors.append(result[i]["vendor"][result[i]["addresses"]["mac"]])                        
                except Exception as e:                  
                    pass
        return IPAddr, MACAddr, Vendors

"""
Used to generate the data source in grafana using the grafana API
After creating the data source it quries it
This is done as a data source can only be used once it's been verified, which can be done by querying it from Grafana
"""
def datasourceGenerator(dbname, dbip, dbport, password, user, grafanaApi, grafanaip, grafanaport):
    query = {
  "from": "1420066800000",
  "to": "1575845999999",
  "queries": [
    {
      "refId": "A",
      "intervalMs": 86400000,
      "maxDataPoints": 1092,
      "datasourceId": 19,
      "rawSql": "SELECT 1 as valueOne, 2 as valueTwo",
      "format": "table"
    }
  ]
}
    DatasourceJson =   {
          "name": dbname,
          "type":"postgres",
          "url": "{}:{}".format(dbip, dbport),
          "database": dbname,
          "user": user,
          "access": "proxy",         
          "isDefault": True,
          "version": 7,
          "secureJsonData":{
          "password": password
          },
          "jsonData":{
            "sslmode": "disable"
          }
        }
    
    try:
        r = grafanaApi.datasource.create_datasource(DatasourceJson)
        r = grafanaApi.datasource.get_datasource_by_name(dbname)               
        query["queries"][0]["datasourceId"] = r["id"]
        response = requests.post("http://{}:{}/api/tsdb/query".format(grafanaip, grafanaport), data = query)  
    except Exception as e:
        
        pass
"""
Generates dashboards based off of the Dashboard.json included in the same directory
changes the json so that the queries now pull data for the device the dashboard is associated to
Also tags the dashboard as to make it easier to identify what the IP relates to  

"""

def dashboardGenerator(mac, ip, vendor, grafanaApi):    
    f = open("Dashboard.json")
    panels = json.load(f)
    for i in range(len(mac)):
        panelStr = json.dumps(panels)    

        panelStr = panelStr.replace('dc:a6:32:98:ef:c7', mac[i].lower())
        panelStr = panelStr.replace('192.168.137.196', ip[i])    
        panels = json.loads(panelStr)
        myDashboard = {'id': None, 'uid': None, 'title': ip[i], 'tags': [vendor[i]],"time": {
        "from": "now-5m",
        "to": "now"
      }, 'timezone': 'browser', "panels": panels,'schemaVersion': 0, 'version': 0, "graphTooltip": 1, "refresh":"5s"}
        r = grafanaApi.dashboard.update_dashboard({'dashboard': myDashboard, 'overwrite': True, 'isStarred': True})

"""
Starts the sniffer on the configured interface
applys a filter so that it only collects packets relating to hosts that were found during the scan
"""
def sniffer():
    sniff(session=NetflowSession, iface = r"\Device\NPF_{}".format(setup["NetworkInterface"]), filter=(hostFilter), prn=packetProcessing)
    

"""
Main, used primarily to call all the different functions
Loads config file srettings in
sets up the initial grafana api client
Loads in the model and scaler
sets up the connection between the script and the database
generates the host filter to be used when sniffing

"""
if __name__ == "__main__":
    f = open("Config.json")
    setup = json.load(f)
    GrafanaKey = setup["Grafana"]["APIKey"]
    grafanaip = "localhost"
    grafanaport = "3000"
    dbname = "pulse"
    user = "postgres"
    dbip = "localhost"
    dbport = "5432"  
    password = setup["Database"]["postgresPassword"]
    fullScan = setup["ScanningSettings"]["Enabled"]
    grafanaApi = GrafanaFace(auth=GrafanaKey, host='{}:{}'.format(grafanaip, grafanaport))
    IPAddr, MACAddr, Vendors = deviceScan(fullScan)
    datasourceGenerator(dbname, dbip, dbport, password, user, grafanaApi, grafanaip, grafanaport)
    r = grafanaApi.search.search_dashboards()
    for i in r:        
        try:
            grafanaApi.dashboard.delete_dashboard(i["uid"])
        except:
            pass    
    dashboardGenerator(MACAddr, IPAddr, Vendors, grafanaApi)
    Model = joblib.load("Model.pkl")
    Scaler = joblib.load("Scaler.pkl")
    try:
        conn = psycopg2.connect("dbname='{}' user='{}' host=\'{}\' password='{}'".format(dbname, user, dbip, password))
    except Exception as e:
        print(e)
        quit()
    
        
    if len(IPAddr) < 1:
        print("No devices have been found")
        quit()
    else:
        hostFilter = "host {}".format(IPAddr[0])
        IPAddr.remove(IPAddr[0])
        if len(IPAddr) >= 1:
            for ip in IPAddr:
                hostFilter = hostFilter + " or {}".format(ip)
    print(hostFilter)
    sniffer()
    
    

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
    
def test(pkt):
    try:
        if (pkt[IP].proto == 17 or pkt[IP].proto == 6):
            ports = [[pkt.sport, pkt.dport]]
            ports = Scaler.transform(ports)
            label = Model.predict(ports)
            #print([pkt.sport, pkt.dport])
            #print(label)
            #print(label[0])
            #print("*********************************************************************")
            #print(ls(pkt))
            cursor = conn.cursor()
            cursor.execute("INSERT INTO NetworkData (TimeStamp, SMac, DMac, SIp, DIp, sport, dport,TTL, TOS, ID, IHL, DLen, Proto, label) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (datetime.now(timezone.utc), pkt.src, pkt.dst, pkt[IP].src
                                                                                                                                                                                              , pkt[IP].dst, pkt.sport, pkt.dport ,
                                                                                                                                                                                              pkt[IP].ttl, pkt[IP].tos, pkt[IP].id, pkt[IP].ihl * 4,
                                                                                                                                                                                              pkt[IP].len, pkt[IP].proto, int(label[0])))
            conn.commit() 
            cursor.close()
            
    except Exception as e:
        #ls(pkt)
        #print(e)
        pass
        
def main(GrafanaKey, fullScan):      
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
    IPAddr = []
    MACAddr = []
    Vendors = []
    nm = nmap.PortScanner(nmap_search_path = nmap_path)
    if fullScan == True:        
        #print("IoT Scan Started")        
        for ip in range(256):
            #print('192.168.137.'+str(ip))
            scan_result = nm.scan(hosts='192.168.137.'+str(ip), arguments='-sn --max-retries 2')
            #print(scan_result)
            result = scan_result["scan"]
            #print(result)
            for i in result.keys():     
                try:
                    if result[i]["addresses"]["mac"][0:8] in setup["ScanningSettings"]["OUIs"].keys():
                        #print(result[i]["addresses"]["mac"])
                        IPAddr.append(result[i]["addresses"]["ipv4"])
                        MACAddr.append(result[i]["addresses"]["mac"])
                        Vendors.append(result[i]["vendor"][result[i]["addresses"]["mac"]])
                        #print(result[i]["vendor"][result[i]["addresses"]["mac"]])
                except:
                    pass
        return IPAddr, MACAddr, Vendors
    elif fullScan == False:        
        IPList = setup["ScanningSettings"]["DeviceIPs"]        
        for ip in IPList:
            #print('192.168.137.'+str(ip))
            scan_result = nm.scan(hosts=ip, arguments='-sn --max-retries 2')
            #print(scan_result)
            result = scan_result["scan"]
            #print(setup["ScanningSettings"]["OUIs"].keys())
            #print(result)
            for i in result.keys():     
                try:
                    if result[i]["addresses"]["mac"][0:8] in setup["ScanningSettings"]["OUIs"].keys():
                        #print(result[i]["addresses"]["mac"])
                        IPAddr.append(result[i]["addresses"]["ipv4"])
                        MACAddr.append(result[i]["addresses"]["mac"])
                        Vendors.append(result[i]["vendor"][result[i]["addresses"]["mac"]])
                        #print(result[i]["vendor"][result[i]["addresses"]["mac"]])
                except Exception as e:
                    #print(e)
                    pass
        return IPAddr, MACAddr, Vendors

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
    #creates a new data source, if it already exists and error is thrown
    try:
        r = grafanaApi.datasource.create_datasource(DatasourceJson)
        r = grafanaApi.datasource.get_datasource_by_name(dbname)               
        query["queries"][0]["datasourceId"] = r["id"]
        response = requests.post("http://{}:{}/api/tsdb/query".format(grafanaip, grafanaport), data = query)  
    except Exception as e:
        #print(e)
        pass

def dashboardGenerator(mac, ip, vendor, grafanaApi):
    f = open("Dashboard.json")
    panels = json.load(f)
    panelStr = json.dumps(panels)
    #Update Base Dashboard for the Specific Device
    newPanelStr = panelStr.replace('dc:a6:32:98:ef:c7', mac.lower())
    panels = json.loads(newPanelStr)
    myDashboard = {'id': None, 'uid': None, 'title': ip, 'tags': [vendor],"time": {
    "from": "now-5m",
    "to": "now"
  }, 'timezone': 'browser', "panels": panels,'schemaVersion': 0, 'version': 0, "graphTooltip": 1}
    r = grafanaApi.dashboard.update_dashboard({'dashboard': myDashboard, 'overwrite': True, 'isStarred': False})
    
    
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
    IPAddr, MACAddr, Vendors = main(GrafanaKey, fullScan)
    datasourceGenerator(dbname, dbip, dbport, password, user, grafanaApi, grafanaip, grafanaport)
    for i in range(len(IPAddr)):
        dashboardGenerator(MACAddr[i], IPAddr[i], Vendors[i], grafanaApi)
    Model = joblib.load("../AI Development/StackingPort.pkl")
    Scaler = joblib.load("PortScaler.pkl")
    try:
        conn = psycopg2.connect("dbname='{}' user='{}' host=\'{}\' password='{}'".format(dbname, user, dbip, password))
        #print("Connection Successful")
    except Exception as e:
        print(e)
        quit()
    
        #print(e)
        #print("I am unable to connect to the database")
        #print(e)
    #time.sleep(60)
    #CamAddress = list(Links.keys())
    #print("host {}".format(CameraAddr[0]))
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
    sniff(session=NetflowSession, iface = r"\Device\NPF_{}".format(setup["NetworkInterface"]), filter=(hostFilter), prn=test)
    

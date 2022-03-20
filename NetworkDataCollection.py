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
    
def test(pkt):
    print(ls(pkt))
    try:
        #UDP
        if pkt[IP].proto == 17:
            
            cursor = conn.cursor()
            cursor.execute("INSERT INTO udponly (TimeStamp, SMac, DMac, SIp, DIp, SPort, DPort, TTL, TOS, ID, IHL, DLen, Proto) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (datetime.now(), pkt.src, pkt.dst, pkt[IP].src
                                                                                                                                                                                              , pkt[IP].dst, pkt[IP].sport, pkt[IP].dport,
                                                                                                                                                                                              pkt[IP].ttl, pkt[IP].tos, pkt[IP].id, pkt[IP].ihl * 4,
                                                                                                                                                                                              pkt[IP].len, pkt[IP].proto))
            conn.commit()
            cursor.close()
                
        #TCP
        elif pkt[IP].proto == 6:
                
            
                
            cursor = conn.cursor()
            cursor.execute("INSERT INTO tcponly (TimeStamp, SMac, DMac, SIp, DIp, SPort, DPort, TTL, TOS, ID, IHL, DLen, Proto) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (datetime.now(), pkt.src, pkt.dst, pkt[IP].src
                                                                                                                                                                                              , pkt[IP].dst, pkt[IP].sport, pkt[IP].dport,
                                                                                                                                                                                              pkt[IP].ttl, pkt[IP].tos, pkt[IP].id, pkt[IP].ihl * 4,
                                                                                                                                                                                              pkt[IP].len, pkt[IP].proto))
            conn.commit()
            cursor.close()
                
        #IGMP
        elif pkt[IP].proto == 2:
               
           
                

            cursor = conn.cursor()
            cursor.execute("INSERT INTO igmponly (TimeStamp, SMac, DMac, SIp, DIp, TTL, TOS, ID, IHL, DLen, Proto) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (datetime.now(), pkt.src, pkt.dst, pkt[IP].src
                                                                                                                                                                                              , pkt[IP].dst, 
                                                                                                                                                                                              pkt[IP].ttl, pkt[IP].tos, pkt[IP].id, pkt[IP].ihl * 4,
                                                                                                                                                                                              pkt[IP].len, pkt[IP].proto))
            conn.commit() 
            cursor.close()
                
        else:
            print(ls(pkt))
            print("Source MAC: " + pkt.src)
            print("Destination MAC: " +pkt.dst)
            print("Source IP: " +pkt[IP].src)
            print("Destination IP: " +pkt[IP].dst)
            #print("Source Port: " +str(pkt.sport)
            print("Destination Port: " +str(pkt.dport))
            print("TTL: " +str(pkt[IP].ttl))
            print("TOS: " +str(pkt[IP].tos))
            print("ID: " +str(pkt[IP].id))
            print("IP Header Length: " +str(pkt[IP].ihl * 4))
            print("Datagram Length: " +str(pkt[IP].len))        
            print("Protocol: " + str(pkt[IP].proto))            
            test = input()
            #print("Source MAC: " +pkt.sniffed_on)
    except Exception  as e:
        if hasattr(pkt, "hwdst"):
            #ARP
            cursor = conn.cursor()
            cursor.execute("INSERT INTO arponly (TimeStamp, SMac, DMac, hwsrc, hwdst, PSrc, PDst) VALUES(%s, %s, %s, %s, %s, %s, %s)", (datetime.now(), pkt.src, pkt.dst, pkt.hwsrc,
                                                                                                                                               pkt.hwdst, pkt.pdst, pkt.psrc))
            conn.commit()
            cursor.close()
                
        else:
            print(ls(pkt))
            print(e)
            test = input()
async def main():
    #print("Packet")
    #devices = await Discover.discover()
    #print(devices)
    TPLinkAddr = {}
    #for addr, dev in devices.items():
        #plug = SmartPlug(addr)
        #asyncio.run(plug.current_consumption())
        #TPLinkAddr[addr] = ""
    #quit()
    #print(TPLinkAddr) 
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
    CameraAddr = {}
    nm = nmap.PortScanner(nmap_search_path = nmap_path)
    #nm = nmap.PortScanner()
    #scan_result = nm.scan(hosts='192.168.0.0-255', arguments='-p80 --max-retries 0 --noninteractive -v')
    #result = scan_result["scan"]
    #print(result)
    print("Smart Plug Scan Started")
    #for i in TPLinkAddr.keys():
        #scan_result = nm.scan(hosts=i, arguments='-p 80 --max-retries 2 --noninteractive')
        #result = scan_result["scan"]
        #print(result)
        #for i in result.keys():     
            #if result[i]["addresses"]["ipv4"] in TPLinkAddr.keys():            
                #TPLinkAddr[result[i]["addresses"]["ipv4"]] = result[i]["addresses"]["mac"]
    #scan_result = nm.scan(hosts='192.168.0.19', arguments='-v')
    #print(scan_result["scan"])
    #quit()
    #print(TPLinkAddr)
    for ip in range(254):        
        #found_devices = await Discover.discover(target = '192.168.0.'+str(ip), discovery_packets=3, timeout = 1)
        print('192.168.0.'+str(ip))
        #print(found_devices)
        scan_result = nm.scan(hosts='192.168.0.'+str(ip), arguments='-p9999 --max-retries 3 --noninteractive --host-timeout 5')
        result = scan_result["scan"]
        print(result)
        #if len(found_devices) != 0:
            #TPLinkAddr[list(found_devices.keys())[0]] = ""       
        for i in result.keys():     
            try:
                MacStart = result[i]["addresses"]["mac"][0:8]
                if MacStart == "C0:06:C3":
                    print(result[i]["addresses"]["mac"])
                    TPLinkAddr[list(result.keys())[0]] = ""
                    print(TPLinkAddr)
            except Exception as e:
                print("pass")
                print(e)
        if len(TPLinkAddr) == 4:
            break
    print(TPLinkAddr)
    if len(TPLinkAddr) != 4:
        print("Not enough smart plugs found going to default list")
        TPLinkAddr = {'192.168.0.15': '', '192.168.0.18': '', '192.168.0.19': '', '192.168.0.20': ''}
        
    #scan_result = nm.scan(hosts='192.168.137.0-255', arguments='-p80 --max-retries 0 --noninteractive -v')
    #result = scan_result["scan"]
    #print(result)
    #quit()
    print("IoT Scan Started")
    for ip in range(256):
        print('192.168.137.'+str(ip))
        scan_result = nm.scan(hosts='192.168.137.'+str(ip), arguments='-p80 --max-retries 3 --noninteractive --host-timeout 5')
        result = scan_result["scan"]
        print(result)
        for i in result.keys():     
            try:
                if result[i]["addresses"]["mac"][0:8] == "60:1D:9D":
                    #print(result[i]["addresses"]["mac"])
                    CameraAddr[result[i]["addresses"]["ipv4"]] = result[i]["addresses"]["mac"]
            except:
                pass                 
        if len(CameraAddr) == 4:
            break
    print(CameraAddr)
    if len(CameraAddr) != 4:
        print("Not enough Cameras found going to default list")
        #CameraAddr = 
        quit()
    Links = {}
    count = 1
    for i in TPLinkAddr.keys():
        LostIP = ""
        plug = SmartPlug(i)
        await plug.turn_off()
        time.sleep(5)
        LostIP = None
        for j in CameraAddr.keys():
            #print(j)       
            scanner = nmap.PortScanner(nmap_search_path = nmap_path)
            host = socket.gethostbyname(j)
            scanner.scan(host, '1', '-v')
            #print("IP Status: ", scanner[host].state())        
            if scanner[host].state() == "down":
                print(CameraAddr[j])
                print("IP Status: ", scanner[host].state()) 
                LostIP = j
                #Links["Camera {}".format(count)] = {}
                #Links["Camera {}".format(count)]["TPLinkMac"] = TPLinkAddr[i]
                #Links["Camera {}".format(count)]["TPLinkIP"] = i
                #Links["Camera {}".format(count)]["CameraLinkMac"] = CameraAddr[j]
                #Links["Camera {}".format(count)]["CameraLinkIP"] = j
                Links[j] = i
                p = SmartPlug(i)
                await p.turn_on()
        try:
            CameraAddr.pop(LostIP)
        except Exception as e:
            print(e)
            pass
        count = count + 1
    print(Links)
    return Links
    
if __name__ == "__main__":
    Links = asyncio.run(main())   
    try:
        conn = psycopg2.connect("dbname='flare' user='postgres' host='192.168.0.25' password='test123'")
        print("Connection Successful")
    except Exception as e:
        print("I am unable to connect to the database")
        print(e)
    #time.sleep(60)
    CamAddress = list(Links.keys())
    print("host {} or host {} or host {} or host {}".format(CamAddress[0],CamAddress[1],CamAddress[2],CamAddress[3]))
    sniff(iface = r"\Device\NPF_{0c1ad16d-601a-492a-9c09-9daf61adafd6}", filter=("host {} or host {} or host {} or host {}".format(CamAddress[0],CamAddress[1],CamAddress[2],CamAddress[3])), prn=test)
    

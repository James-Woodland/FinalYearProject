import asyncio
import time
import socket
import nmap
from kasa import Discover, SmartPlug

async def main():
    devices = await Discover.discover()

    TPLinkAddr = {}
    for addr, dev in devices.items():
        #plug = SmartPlug(addr)
        #asyncio.run(plug.current_consumption())
        TPLinkAddr[addr] = ""
    #quit()
    #print(TPLinkAddr) 
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]
    CameraAddr = {}
    nm = nmap.PortScanner(nmap_search_path = nmap_path)
    #nm = nmap.PortScanner()
    #scan_result = nm.scan(hosts='192.168.0.0-255', arguments='-p80 --max-retries 0 --noninteractive -v')
    #result = scan_result["scan"]
    #print(result)
    print("scan started")
    for i in TPLinkAddr.keys():
        scan_result = nm.scan(hosts=i, arguments='-p 80 --max-retries 0 --noninteractive')
        result = scan_result["scan"]
        #print(result)
        for i in result.keys():     
            if result[i]["addresses"]["ipv4"] in TPLinkAddr.keys():            
                TPLinkAddr[result[i]["addresses"]["ipv4"]] = result[i]["addresses"]["mac"]
    print(TPLinkAddr)

    #scan_result = nm.scan(hosts='192.168.137.0-255', arguments='-p80 --max-retries 0 --noninteractive -v')
    #result = scan_result["scan"]
    #print(result)
    #quit()
    for ip in range(256):
        #print(ip)
        scan_result = nm.scan(hosts='192.168.137.'+str(ip), arguments='-p80 --max-retries 0 --noninteractive')
        result = scan_result["scan"]
        #print(result)
        for i in result.keys():     
            try:
                if result[i]["addresses"]["mac"][0:8] == "60:1D:9D":
                    #print(result[i]["addresses"]["mac"])
                    CameraAddr[result[i]["addresses"]["ipv4"]] = result[i]["addresses"]["mac"]
            except:
                pass                 

    print(CameraAddr)

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


if __name__ == "__main__":
    asyncio.run(main())

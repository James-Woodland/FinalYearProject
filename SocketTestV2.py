from scapy.all import *
import psycopg2
def test(pkt):
    try:
        #UDP
        if pkt[IP].proto == 17:
            print(ls(pkt))
            print("Source MAC: " + pkt.src)
            print("Destination MAC: " +pkt.dst)
            print("Source IP: " +pkt[IP].src)
            print("Destination IP: " +pkt[IP].dst)
            print("Source Port: " +str(pkt.sport))
            print("Destination Port: " +str(pkt.dport))
            print("TTL: " +str(pkt[IP].ttl))
            print("TOS: " +str(pkt[IP].tos))
            print("ID: " +str(pkt[IP].id))
            print("IP Header Length: " +str(pkt[IP].ihl * 4))
            print("Datagram Length: " +str(pkt[IP].len))        
            print("Protocol: " + str(pkt[IP].proto))
        #TCP
        elif pkt[IP].proto == 6:
            print(ls(pkt))
            print("Source MAC: " + pkt.src)
            print("Destination MAC: " +pkt.dst)
            print("Source IP: " +pkt[IP].src)
            print("Destination IP: " +pkt[IP].dst)
            print("Source Port: " +str(pkt.sport))
            print("Destination Port: " +str(pkt.dport))
            print("TTL: " +str(pkt[IP].ttl))
            print("TOS: " +str(pkt[IP].tos))
            print("ID: " +str(pkt[IP].id))
            print("IP Header Length: " +str(pkt[IP].ihl * 4))
            print("Datagram Length: " +str(pkt[IP].len))        
            print("Protocol: " + str(pkt[IP].proto))
        #IGMP
        elif pkt[IP].proto == 2:
            print(ls(pkt))
            print("Source MAC: " + pkt.src)
            print("Destination MAC: " +pkt.dst)
            print("Source IP: " +pkt[IP].src)
            print("Destination IP: " +pkt[IP].dst)
            print("TTL: " +str(pkt[IP].ttl))
            print("TOS: " +str(pkt[IP].tos))
            print("ID: " +str(pkt[IP].id))
            print("IP Header Length: " +str(pkt[IP].ihl * 4))
            print("Datagram Length: " +str(pkt[IP].len))        
            print("Protocol: " + str(pkt[IP].proto))            
        else:
            print(ls(pkt))
            print("Source MAC: " + pkt.src)
            print("Destination MAC: " +pkt.dst)
            print("Source IP: " +pkt[IP].src)
            print("Destination IP: " +pkt[IP].dst)
            print("Source Port: " +str(pkt.sport))
            print("Destination Port: " +str(pkt.dport))
            print("TTL: " +str(pkt[IP].ttl))
            print("TOS: " +str(pkt[IP].tos))
            print("ID: " +str(pkt[IP].id))
            print("IP Header Length: " +str(pkt[IP].ihl * 4))
            print("Datagram Length: " +str(pkt[IP].len))        
            print("Protocol: " + str(pkt[IP].proto))            
            test = input()
        #print("Source MAC: " +pkt.sniffed_on)
    except:
        if hasattr(pkt, "hwdst"):
            #ARP
            print(ls(pkt))
            print(pkt.src)
            print(pkt.dst)
            print(pkt.hwsrc)
            print(pkt.hwdst)
            print(pkt.pdst)
            print(pkt.psrc)
        else:
            print(ls(pkt))
            test = input()
try:
    conn = psycopg2.connect("dbname='flare' user='postgres' host='192.168.0.25' password='Crimson1712!'")
except Exception as e:
    print("I am unable to connect to the database")
    print(e)
sniff(iface = r"\Device\NPF_{cbc3b2d4-0a4c-4b41-9b38-cc4c73b82309}", filter=("host 192.168.137.165 or host 192.168.137.17 or host 192.168.137.124 or host 192.168.137.155"), prn=test)

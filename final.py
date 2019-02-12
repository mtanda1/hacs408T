import netifaces
from netaddr import *
import netaddr
import threading
import socket
from time import sleep
import struct
import json
#import sys

#reload(sys)
#sys.setdefaultencoding('utf8')


listip = []
activeMacIp = []
def findinterface():
    interfaces = netifaces.interfaces()
    for interface in interfaces:

        if(interface != 'lo'):
            addrs = netifaces.ifaddresses(interface)
            lib = addrs[netifaces.AF_INET]

            for dictionary in lib:
                #print(dictionary)
                cidr = IPAddress(dictionary["netmask"]).netmask_bits()#returns subnet cidr
                cidrip=("%s/%s" % (dictionary["addr"],cidr))
                #print(cidrip)
                iplist(interface, cidrip)
                

#after I find IP, I need to convert the subnetmask to size and add to gateway
def iplist(interface, cidrip):
    for ip in IPNetwork(cidrip):
        #print(ip)
        tup = (interface,struct.pack('!I',int(hex(ip),16)))
        #print(tup)
        listip.append(tup)

findinterface()

def arpscan(sock,sender_ip,sender_mac,target_ip):
    #print(struct.unpack('!I',target_ip))
    #print("sending data to %s" % (target_ip))
    broadcast_mac = "\xff\xff\xff\xff\xff\xff" #change this to all ff after
    sender_mac = sender_mac#"\x52\x54\x00\x1e\x33\x45" #sender_mac
    #ethernet header
    ethernet_header = broadcast_mac #Destination Mac
    ethernet_header += sender_mac #source MAC
    ethernet_header += "\x08\x06" # ARP Type: 0x0806
    #build arp packet
    arp_data = "\x00\x01" #Ethernet type
    arp_data += "\x08\x00" #IP Protocol
    arp_data += "\x06" #addr length
    arp_data += "\x04" #prot addr length
    arp_data += "\x00\x01" #operation = request
    arp_data += sender_mac #sender hardware address (my mac address)
    arp_data += sender_ip # "\x0a\x02\x00\x81"#sender protocol address (my ip address-> this has to be done  
    arp_data += "\x00\x00\x00\x00\x00\x00" #\x52\x54\x00\x18\xfa\xfa" #target hardware address set to all 0
    arp_data += target_ip #"\x0a\x02\x00\x82" #target IP increment based on subnet and IP

    #finish arp packet here
    frame = ethernet_header + arp_data
    #create raw socket
    
    sock.sendall(frame)
    
def rec(sock,target_ip):
    try:
        byte = sock.recvfrom(20000)
        resp = struct.unpack('!6s6sHHHBBH6s6s6s6s',byte[0][0:46])
        if(resp[2]==2054 and resp[7]==2):
            
            tupl=(resp[0],struct.unpack('!I',target_ip))
            #print(tupl)
            activeMacIp.append(tupl)
    except:
        pass

s=netifaces.ifaddresses('eth0')[netifaces.AF_LINK][0]['addr']

for tupl in listip:

    sender_ip=IPAddress(netifaces.ifaddresses(tupl[0])[2][0]['addr'])
    sender_ip=int(hex(sender_ip),16)
    sender_ip=struct.pack('!I',sender_ip)
    target_ip=tupl[1]
   
    sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW, socket.htons(3))
    sock.bind((tupl[0],0))
    sender_mac=sock.getsockname()[4]
    sock.settimeout(.5)

    t = threading.Thread(target = rec, args=(sock,target_ip))
    t2 = threading.Thread(target = arpscan, args=(sock,sender_ip,sender_mac,target_ip))

    try:
        t.start()
        t2.start()
        t.join()
        t2.join() 
        sock.close()
    except:
        pass
#
#port scanner

activeports = []
#activeMacIp.append(('eth0',"RT\\x00\\x1e3E", (167903362,)))
def portscanner():
    for ip in activeMacIp:
        #print str(ip[1])

        print(str(IPAddress(ip[1][0])))
        #print("Mac address in bytes: %s") % (activeMacIp[0])
        #print("%x:%x:%x:%x:%x:%x" % struct.unpack('BBBBBB', activeMacIp[0]))
        # print(activeMacIp[0][0])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #print(sock.connect((str(IPAddress(ip[1][0])),8000)))
        #byte = sock.recvfrom(20000)
        sock.close()
        for port in range(1,65535):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                is_active=sock.connect((str(IPAddress(ip[1][0])),port))
                #print(port)
                #print(str(is_active))
                if(str(is_active)=="None"):
                    #print(port)
                    sock.sendall("GET / HTTP/1.1\r\n\r\n")
                    byte = sock.recvfrom(20000)
                    #print(byte)
                    if("SSH"in byte[0]):
                        print("port %s : SSH") % (port)
                    elif("SMTP" in byte[0].upper()):
                        print("port %s : SMTP") % (port)
                    elif("\xff" in byte[0]):
                        print("port %s : telnet") % (port)
                    elif("FTP"in byte[0]):
                        print("port %s : FTP server") % (port)
                    elif(str(byte[0])=="HTTP/1.0\n"):
                        print("port %s : echo server") % (port)
                    elif("HTTP/1.0 200 OK" in str(byte[0])):
                        print("port %s : HTTP") % (port)
                    else:
                        print("port %s : other")  % (port)
                sock.close()
                    #print(type(str(byte[0])))
                    #print(s)
            except:
                sock.close()
        print(' ')
portscanner()

#scan={"machines":''}
#interfacesdict = {}
#interfacesdict[] = {}
#scan['machines'] = interfacesdict





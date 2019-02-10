import netifaces
from netaddr import *
import netaddr
import threading
import socket
from time import sleep
import struct
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
                print(cidrip)
                iplist(interface, cidrip)
                

#after I find IP, I need to convert the subnetmask to size and add to gateway
def iplist(interface, cidrip):
    for ip in IPNetwork(cidrip):
        tup = (interface,struct.pack('!I',int(hex(ip),16)))
        listip.append(tup)

findinterface()

def arpscan(sock,sender_ip,sender_mac,target_ip):
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
    
    byte = sock.recvfrom(20000)
    resp = struct.unpack('!6s6sHHHBBH6s6s6s6s',byte[0][0:46])
    if(resp[2]==2054 and resp[7]==2):
        
        tupl=(resp[0],struct.unpack('!I',target_ip))
        
        activeMacIp.append(tupl)

s=netifaces.ifaddresses('eth0')[netifaces.AF_LINK][0]['addr']

for tupl in listip:

    sender_ip=IPAddress(netifaces.ifaddresses(tupl[0])[2][0]['addr'])
    sender_ip=int(hex(sender_ip),16)
    sender_ip=struct.pack('!I',sender_ip)
    target_ip=tupl[1]
   
    sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW, socket.htons(3))
    sock.bind((tupl[0],0))
    sender_mac=sock.getsockname()[4]

    t = threading.Thread(target = rec, args=(sock,target_ip))
    t2 = threading.Thread(target = arpscan, args=(sock,sender_ip,sender_mac,target_ip))

    t.start()
    t2.start()
    t.join()
    t2.join() 
    sock.close()


#
#get ports

#for ip in activeMacIp:
#    print ip
#    sock = socket
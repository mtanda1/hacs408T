import netifaces
from netaddr import *
import netaddr
import threading
import socket
from time import sleep
import struct

listip = []
def findinterface():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
    #print(interface)
        if(interface != 'lo'):
            addrs = netifaces.ifaddresses(interface)
            #print interface
#addrs = netifaces.ifaddresses('lo')
            lib = addrs[netifaces.AF_INET]
  # print(addrs[netifaces.AF_INET])
            for dictionary in lib:

                #print(dictionary)
                cidr = IPAddress(dictionary["netmask"]).netmask_bits()#returns subnet cidr

                cidrip=("%s/%s" % (dictionary["addr"],cidr))
                print(cidrip)
                iplist(interface, cidrip)
                #for data in dictionary:
                    #print(data)
                    #print(IPNetwork(dictionary[data]))
           # if (data2 ==
            # print(data2)
           
#print(netifaces.gateways())

#after I find IP, I need to convert the subnetmask to size and add to gateway
def iplist(interface, cidrip):
    for ip in IPNetwork(cidrip):
        tup = (interface,struct.pack('!I',int(int(hex(ip),16))))
        listip.append(tup)
        print(tup)
#iplist()
#ip = IPNetwork('192.0.2.0/23')
#print(ip.netmask)

findinterface()

#for ip in listip:
 #   print(ip)
    #print(obj)
#print("\x52\x54\x00\x87\xcd\xd4")

def arpscan(sock,sender_ip,sender_mac,target_ip):
    broadcast_mac = "\x52\x54\x00\x18\xfa\xfa"
    spoof_mac = "\x52\x54\x00\x87\xcd\xd4"
    #ethernet header
    ethernet_header = broadcast_mac #Destination Mac
    ethernet_header += spoof_mac #source MAC
    ethernet_header += "\x08\x06" # ARP Type: 0x0806
    #build arp packet
    arp_data = "\x00\x01" #Ethernet type
    arp_data += "\x08\x00" #IP Protocol
    arp_data += "\x06" #addr length
    arp_data += "\x04" #prot addr length
    arp_data += "\x00\x01" #operation = request
    arp_data += "\x52\x54\x00\x87\xcd\xd4" #sender hardware address (my mac address)
    arp_data += "\xac\x1e\x00\x17" #sender protocol address (my ip address-> this has to be done  
    arp_data += "\x00\x00\x00\x00\x00\x00" #\x52\x54\x00\x18\xfa\xfa" #target hardware address set to all 0
    arp_data += "\xac\x1e\x00\x70" #target IP increment based on subnet and IP


    #finish arp packet here
    frame = ethernet_header + arp_data
    #create raw socket
    

    sock.sendall(frame)
    print("sent data")
    

def rec(sock):
    #print("in rec")
    byte = sock.recvfrom(20000)
    #print(byte)
    #print(byte[1][4])
    #print(len(byte[1][4]))
    numb="B"*len(byte[1][4])
    print(struct.unpack(numb,byte[1][4]))
    #print("red term")

sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW, socket.htons(3))
sock.bind(('eth0',0))
#print("socket bound")
t = threading.Thread(target = rec, args=(sock,))
t2 = threading.Thread(target = arpscan, args=(sock,))


#t.start()
#t2.start()
#t.join()
#t2.join() 
#sock.close()


#
#get tcp 


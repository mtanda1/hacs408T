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
        tup = (interface,struct.pack('!I',int(hex(ip),16)))
        #tup = (interface,socket.inet_aton(str(ip)))
        listip.append(tup)
        #print(socket.inet_aton(str(ip)))
        #print(tup[1])
#iplist()
#ip = IPNetwork('192.0.2.0/23')
#print(ip.netmask)

findinterface()

#for ip in listip:
 #   print(ip)
    #print(obj)
#print("\x52\x54\x00\x87\xcd\xd4")

def arpscan(sock,sender_ip,sender_mac,target_ip):
    print("sending data to %s" % (target_ip))
    broadcast_mac = "\xff\xff\xff\xff\xff\xff" #change this to all ff after
    sender_mac = sender_mac
    #ethernet header
    ethernet_header = broadcast_mac #Destination Mac
    print(type(sender_mac))
    ethernet_header += sender_mac #source MAC
    ethernet_header += "\x08\x06" # ARP Type: 0x0806
    #build arp packet
    arp_data = "\x00\x01" #Ethernet type
    arp_data += "\x08\x00" #IP Protocol
    arp_data += "\x06" #addr length
    arp_data += "\x04" #prot addr length
    arp_data += "\x00\x01" #operation = request
    arp_data += sender_mac #sender hardware address (my mac address)
    arp_data += sender_ip #sender protocol address (my ip address-> this has to be done  
    arp_data += "\x00\x00\x00\x00\x00\x00" #\x52\x54\x00\x18\xfa\xfa" #target hardware address set to all 0
    arp_data += target_ip #target IP increment based on subnet and IP


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
    #print(struct.unpack(numb,byte[1][4]))
    #print("red term")


#print(netifaces.interfaces())
s=netifaces.ifaddresses('eth0')[netifaces.AF_LINK][0]['addr']
#s[netifaces.AF_LINK]
#print(s)
for tupl in listip:

    #sender_ip=struct.pack(netifaces.ifaddresses(tupl[0])[2][0]['addr'])
    #sender_ip=struct.pack('!I',int(hex(netifaces.ifaddresses(tupl[0])[2][0]['addr']),16))
    sender_ip=IPAddress(netifaces.ifaddresses(tupl[0])[2][0]['addr'])
    sender_ip=int(hex(sender_ip),16)
    sender_ip=struct.pack('!I',sender_ip)
    #print(struct.unpack('!I',sender_ip))
    #print(sender_ip)
#print(socket.inet_aton(sender_ip))
    sender_mac=netifaces.ifaddresses(tupl[0])[netifaces.AF_LINK][0]['addr']
    target_ip=tupl[1]
    sender_mac=sender_mac.replace(':','\\x')
    sender_mac=str(('\\x'+sender_mac))
    #sender_mac=struct.pack('!I',int(hex(EUI(sender_mac)),16))
    #print(type(sender_mac))
#print(sender_ip)
#print(target_ip)



    sock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW, socket.htons(3))
    sock.bind((tupl[0],0))
    #print("socket bound")
    t = threading.Thread(target = rec, args=(sock,))
    t2 = threading.Thread(target = arpscan, args=(sock,sender_ip,sender_mac,target_ip))


    t.start()
    t2.start()
    t.join()
    t2.join() 
    sock.close()


#
#get tcp 


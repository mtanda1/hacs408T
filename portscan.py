import netifaces
from netaddr import *
import netaddr
import threading
import socket
from time import sleep
import struct

activeMacIp = []
activeports = []
activeMacIp.append(('eth0',"RT\\x00\\x1e3E", (167903362,)))
for ip in activeMacIp:
    print str(ip[0])
    #print str(IPAddress(ip[2][0]))
    
    # print(activeMacIp[0][0])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(sock.connect_ex((str(IPAddress(ip[2][0])),22)))
    sock.close()
    for port in range(1,24):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            is_active=sock.connect_ex((str(IPAddress(ip[2][0])),port))
            print(is_active)
            if(is_active==0):
                print(port)
                byte = sock.recvfrom(20000)
                if("SSH"in byte[0]):
                    print("this is an ssh server")

                print(byte)

                #print(s)
        except:
            print("conn refused for port: %s") % (port)
        sock.close()
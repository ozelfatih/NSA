#import logging
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys, os
import socket

#####################################################
# ICMP Kodları (Type 3)                             #
# 1  Host Ulaşılamaz                                #
# 2  Protocol Ulaşılamaz                            #
# 3  Port Ulaşılamaz                                #
# 9  Hedefdeki ağ yönetici tarafından yasaklanmış   #
# 10 Hedefteki host yönetici tarafından yasaklanmış #
# 13 Bağlantı yönetici tarafından yasaklanmış       #
#####################################################

conf.verb=0 #disables scapy default verbose mode

#logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #disables 'No route found for IPv6 destination' warning

t_wait=.25 #Her bir paketin cevap beklenme süresi
openPorts = [] #Açık portlar
closedPorts = [] #Kapalı portlar
filteredPorts = [] #Filtrelenmiş portlar

tgt = input("Destination IP: ")
bP = int(input("Start Port: "))
eP = int(input("End Port: "))


def synScan(tgt, bP, eP):
  for port in range(bP, eP+1):
    answer = sr1(IP(dst=tgt)/TCP(dport=port,flags="S"),timeout=t_wait)
    if(str(type(answer))=="<type 'NoneType'>"):
      filteredPorts.append(int(port))
      print ("Port %d - Filtered" % port)
    elif(answer.haslayer(TCP)):
      if(answer.getlayer(TCP).flags == 0x12):
        send_rst = sr1(IP(dst=tgt)/TCP(dport=port,flags="R"),timeout=t_wait)
        openPorts.append(int(port))
        print ("Port %d - Open" % port)
      elif (answer.getlayer(TCP).flags == 0x14):
            closedPorts.append(int(port))
            print ("Port %d - Closed" % port)
      elif(answer.haslayer(ICMP)):
            if(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                filteredPorts.append(int(port))
                print ("Port %d - Filtered" % port)

  summary()

  def summary():
    print ("============================================================================================")
    print ("There are {0} open ports, {1} filtered ports, {2} closed ports".format(len(openPorts), len(filteredPorts), len(closedPorts)))
    print ("The following ports are open:")
    for port in openPorts:
        print ("[+] %d Open" % port)

synScan(tgt,bP,eP)

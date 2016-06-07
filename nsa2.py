# Aktif bilgisayar tespiti

import nmap
nm = nmap.PortScanner()

hostlist = ['ipler_buraya']
for h in hostlist:
   sc = nm.scan(h, '80', '-sV -O')
   state = sc['nmap']['scanstats']['uphosts']
   if state == '1':
      print h, " : Aktif  host :)"
   else:
      print h, " : Kapali host :("


# Aktif bilgisayarların mac tespiti


import nmap
nm = nmap.PortScanner()

hostlist = ['ipler_buraya']
for h in hostlist:
   sc = nm.scan(h, '80', '-sV -O')
   state = sc['nmap']['scanstats']['uphosts']
   if state == '1':
      mac = sc['scan']['addressses']['mac']
      print mac, " : ", h
      
      
      
      
# Aktif bilgisayarların işletim sistemi bilgisini elde etmek

import nmap
nm = nmap.PortScanner()

hostlist = ['ipler_buraya']
for h in hostlist:
   sc = nm.scan(h, '80', '-sV -O')
   state = sc['nmap']['scanstats']['uphosts']
   if state == '1':
      os  = sc['scan'][h]['osmatch'][1]['osclass'][0]['osfamily']
      mac = sc['scan']['addressses']['mac']
      print mac, " : ", h, " : ", os 

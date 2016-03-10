from scapy.all import *

ans, unans = sr(IP(dst="10.99.5.22")/TCP(sport=4444, dport=[135, 445, 8080, 443, 80, 1433], flags="S"))

ans.summary(lambda s,r: r.sprintf("TCP: {0} %TCP.sport% ----------------> %TCP.flags%".format(str(r[TCP].sport))))

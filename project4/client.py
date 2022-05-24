# Send UDP broadcast packets
MYPORT = 50000
import sys, time
from socket import *
s = socket(AF_INET, SOCK_DGRAM)
s.bind(('', 0))
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
while 1:
    data = repr(0)
    s.sendto(data, ('10.255.255.255', MYPORT))
    time.sleep(2)
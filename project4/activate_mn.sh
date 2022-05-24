sudo mn -c
sudo mn --controller=remote,ip=127.0.0.1 --topo tree,depth=4 --switch default,protocols=OpenFlow13 --mac --arp
sudo mn -c
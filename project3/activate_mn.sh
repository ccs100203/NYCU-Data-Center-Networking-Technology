sudo mn -c
# sudo mn --controller=remote,ip=127.0.0.1 --topo tree,depth=3
sudo mn --custom=topo.py --topo=mytopo --link=tc --controller=remote,ip=127.0.0.1,port=6653
sudo mn -c

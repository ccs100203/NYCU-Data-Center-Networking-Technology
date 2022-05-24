# cd /usr/local/lib/python3.6/dist-packages
if [ -z "$1" ]
then
    ryu-manager my_switch.py
else
    ryu-manager "$1"
fi
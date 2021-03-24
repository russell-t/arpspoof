### Install Scapy
```
sudo apt-get install python3-scapy
```

### Install iptables and follow this guide
http://www.intellamech.com/RaspberryPi-projects/rpi_iptables.html
```
sudo apt-get install iptables-persistent
```

### Install NetfilterQueue
```
git clone https://github.com/kti/python-netfilterqueue.git
cd python-netfilterqueue
pip3 install Cython --install-option="--no-cython-compile"
python3 setup.py build_ext --force
python3 setup.py install
```

### Open one terminal and run arp-psn.py
```
sudo python3 arp-psn.py <victim ip> <gateway ip>
```
  
### Open another terminal and run httpspoof.py
```
sudo python3 httpspoof.py <victim ip> <word to replace> <replacement word>
```
**Note:** the word to replace and replacement word must have the same number of characters


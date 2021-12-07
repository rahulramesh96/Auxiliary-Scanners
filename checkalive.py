#!/usr/bin/env python

import scapy.all as scapy
import argparse
from pyparsing import *

def get_arguments():
    parser = argparse.ArgumentParser(description='Check Alive Hosts')
    parser._optionals.title = "Optional Arguments"

    required_arguments = parser.add_argument_group('Required Arguments')
    required_arguments.add_argument("-t", "--target", dest="target", help="Target's IP Address/IP Range.", required=True)
    return parser.parse_args()




def scan(ip):
    with open("ipaddress.txt", "r", newline=None) as fd:
        for ip in fd:

            ip = ip.replace("\n", "")
            ip = str(ip)
            print("pinging", ip)
            
            for var in range(1):
                arp_request = scapy.ARP(pdst=ip)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                    
                results_list = []
                for element in answered_list:
                    clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                    results_list.append(clients_dict)
                    print("\x1b[0;30;42m" + f"[*] Success! The above host is up!: {ip}" + "\x1b[0m")
                    
        return results_list


arguments = get_arguments()
scan_result = scan(arguments.target) 
 
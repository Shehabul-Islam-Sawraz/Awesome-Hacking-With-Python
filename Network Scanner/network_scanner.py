#!/usr/bin/env python

import scapy.layers.all as scapy 
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP/IP Range\nExample: python3 mac_changer.py -t 10.0.1.1/24")
    options = parser.parse_args() 
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)
    clients_list=[]
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    
    return clients_list

def print_results(result_list):
    print("IP\t\t\tMAC Adress\n-----------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_results(scan_result)
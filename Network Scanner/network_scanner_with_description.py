#!/usr/bin/env python

#from scapy import all as scapy
import scapy.layers.all as scapy 
import argparse

### ARP = Adress Resolution Protocol 
# At first step we have to create ARP request directed to broadcast MAC asking for ip. To do this we will
# use ARP request to ask who has the target ip address.So we are doing this and saving it in a variable
# called ```arp_request```. The next thing that we need to do is to set the destination MAC to the broadcast 
# MAC address to make sure that this will be sent to all the clients on the same network. In order to do
# this we need to use an ethernet frame because data in networks is sent using the MAC address not the IP 
# address.The source MAC and the destination MAC is set in the Ethernet part of each packet.Therefore we 
# need to create an Ethernet frame and then append our ARP request to it.So we have to create an Ethernet 
# frame that will be sent to the broadcast.To create an Ethernet object for us from scapy using a class 
# that's implemented by scapy.It's going to store an instance of that broadcast in a variable called 
# ```broadcast```.Here we need to set the destination MAC address to the broadcast MAC address and the whole point of
# using it in here is to make sure that the packet that we'll be sending will be sent to the broadcast MAC 
# address and not to only one device.Now the broadcast MAC address is actually a virtual MAC address that 
# doesn't exist really.But when you send something to it all clients will receive it in the network. And
# the value of this MAC address is ff:ff:ff:ff:ff:ff.Now if we combine the arp_request & broadcast request,
# we will complete our first step.Now to do combine these two requests, we can just use slash & store the 
# combination in a variable called ```arp_request_broadcast```.

### SRP = Send Receive Packet
# In the secon step, we have to send the packet that contains the combination of the broadcast and the ARP
# request & it will automatically go to the broadcast MAC address asking for who has the IP that we pass as 
# the IP as a variable.So send packet we will use 'srp' function of scrapy.As the name suggests this will 
# send the packet that we give it and receive the response.The response will return a couple of two lists.
# The first element is a list of answered packets. The second element is a list of unanswered packets.
# So we are storing the response in two variables named ```answered_list``` & ```unanswered_list```.We also 
# have to set a timeout.If there is no response for that time, then move on, don't keep waiting.If we don't 
# set a timeout, we will never exit of the program.

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP/IP Range\nExample: python3 network_scanner.py -t 10.0.1.1/24")
    options = parser.parse_args() 
    if not options.target:
        parser.error("[-] Please specify a target range, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    #print(scapy.ls(scapy.ARP)) # This will help to see the constructor variables of scapy.ARP
    #print(arp_request.summary()) # This line will print the summary of the request
    #arp_request.show() # This line will print the full details of ARP request
    
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #print(broadcast.summary()) # This line will print the summary of the broadcast.In the summary, you can see from which MAC address ethernet packets are being sent to Broadcast MAC address.
    #broadcast.show() # This line will print the full details of broadcast request
    
    arp_request_broadcast = broadcast/arp_request
    #print(arp_request_broadcast.summary()) # This line will print the summary of the combination request
    #arp_request_broadcast.show() # This will print the full details of the combination request

    answered_list, unanswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False) # We are setting timeout to 1 second & verbose mode to false so that it will not show extra information about answered packets numbers
    #print (answered_list.summary()) # This will print the answered packet requests and will provi de us the MAC address of the response sender or we can say succesfully packet receiver.

    clients_list=[]

    for element in answered_list:
        # print(element[1].show()) # This will print the details of the receiver of the packet requests.
        #print(element[1].psrc) # This will give us the ip adress of the receiver of the packet requests.
        #print(element[1].hwsrc) # This will give us the MAC address of the receiver of the packet requests.
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
        #print(element[1].psrc + "\t\t" + element[1].hwsrc)
    
    return clients_list

def print_results(result_list):
    print("IP\t\t\tMAC Adress\n-----------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_results(scan_result)
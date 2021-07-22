#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="Interface to change it's MAC Address")
    parser.add_option("-m","--mac",dest="new_mac",help="New MAC Address\nExample: python3 mac_changer.py -i eth0 -m 00:11:22:33:44:55")
    (options,arguments) = parser.parse_args() 

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_mac:
        parser.error("[-] Please specify a new mac address, use --help for more info.")
    return options


def change_mac_address(interface,new_address):
    print("[+] Changing MAC Address of "+interface+" to "+new_mac)
    subprocess.call(["ifconfig",interface,"down"]) 
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig",interface,"up"])


def get_current_mac_address(interface):
    ifconfig_result = subprocess.check_output(["ifconfig",interface])
    #print("[+] Information of the interface "+interface+" : ")
    #print(ifconfig_result)
    search_mac_address_regex = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_result)
    if search_mac_address_regex:
        return search_mac_address_regex.group(0)
    else:
        print("[-] Could not read MAC Address")


options = get_arguments() 
interface = options.interface
new_mac = options.new_mac

current_mac = get_current_mac_address(interface)
print("Current MAC Address: " + str(current_mac))

change_mac_address(interface,new_mac)

current_mac = get_current_mac_address(interface)
if current_mac == new_mac:
    print("[+] MAC Address was succesfully changed to: "+current_mac)
else:
    print("[+] MAC Address didn't get changed")

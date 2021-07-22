#!/usr/bin/env python

import subprocess # This module helps to run linux commands before executing any other operations on OS.
import optparse # This module helps us to add arguments along with manual command & provides us help manual.
import re # Helps for finding regex

def get_arguments():
    parser = optparse.OptionParser() # Taking an object of parser class

    # This line will helps us to call arguments like '-i' or '--interface' and take a value of the argument. Then it will save the given value
    # in a variable named 'interface' which is defined as `dest` in function call. We have also defined the help manual for these arguments.
    # For example: python3 mac_changer.py -i eth0 . We can also call it by using: python3 mac_changer.py --interface eth0
    parser.add_option("-i","--interface",dest="interface",help="Interface to change it's MAC Address")

    # This line will helps us to call arguments like '-m' or '--mac' and take a value of the argument. Then it will save the given value
    # in a variable named 'new_mac' which is defined as `dest` in function call. We have also defined the help manual for these arguments.
    # For example: python3 mac_changer.py -m 00:11:22:33:44:55 . We can also call it by using: python3 mac_changer.py --mac 00:11:22:33:44:55
    parser.add_option("-m","--mac",dest="new_mac",help="New MAC Address")

    parser.add_option(help="Example: python3 mac_changer.py -i eth0 -m 00:11:22:33:44:55")

    (options,arguments) = parser.parse_args() # Here we are parsing the values from the parser. The varible 'options' will store the value of 
                                            # the interface & the mac address. And the varible 'arguments' will store the commands '--interface'
                                            # & '--mac'

    if not options.interface: # If interface is not specified, then show error
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_mac: # If new mac address is not specified, then show error
        parser.error("[-] Please specify a new mac address, use --help for more info.")
    return options


def change_mac_address(interface,new_address):
    print("[+] Changing MAC Address of "+interface+" to "+new_mac)
    subprocess.call(["ifconfig",interface,"down"]) # This command will deactivate the 'interface' give by us if the interface is in active 
                                                #mode. So that we can make changes to the given interface.
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac]) # This command will change the mac address of the given interface to our  
                                                                # given mac address.
    subprocess.call(["ifconfig",interface,"up"]) # This command will activate the 'interface' give by us if the interface is in deactive mode.


def get_current_mac_address(interface):
    ifconfig_result = subprocess.check_output(["ifconfig",interface]) # This line will extract the information of given interface from the 'inconfig' command
    #print("[+] Information of the interface "+interface+" : ")
    #print(ifconfig_result)
    search_mac_address_regex = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_result) # Checking whether there exists any mac address in the inconfig information

    if search_mac_address_regex:
        return search_mac_address_regex.group(0) # If there is a match, then return the mac address
    else:
        print("[-] Could not read MAC Address")


options = get_arguments() # Calling the function that returns values
interface = options.interface # Parsing value of the interface from options
new_mac = options.new_mac # Parsing value of the mac address from options

current_mac = get_current_mac_address(interface)
print("Current MAC Address: " + str(current_mac))

change_mac_address(interface,new_mac)

current_mac = get_current_mac_address(interface)
if current_mac == new_mac:
    print("[+] MAC Address was succesfully changed to: "+current_mac)
else:
    print("[+] MAC Address didn't get changed")
